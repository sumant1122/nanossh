use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use std::io::{IsTerminal, Read, Write};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{
    compute_auth_tag, derive_session_keys, Decryptor, Encryptor, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use crate::protocol::{read_raw_frame, write_raw_frame, Message};

struct RawModeGuard {
    active: bool,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

pub struct Client {
    server_addr: SocketAddr,
    secret_token: Vec<u8>,
}

impl Client {
    pub fn new(server_addr: SocketAddr, secret_token: Vec<u8>) -> Self {
        Self {
            server_addr,
            secret_token,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let mut stream = TcpStream::connect(self.server_addr)
            .await
            .with_context(|| format!("Failed to connect to nanossh server at {}", self.server_addr))?;

        // Handshake: generate client ephemeral key
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pubkey = PublicKey::from(&client_secret);
        let client_auth_tag = compute_auth_tag(&self.secret_token, client_pubkey.as_bytes());

        // Send handshake request: [Magic: 4B][Version: 1B][Client PubKey: 32B][Auth Tag: 32B] (69 bytes)
        let mut req = Vec::with_capacity(69);
        req.extend_from_slice(&PROTOCOL_MAGIC);
        req.push(PROTOCOL_VERSION);
        req.extend_from_slice(client_pubkey.as_bytes());
        req.extend_from_slice(&client_auth_tag);
        stream.write_all(&req).await.context("Failed sending client handshake")?;
        stream.flush().await?;

        // Read server status byte
        let mut status = [0u8; 1];
        stream
            .read_exact(&mut status)
            .await
            .context("Failed reading server handshake status")?;

        if status[0] != 0 {
            bail!("Authentication rejected by server: incorrect secret key");
        }

        // Read server response (64 bytes): [Server PubKey: 32B][Server Auth Tag: 32B]
        let mut resp_buf = [0u8; 64];
        stream
            .read_exact(&mut resp_buf)
            .await
            .context("Failed reading server handshake payload")?;

        let server_pubkey_bytes: [u8; 32] = resp_buf[0..32].try_into().unwrap();
        let server_auth_tag = &resp_buf[32..64];

        let expected_auth_tag = compute_auth_tag(&self.secret_token, &server_pubkey_bytes);
        if expected_auth_tag != server_auth_tag {
            bail!("Server authentication failed: forged or invalid server tag");
        }

        let server_pubkey = PublicKey::from(server_pubkey_bytes);
        let shared_secret = client_secret.diffie_hellman(&server_pubkey);
        let (c2s_key, s2c_key) = derive_session_keys(&shared_secret, &self.secret_token);

        // Split socket for full-duplex communication
        let (mut socket_read, mut socket_write) = stream.into_split();

        // Client sends with c2s_key, receives with s2c_key
        let mut encryptor = Encryptor::new(&c2s_key, true);
        let mut decryptor = Decryptor::new(&s2c_key, true);

        let is_interactive = std::io::stdin().is_terminal();

        // Terminal dimensions & TERM variable
        let (cols, rows) = if is_interactive {
            crossterm::terminal::size().unwrap_or((80, 24))
        } else {
            (80, 24)
        };

        let term = if is_interactive {
            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string())
        } else {
            "dumb".to_string()
        };

        let mut guard = RawModeGuard { active: false };
        if is_interactive {
            if crossterm::terminal::enable_raw_mode().is_ok() {
                guard.active = true;
            }
        }

        // Channel for messages to send to server
        let (tx_to_server, mut rx_to_server) = tokio::sync::mpsc::channel::<Message>(128);

        // Send initial PtyRequest
        tx_to_server
            .send(Message::PtyRequest { cols, rows, term })
            .await
            .context("Failed to queue initial PtyRequest")?;

        // Spawn window resize (SIGWINCH) listener task if interactive
        if is_interactive {
            let tx_resize = tx_to_server.clone();
            tokio::spawn(async move {
                if let Ok(mut sigwinch) = signal(SignalKind::window_change()) {
                    while sigwinch.recv().await.is_some() {
                        if let Ok((cols, rows)) = crossterm::terminal::size() {
                            let _ = tx_resize.send(Message::PtyResize { cols, rows }).await;
                        }
                    }
                }
            });
        }

        // Spawn stdin reader thread
        let tx_stdin = tx_to_server.clone();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break, // EOF reached
                    Ok(n) => {
                        if tx_stdin.blocking_send(Message::Stdin(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Network writer task: consumes messages from rx_to_server, encrypts and writes to socket
        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx_to_server.recv().await {
                let encoded = msg.encode();
                match encryptor.encrypt(&encoded) {
                    Ok(ciphertext) => {
                        if let Err(e) = write_raw_frame(&mut socket_write, &ciphertext).await {
                            warn!("Failed writing frame to server: {:#}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Client encryption error: {:#}", e);
                        break;
                    }
                }
            }
        });

        // Network reader loop: receives encrypted frames from server and renders to stdout
        let mut exit_code = 0;
        loop {
            match read_raw_frame(&mut socket_read).await {
                Ok(ciphertext) => {
                    let plaintext = match decryptor.decrypt(&ciphertext) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("Decryption error from server: {:#}", e);
                            break;
                        }
                    };

                    match Message::decode(&plaintext) {
                        Ok(Message::Stdout(data)) => {
                            let mut stdout = std::io::stdout();
                            let _ = stdout.write_all(&data);
                            let _ = stdout.flush();
                        }
                        Ok(Message::Exit(code)) => {
                            exit_code = code;
                            break;
                        }
                        Ok(Message::Ping(ts)) => {
                            let _ = tx_to_server.send(Message::Pong(ts)).await;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to decode server frame: {:#}", e);
                            break;
                        }
                    }
                }
                Err(_) => {
                    // Server closed connection
                    break;
                }
            }
        }

        write_task.abort();
        drop(guard); // Restores terminal normal mode if enabled

        if exit_code != 0 {
            std::process::exit(exit_code);
        }

        Ok(())
    }
}
