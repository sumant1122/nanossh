use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{
    compute_auth_tag, derive_session_keys, Decryptor, Encryptor, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use crate::protocol::{read_raw_frame, write_raw_frame, Message};
use crate::pty::PtySession;

pub struct Server {
    bind_addr: SocketAddr,
    secret_token: Arc<Vec<u8>>,
}

impl Server {
    pub fn new(bind_addr: SocketAddr, secret_token: Vec<u8>) -> Self {
        Self {
            bind_addr,
            secret_token: Arc::new(secret_token),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind server to {}", self.bind_addr))?;

        info!("nanossh server listening on {}", self.bind_addr);
        info!("Ready for client connections");

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("Incoming connection from {}", peer_addr);
                    let secret = Arc::clone(&self.secret_token);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(socket, peer_addr, &secret).await {
                            warn!("Session with {} ended: {:#}", peer_addr, e);
                        } else {
                            info!("Session with {} disconnected cleanly", peer_addr);
                        }
                    });
                }
                Err(e) => {
                    error!("Listener error: {:#}", e);
                }
            }
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    secret_token: &[u8],
) -> Result<()> {
    // Handshake: Read client initial frame (69 bytes)
    // [Magic: 4B][Version: 1B][Client PubKey: 32B][Client Auth Tag: 32B]
    let mut handshake_buf = [0u8; 69];
    stream
        .read_exact(&mut handshake_buf)
        .await
        .context("Failed reading client handshake")?;

    if &handshake_buf[0..4] != &PROTOCOL_MAGIC {
        bail!("Invalid protocol magic from client {}", peer_addr);
    }
    if handshake_buf[4] != PROTOCOL_VERSION {
        bail!(
            "Protocol version mismatch: expected {}, got {}",
            PROTOCOL_VERSION,
            handshake_buf[4]
        );
    }

    let client_pubkey_bytes: [u8; 32] = handshake_buf[5..37].try_into().unwrap();
    let client_auth_tag = &handshake_buf[37..69];

    let expected_auth_tag = compute_auth_tag(secret_token, &client_pubkey_bytes);
    if expected_auth_tag != client_auth_tag {
        let _ = stream.write_all(&[1u8]).await;
        let _ = stream.flush().await;
        bail!("Authentication rejected: invalid secret key from {}", peer_addr);
    }

    // Server ephemeral key exchange
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pubkey = PublicKey::from(&server_secret);
    let server_auth_tag = compute_auth_tag(secret_token, server_pubkey.as_bytes());

    let client_pubkey = PublicKey::from(client_pubkey_bytes);
    let shared_secret = server_secret.diffie_hellman(&client_pubkey);
    let (c2s_key, s2c_key) = derive_session_keys(&shared_secret, secret_token);

    // Send response: [Status: 1B (0 = OK)][Server PubKey: 32B][Server Auth Tag: 32B]
    let mut resp = Vec::with_capacity(65);
    resp.push(0u8);
    resp.extend_from_slice(server_pubkey.as_bytes());
    resp.extend_from_slice(&server_auth_tag);
    stream
        .write_all(&resp)
        .await
        .context("Failed sending server handshake response")?;
    stream.flush().await?;

    info!("Handshake & authentication successful with {}", peer_addr);

    // Split stream into read and write halves
    let (mut socket_read, mut socket_write) = stream.into_split();

    // Server sends with s2c_key, receives with c2s_key
    let mut encryptor = Encryptor::new(&s2c_key, false);
    let mut decryptor = Decryptor::new(&c2s_key, false);

    // The first message MUST be PtyRequest
    let init_cipher = read_raw_frame(&mut socket_read)
        .await
        .context("Failed reading initial PtyRequest")?;
    let init_plain = decryptor.decrypt(&init_cipher)?;
    let init_msg = Message::decode(&init_plain)?;

    let (pty_handle, mut rx_pty_stdout) = match init_msg {
        Message::PtyRequest { cols, rows, term } => {
            info!(
                "Allocating PTY for {} (cols={}, rows={}, term={})",
                peer_addr, cols, rows, term
            );
            PtySession::spawn(cols, rows, &term).context("Failed to spawn PTY session")?
        }
        other => {
            bail!("Expected PtyRequest message, got: {:?}", other);
        }
    };

    // Channel for outbound messages to client
    let (tx_to_client, mut rx_to_client) = tokio::sync::mpsc::channel::<Message>(128);

    // Network writer task: consumes messages from rx_to_client, encrypts and writes frames to socket
    let write_task = tokio::spawn(async move {
        while let Some(msg) = rx_to_client.recv().await {
            let encoded = msg.encode();
            match encryptor.encrypt(&encoded) {
                Ok(ciphertext) => {
                    if let Err(e) = write_raw_frame(&mut socket_write, &ciphertext).await {
                        warn!("Network write error: {:#}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Encryption error: {:#}", e);
                    break;
                }
            }
        }
    });

    // PTY stdout forwarding task: reads bytes from rx_pty_stdout and sends to tx_to_client
    let tx_stdout_forward = tx_to_client.clone();
    let pty_stdout_task = tokio::spawn(async move {
        while let Some(data) = rx_pty_stdout.recv().await {
            if tx_stdout_forward.send(Message::Stdout(data)).await.is_err() {
                break;
            }
        }
        // Shell exited: notify client with Exit(0)
        let _ = tx_stdout_forward.send(Message::Exit(0)).await;
    });

    // Client network reading loop: receives encrypted frames from client
    loop {
        match read_raw_frame(&mut socket_read).await {
            Ok(ciphertext) => {
                let plaintext = match decryptor.decrypt(&ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Decryption error from {}: {:#}", peer_addr, e);
                        break;
                    }
                };

                match Message::decode(&plaintext) {
                    Ok(Message::Stdin(data)) => {
                        if pty_handle.send_stdin(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::PtyResize { cols, rows }) => {
                        let _ = pty_handle.resize(cols, rows);
                    }
                    Ok(Message::Ping(ts)) => {
                        let _ = tx_to_client.send(Message::Pong(ts)).await;
                    }
                    Ok(Message::Exit(_)) => {
                        info!("Client requested session exit");
                        break;
                    }
                    Ok(msg) => {
                        warn!("Unexpected message received from client: {:?}", msg);
                    }
                    Err(e) => {
                        warn!("Frame decode error from {}: {:#}", peer_addr, e);
                        break;
                    }
                }
            }
            Err(_) => {
                // Client closed socket or connection reset
                break;
            }
        }
    }

    // Abort background tasks
    write_task.abort();
    pty_stdout_task.abort();

    Ok(())
}
