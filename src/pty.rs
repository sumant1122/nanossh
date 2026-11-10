use anyhow::{Context, Result};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Receiver, Sender};

#[derive(Clone)]
pub struct PtyHandle {
    #[allow(dead_code)]
    pub child_pid: u32,
    tx_stdin: Sender<Vec<u8>>,
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
}

impl PtyHandle {
    pub async fn send_stdin(&self, data: Vec<u8>) -> Result<()> {
        self.tx_stdin
            .send(data)
            .await
            .map_err(|_| anyhow::anyhow!("PTY stdin channel closed"))
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let master = self.master.lock().unwrap();
        master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("Failed to resize PTY")?;
        Ok(())
    }
}

pub struct PtySession;

impl PtySession {
    pub fn spawn(cols: u16, rows: u16, term: &str) -> Result<(PtyHandle, Receiver<Vec<u8>>)> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("Failed to open PTY pair")?;

        let shell = std::env::var("SHELL").unwrap_or_else(|_| {
            if std::path::Path::new("/bin/bash").exists() {
                "/bin/bash".to_string()
            } else {
                "/bin/sh".to_string()
            }
        });

        let mut cmd = CommandBuilder::new(shell);
        cmd.env("TERM", term);
        cmd.env("COLORTERM", "truecolor");

        let child = pair
            .slave
            .spawn_command(cmd)
            .context("Failed to spawn shell process in PTY slave")?;

        let child_pid = child.process_id().unwrap_or(0);
        let master = Arc::new(Mutex::new(pair.master));

        // Reader thread: reads PTY master stdout and sends to rx_stdout channel
        let (tx_stdout, rx_stdout) = mpsc::channel::<Vec<u8>>(128);
        let mut reader = master
            .lock()
            .unwrap()
            .try_clone_reader()
            .context("Failed to clone PTY master reader")?;

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break, // Shell closed / EOF
                    Ok(n) => {
                        if tx_stdout.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Writer thread: receives stdin packets and writes to PTY master
        let (tx_stdin, mut rx_stdin) = mpsc::channel::<Vec<u8>>(128);
        let mut writer = master
            .lock()
            .unwrap()
            .take_writer()
            .context("Failed to take PTY master writer")?;

        std::thread::spawn(move || {
            while let Some(data) = rx_stdin.blocking_recv() {
                if writer.write_all(&data).is_err() || writer.flush().is_err() {
                    break;
                }
            }
        });

        let handle = PtyHandle {
            child_pid,
            tx_stdin,
            master,
        };

        Ok((handle, rx_stdout))
    }
}
