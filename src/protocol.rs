use anyhow::{bail, Result};
use std::convert::TryInto;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MSG_PTY_REQUEST: u8 = 0x01;
pub const MSG_PTY_RESIZE: u8 = 0x02;
pub const MSG_STDIN: u8 = 0x03;
pub const MSG_STDOUT: u8 = 0x04;
pub const MSG_PING: u8 = 0x05;
pub const MSG_PONG: u8 = 0x06;
pub const MSG_EXIT: u8 = 0x07;

/// Maximum payload size per frame (64KB is optimal for low-latency streaming and low memory)
pub const MAX_FRAME_SIZE: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    PtyRequest {
        cols: u16,
        rows: u16,
        term: String,
    },
    PtyResize {
        cols: u16,
        rows: u16,
    },
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Ping(u64),
    Pong(u64),
    Exit(i32),
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Message::PtyRequest { cols, rows, term } => {
                buf.push(MSG_PTY_REQUEST);
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                let term_bytes = term.as_bytes();
                buf.extend_from_slice(&(term_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(term_bytes);
            }
            Message::PtyResize { cols, rows } => {
                buf.push(MSG_PTY_RESIZE);
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
            }
            Message::Stdin(data) => {
                buf.push(MSG_STDIN);
                buf.extend_from_slice(data);
            }
            Message::Stdout(data) => {
                buf.push(MSG_STDOUT);
                buf.extend_from_slice(data);
            }
            Message::Ping(ts) => {
                buf.push(MSG_PING);
                buf.extend_from_slice(&ts.to_be_bytes());
            }
            Message::Pong(ts) => {
                buf.push(MSG_PONG);
                buf.extend_from_slice(&ts.to_be_bytes());
            }
            Message::Exit(code) => {
                buf.push(MSG_EXIT);
                buf.extend_from_slice(&code.to_be_bytes());
            }
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            bail!("Empty frame payload");
        }
        let msg_type = bytes[0];
        let rest = &bytes[1..];

        match msg_type {
            MSG_PTY_REQUEST => {
                if rest.len() < 6 {
                    bail!("Malformed PtyRequest frame");
                }
                let cols = u16::from_be_bytes(rest[0..2].try_into()?);
                let rows = u16::from_be_bytes(rest[2..4].try_into()?);
                let term_len = u16::from_be_bytes(rest[4..6].try_into()?) as usize;
                if rest.len() < 6 + term_len {
                    bail!("Truncated PtyRequest terminal name");
                }
                let term = String::from_utf8_lossy(&rest[6..6 + term_len]).to_string();
                Ok(Message::PtyRequest { cols, rows, term })
            }
            MSG_PTY_RESIZE => {
                if rest.len() < 4 {
                    bail!("Malformed PtyResize frame");
                }
                let cols = u16::from_be_bytes(rest[0..2].try_into()?);
                let rows = u16::from_be_bytes(rest[2..4].try_into()?);
                Ok(Message::PtyResize { cols, rows })
            }
            MSG_STDIN => Ok(Message::Stdin(rest.to_vec())),
            MSG_STDOUT => Ok(Message::Stdout(rest.to_vec())),
            MSG_PING => {
                if rest.len() < 8 {
                    bail!("Malformed Ping frame");
                }
                let ts = u64::from_be_bytes(rest[0..8].try_into()?);
                Ok(Message::Ping(ts))
            }
            MSG_PONG => {
                if rest.len() < 8 {
                    bail!("Malformed Pong frame");
                }
                let ts = u64::from_be_bytes(rest[0..8].try_into()?);
                Ok(Message::Pong(ts))
            }
            MSG_EXIT => {
                if rest.len() < 4 {
                    bail!("Malformed Exit frame");
                }
                let code = i32::from_be_bytes(rest[0..4].try_into()?);
                Ok(Message::Exit(code))
            }
            other => bail!("Unknown message type: 0x{:02x}", other),
        }
    }
}

/// Reads a length-prefixed raw frame from an async stream
pub async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE + 64 {
        bail!("Frame size exceeds maximum allowed limit: {} bytes", len);
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Writes a length-prefixed raw frame to an async stream
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msgs = vec![
            Message::PtyRequest {
                cols: 120,
                rows: 40,
                term: "xterm-256color".to_string(),
            },
            Message::PtyResize { cols: 80, rows: 24 },
            Message::Stdin(b"echo 'hello world'\n".to_vec()),
            Message::Stdout(b"hello world\n".to_vec()),
            Message::Ping(123456789),
            Message::Pong(123456789),
            Message::Exit(0),
            Message::Exit(127),
        ];

        for msg in msgs {
            let encoded = msg.encode();
            let decoded = Message::decode(&encoded).expect("Decode should succeed");
            assert_eq!(msg, decoded);
        }
    }
}

