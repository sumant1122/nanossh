use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

mod client;
mod crypto;
mod protocol;
mod pty;
mod server;

#[derive(Parser)]
#[command(name = "nanossh")]
#[command(about = "Ultra-lightweight, encrypted SSH-like protocol and shell in Rust", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the nanossh server (host shell on this machine)
    Server {
        /// Socket address to listen on (e.g. 0.0.0.0:2222)
        #[arg(short, long, default_value = "0.0.0.0:2222")]
        bind: SocketAddr,

        /// Pre-shared secret passphrase / key
        #[arg(short, long, env = "NANOSSH_SECRET")]
        secret: Option<String>,

        /// Path to file containing pre-shared secret
        #[arg(long)]
        secret_file: Option<PathBuf>,
    },

    /// Connect to a remote nanossh server
    Client {
        /// Socket address of the nanossh server to connect to (e.g. 192.168.1.100:2222)
        #[arg(short, long)]
        connect: SocketAddr,

        /// Pre-shared secret passphrase / key
        #[arg(short, long, env = "NANOSSH_SECRET")]
        secret: Option<String>,

        /// Path to file containing pre-shared secret
        #[arg(long)]
        secret_file: Option<PathBuf>,
    },

    /// Generate a cryptographically secure random secret token
    Keygen,
}

fn resolve_secret(secret_arg: Option<String>, secret_file: Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(path) = secret_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read secret file at {:?}", path))?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            bail!("Secret file is empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    if let Some(secret) = secret_arg {
        let trimmed = secret.trim();
        if trimmed.is_empty() {
            bail!("Secret cannot be empty");
        }
        return Ok(trimmed.as_bytes().to_vec());
    }

    // If neither is provided, check default secret file ~/.nanossh/secret
    if let Some(home) = std::env::var_os("HOME") {
        let default_file = PathBuf::from(home).join(".nanossh").join("secret");
        if default_file.exists() {
            let content = fs::read_to_string(&default_file)?;
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.as_bytes().to_vec());
            }
        }
    }

    bail!("No secret provided. Use --secret, set NANOSSH_SECRET, or pass --secret-file");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let hex_key = hex_encode(&key);
            println!("{}", hex_key);
            Ok(())
        }
        Commands::Server {
            bind,
            secret,
            secret_file,
        } => {
            // Initialize logging only for server
            tracing_subscriber::fmt::init();
            let secret_bytes = resolve_secret(secret, secret_file)?;
            let server = server::Server::new(bind, secret_bytes);
            server.run().await
        }
        Commands::Client {
            connect,
            secret,
            secret_file,
        } => {
            let secret_bytes = resolve_secret(secret, secret_file)?;
            let client = client::Client::new(connect, secret_bytes);
            client.run().await
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
