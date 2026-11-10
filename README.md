# nanossh 🦀

**nanossh** is an ultra-lightweight, secure, SSH-like remote shell protocol and standalone binary written in Rust. It is engineered specifically for resource-constrained machines (such as older laptops with 1–2 GB RAM, netbooks, or Raspberry Pis) connecting to modern Macs or Linux workstations.

---

## ⚡ Highlights for Low-Spec / 2GB RAM Machines

- **Tiny Memory Footprint:** Consumes only **~2.5 MB Resident Memory (RSS)** at runtime (<0.15% of 2 GB RAM).
- **Fast CPU Cipher without Hardware AES:** Uses **ChaCha20-Poly1305** AEAD, which runs exceptionally fast on older x86/x86_64 CPUs (Core 2 Duo, Atom, older Celerons/i3/i5) that lack hardware AES-NI instructions.
- **Single Self-Contained Binary:** Exactly **1.0 MB** stripped binary with zero external runtime dependencies.
- **True Interactive Terminal (PTY):** Real pseudo-terminal support with raw-mode forwarding. Seamlessly runs fullscreen TUIs (`vim`, `htop`, `tmux`, `nano`, `less`), supports tab completion, arrow history, and `Ctrl+C`/`Ctrl+Z` signal propagation.
- **Dynamic Terminal Resize:** Window resize events (`SIGWINCH`) on your Mac terminal propagate across the wire, automatically adjusting the remote shell size via `ioctl(TIOCSWINSZ)`.
- **Authenticated Forward-Secret Handshake:** Ephemeral **X25519** Diffie-Hellman key exchange authenticated with a pre-shared secret token via HMAC-SHA256, deriving independent directional 256-bit encryption keys and monotonic 64-bit sequence counters.

---

## 📋 Protocol Specification

### 1. Wire Framing

Every frame sent over the TCP connection is framed with a 4-byte big-endian payload length:
```
+------------------------+---------------------------------------+
|  Length (4 bytes, BE)  |  Encrypted Ciphertext (Length bytes)  |
+------------------------+---------------------------------------+
```

### 2. Handshake Phase

1. **Client -> Server (`69 bytes`):**
   ```
   [Magic: "TSSH" (4B)][Version: 0x01 (1B)][Client Ephemeral PubKey (32B)][HMAC-SHA256 Auth Tag (32B)]
   ```
2. **Server Verification:**
   - Server validates the client's HMAC-SHA256 auth tag against the pre-shared secret.
   - If invalid, server sends `0x01` status and closes immediately.
3. **Server -> Client (`65 bytes`):**
   ```
   [Status: 0x00 (1B)][Server Ephemeral PubKey (32B)][HMAC-SHA256 Auth Tag (32B)]
   ```
4. **Key Derivation (HKDF/SHA-256):**
   - Both sides compute the shared secret via X25519.
   - Derives two independent 32-byte keys:
     - `Client-to-Server Key`: encrypts client keystrokes / commands.
     - `Server-to-Client Key`: encrypts remote shell output.
   - Each frame uses a 12-byte nonce formed by `[Role Prefix (4B)][64-bit Monotonic Sequence Number (8B)]`.

### 3. Encrypted Message Types

Inside the decrypted payload:
| Opcode | Type | Description |
|:---:|:---|:---|
| `0x01` | `PTY_REQUEST` | Initial terminal request: columns, rows, terminal name (`xterm-256color`) |
| `0x02` | `PTY_RESIZE` | Dynamic terminal resize notification: new `cols` and `rows` |
| `0x03` | `STDIN` | Raw keystrokes and data from client to remote PTY |
| `0x04` | `STDOUT` | Terminal output stream from remote PTY to client |
| `0x05` | `PING` | Keepalive heartbeat ping |
| `0x06` | `PONG` | Keepalive heartbeat pong |
| `0x07` | `EXIT` | Shell termination notification with exit code |

---

## 🚀 Quickstart

### 1. Generate a Shared Secret Token

Run on either machine:
```bash
nanossh keygen
```
*Example output:*
```
54c93347eff231d9ea13491cc34b46e50c761b1aeb013f467cbecbddf3efd7a8
```

You can save this to `~/.nanossh/secret` or provide it via `--secret` or the `NANOSSH_SECRET` environment variable.

---

### 2. Start the Server (e.g., on the Old Laptop)

To open a remote shell on your old laptop:
```bash
nanossh server --bind 0.0.0.0:2222 --secret "<YOUR_SECRET_KEY>"
```

### 3. Connect from Client (e.g., from your Mac)

From your Mac terminal:
```bash
nanossh client --connect 192.168.1.50:2222 --secret "<YOUR_SECRET_KEY>"
```
Your Mac terminal switches to raw mode and attaches directly to the laptop's bash/zsh shell!

---

## 🛠 Building & Cross-Compiling

### Build for Host (macOS or Linux)
```bash
cargo build --release
```
The optimized 1.0 MB binary is available at `target/release/nanossh`.

### Cross-Compiling for an Old Linux Laptop (from Mac)

If your laptop runs 64-bit Linux (Debian, Ubuntu, Alpine, Arch):
```bash
# Add musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary using cargo-zigbuild or cross
cargo install cross
cross build --target x86_64-unknown-linux-musl --release
```
Copy `target/x86_64-unknown-linux-musl/release/nanossh` directly to the laptop via USB or network. Because it is statically linked with musl, it runs on any Linux distribution without needing any dependencies.

If your laptop is a 32-bit machine:
```bash
cross build --target i686-unknown-linux-musl --release
```

---

## 🐧 Systemd Service for Auto-Starting on Laptop Boot

To have your old laptop automatically listen for connections when powered on, create `/etc/systemd/system/nanossh.service`:

```ini
[Unit]
Description=nanossh lightweight remote shell daemon
After=network.target

[Service]
Type=simple
User=your_username
Environment="NANOSSH_SECRET=your_generated_secret_key"
ExecStart=/usr/local/bin/nanossh server --bind 0.0.0.0:2222
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nanossh
```
