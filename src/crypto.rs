use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use x25519_dalek::SharedSecret;

pub const PROTOCOL_MAGIC: [u8; 4] = *b"TSSH";
pub const PROTOCOL_VERSION: u8 = 1;

pub struct Encryptor {
    cipher: ChaCha20Poly1305,
    seq: u64,
    prefix: u32,
}

impl Encryptor {
    pub fn new(key: &[u8; 32], is_client: bool) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            seq: 0,
            prefix: if is_client { 0x01010101 } else { 0x02020202 },
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&self.prefix.to_be_bytes());
        nonce_bytes[4..12].copy_from_slice(&self.seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.seq = self.seq.checked_add(1).context("Sequence number overflow")?;

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;

        Ok(ciphertext)
    }
}

pub struct Decryptor {
    cipher: ChaCha20Poly1305,
    seq: u64,
    prefix: u32,
}

impl Decryptor {
    pub fn new(key: &[u8; 32], is_client: bool) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            seq: 0,
            prefix: if is_client { 0x02020202 } else { 0x01010101 },
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&self.prefix.to_be_bytes());
        nonce_bytes[4..12].copy_from_slice(&self.seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.seq = self.seq.checked_add(1).context("Sequence number overflow")?;

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption / MAC verification failed: {:?}", e))?;

        Ok(plaintext)
    }
}

/// Compute HMAC-SHA256 authentication tag for key exchange validation
pub fn compute_auth_tag(secret: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"NANOSSH-AUTH-KEY-PREFIX");
    hasher.update(secret);
    let key_hash = hasher.finalize();

    let mut o_key_pad = [0x5cu8; 64];
    let mut i_key_pad = [0x36u8; 64];
    for (i, &b) in key_hash.iter().enumerate() {
        o_key_pad[i] ^= b;
        i_key_pad[i] ^= b;
    }

    let mut inner = Sha256::new();
    inner.update(&i_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&o_key_pad);
    outer.update(&inner_hash);
    let res = outer.finalize();

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&res);
    tag
}

/// Key derivation function: derives client-to-server and server-to-client 32-byte keys
pub fn derive_session_keys(
    shared_secret: &SharedSecret,
    secret_token: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut hasher1 = Sha256::new();
    hasher1.update(b"NANOSSH-C2S-KEY");
    hasher1.update(shared_secret.as_bytes());
    hasher1.update(secret_token);
    let c2s = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(b"NANOSSH-S2C-KEY");
    hasher2.update(shared_secret.as_bytes());
    hasher2.update(secret_token);
    let s2c = hasher2.finalize();

    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key1.copy_from_slice(&c2s);
    key2.copy_from_slice(&s2c);
    (key1, key2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn test_auth_tag_matching() {
        let secret = b"my_super_secret_passphrase";
        let data = b"some_public_key_bytes";
        let tag1 = compute_auth_tag(secret, data);
        let tag2 = compute_auth_tag(secret, data);
        assert_eq!(tag1, tag2);

        let tag3 = compute_auth_tag(b"wrong_secret", data);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_encryption_decryption_flow() {
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_pubkey = PublicKey::from(&client_secret);

        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_pubkey = PublicKey::from(&server_secret);

        let token = b"shared_laptop_secret";

        let client_shared = client_secret.diffie_hellman(&server_pubkey);
        let server_shared = server_secret.diffie_hellman(&client_pubkey);

        let (c2s_client, s2c_client) = derive_session_keys(&client_shared, token);
        let (c2s_server, s2c_server) = derive_session_keys(&server_shared, token);

        assert_eq!(c2s_client, c2s_server);
        assert_eq!(s2c_client, s2c_server);

        // Client -> Server
        let mut client_enc = Encryptor::new(&c2s_client, true);
        let mut server_dec = Decryptor::new(&c2s_server, false);

        let plaintext = b"Hello from old laptop!";
        let cipher = client_enc.encrypt(plaintext).expect("Encryption failed");
        let decrypted = server_dec.decrypt(&cipher).expect("Decryption failed");
        assert_eq!(plaintext.to_vec(), decrypted);

        // Server -> Client
        let mut server_enc = Encryptor::new(&s2c_server, false);
        let mut client_dec = Decryptor::new(&s2c_client, true);

        let reply = b"Hello from Mac!";
        let cipher_reply = server_enc.encrypt(reply).expect("Server enc failed");
        let dec_reply = client_dec.decrypt(&cipher_reply).expect("Client dec failed");
        assert_eq!(reply.to_vec(), dec_reply);

        // Tamper test: flipped byte should fail authentication
        let mut tampered = cipher_reply.clone();
        tampered[0] ^= 0xff;
        assert!(client_dec.decrypt(&tampered).is_err());
    }
}

