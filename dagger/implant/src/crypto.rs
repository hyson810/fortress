use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

/// Ephemeral keypair for key exchange
pub struct EphemeralKeys {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeys {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Compute shared secret from our private key + server's public key
pub fn compute_shared(secret: &StaticSecret, server_pub: &PublicKey) -> [u8; KEY_SIZE] {
    *secret.diffie_hellman(server_pub).as_bytes()
}

/// Derive session key from shared secret using HKDF
pub fn derive_session_key(shared: &[u8; KEY_SIZE], salt: &[u8], info: &[u8]) -> [u8; KEY_SIZE] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; KEY_SIZE];
    hk.expand(info, &mut okm).expect("HKDF expand should not fail for 32B output");
    okm
}

/// Encrypt plaintext with XChaCha20-Poly1305
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CryptoError::RngError)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptError)?;
    let mut out = nonce_bytes.to_vec();
    out.append(&mut ciphertext);
    Ok(out)
}

/// Decrypt ciphertext (nonce || payload) with XChaCha20-Poly1305
pub fn decrypt(key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::TooShort);
    }
    let (nonce_bytes, payload) = ciphertext.split_at(NONCE_SIZE);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptError)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key")]
    InvalidKey,
    #[error("ciphertext too short")]
    TooShort,
    #[error("encryption failed")]
    EncryptError,
    #[error("decryption failed: wrong key or corrupted data")]
    DecryptError,
    #[error("RNG error")]
    RngError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let msg = b"the quick brown fox jumps over the lazy dog";
        let ct = encrypt(&key, msg).unwrap();
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_key_exchange() {
        let client = EphemeralKeys::generate();
        let server = EphemeralKeys::generate();
        let shared_client = compute_shared(&client.secret, &PublicKey::from(server.public));
        let shared_server = compute_shared(&server.secret, &PublicKey::from(client.public));
        assert_eq!(shared_client, shared_server);
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = [0x11u8; KEY_SIZE];
        let k2 = [0x22u8; KEY_SIZE];
        let ct = encrypt(&k1, b"secret").unwrap();
        assert!(decrypt(&k2, &ct).is_err());
    }
}
