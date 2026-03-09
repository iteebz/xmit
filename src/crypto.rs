use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::XmitError;

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn shared_secret(our_secret: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    our_secret.diffie_hellman(their_public).to_bytes()
}

pub fn encrypt(shared: &[u8; 32], plaintext: &[u8]) -> Result<String, XmitError> {
    let cipher = Aes256Gcm::new_from_slice(shared).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| XmitError::Crypto(e.to_string()))?;

    // nonce || ciphertext, base64 encoded
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(B64.encode(&combined))
}

pub fn decrypt(shared: &[u8; 32], encoded: &str) -> Result<Vec<u8>, XmitError> {
    let combined = B64
        .decode(encoded)
        .map_err(|e| XmitError::Crypto(e.to_string()))?;
    if combined.len() < 12 {
        return Err(XmitError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(shared).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| XmitError::Crypto(e.to_string()))
}

pub fn encode_public_key(key: &PublicKey) -> String {
    B64.encode(key.as_bytes())
}

pub fn decode_public_key(encoded: &str) -> Result<PublicKey, XmitError> {
    let bytes = B64
        .decode(encoded)
        .map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid public key length".into()))?;
    Ok(PublicKey::from(arr))
}

pub fn encode_secret_key(key: &StaticSecret) -> String {
    // StaticSecret doesn't expose bytes directly, we need to clone
    B64.encode(key.to_bytes())
}

pub fn decode_secret_key(encoded: &str) -> Result<StaticSecret, XmitError> {
    let bytes = B64
        .decode(encoded)
        .map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid secret key length".into()))?;
    Ok(StaticSecret::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let (alice_secret, alice_public) = generate_keypair();
        let (bob_secret, bob_public) = generate_keypair();

        let alice_shared = shared_secret(&alice_secret, &bob_public);
        let bob_shared = shared_secret(&bob_secret, &alice_public);
        assert_eq!(alice_shared, bob_shared);

        let plaintext = b"context payload from tyson's swarm";
        let encrypted = encrypt(&alice_shared, plaintext).unwrap();
        let decrypted = decrypt(&bob_shared, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_key_encoding() {
        let (secret, public) = generate_keypair();

        let pub_encoded = encode_public_key(&public);
        let pub_decoded = decode_public_key(&pub_encoded).unwrap();
        assert_eq!(public.as_bytes(), pub_decoded.as_bytes());

        let sec_encoded = encode_secret_key(&secret);
        let sec_decoded = decode_secret_key(&sec_encoded).unwrap();
        assert_eq!(secret.to_bytes(), sec_decoded.to_bytes());
    }
}
