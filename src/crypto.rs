use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::XmitError;

const HKDF_INFO: &[u8] = b"xmit-v0-aes256gcm";

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

fn derive_key(shared: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is valid for HKDF-SHA256");
    key
}

pub fn shared_secret(our_secret: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    let raw = our_secret.diffie_hellman(their_public).to_bytes();
    derive_key(&raw)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, XmitError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| XmitError::Crypto(e.to_string()))?;
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

pub fn decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, XmitError> {
    let combined = B64.decode(encoded).map_err(|e| XmitError::Crypto(e.to_string()))?;
    if combined.len() < 12 {
        return Err(XmitError::Crypto("ciphertext too short".into()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| XmitError::Crypto(e.to_string()))
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> String {
    let signature = signing_key.sign(message);
    B64.encode(signature.to_bytes())
}

pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature_b64: &str) -> Result<(), XmitError> {
    let sig_bytes = B64
        .decode(signature_b64)
        .map_err(|e| XmitError::Crypto(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| XmitError::Crypto(e.to_string()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| XmitError::Crypto(format!("signature verification failed: {e}")))
}

// --- key encoding ---

pub fn encode_public_key(key: &PublicKey) -> String {
    B64.encode(key.as_bytes())
}

pub fn decode_public_key(encoded: &str) -> Result<PublicKey, XmitError> {
    let bytes = B64.decode(encoded).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid public key length".into()))?;
    Ok(PublicKey::from(arr))
}

pub fn encode_secret_key(key: &StaticSecret) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_secret_key(encoded: &str) -> Result<StaticSecret, XmitError> {
    let bytes = B64.decode(encoded).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid secret key length".into()))?;
    Ok(StaticSecret::from(arr))
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_signing_key(encoded: &str) -> Result<SigningKey, XmitError> {
    let bytes = B64.decode(encoded).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid signing key length".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, XmitError> {
    let bytes = B64.decode(encoded).map_err(|e| XmitError::Crypto(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| XmitError::Crypto("invalid verifying key length".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| XmitError::Crypto(e.to_string()))
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
    fn hkdf_produces_different_key_than_raw_dh() {
        let (alice_secret, _) = generate_keypair();
        let (_, bob_public) = generate_keypair();
        let raw = alice_secret.diffie_hellman(&bob_public).to_bytes();
        let derived = derive_key(&raw);
        assert_ne!(raw, derived);
    }

    #[test]
    fn roundtrip_sign_verify() {
        let (signing, verifying) = generate_signing_keypair();
        let message = b"swarm coordination payload";
        let sig = sign(&signing, message);
        verify(&verifying, message, &sig).unwrap();
    }

    #[test]
    fn signature_rejects_tampered_message() {
        let (signing, verifying) = generate_signing_keypair();
        let sig = sign(&signing, b"original");
        assert!(verify(&verifying, b"tampered", &sig).is_err());
    }

    #[test]
    fn signature_rejects_wrong_key() {
        let (signing, _) = generate_signing_keypair();
        let (_, wrong_verifying) = generate_signing_keypair();
        let sig = sign(&signing, b"message");
        assert!(verify(&wrong_verifying, b"message", &sig).is_err());
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

    #[test]
    fn roundtrip_signing_key_encoding() {
        let (signing, verifying) = generate_signing_keypair();

        let sk_encoded = encode_signing_key(&signing);
        let sk_decoded = decode_signing_key(&sk_encoded).unwrap();
        assert_eq!(signing.to_bytes(), sk_decoded.to_bytes());

        let vk_encoded = encode_verifying_key(&verifying);
        let vk_decoded = decode_verifying_key(&vk_encoded).unwrap();
        assert_eq!(verifying.to_bytes(), vk_decoded.to_bytes());
    }
}
