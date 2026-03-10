use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::XmitError;

#[derive(Serialize, Deserialize)]
pub struct Peer {
    pub encryption_key: String, // x25519 public
    pub verifying_key: String,  // ed25519 public
}

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub username: String,
    pub secret_key: String,    // x25519 secret
    pub public_key: String,    // x25519 public
    pub signing_key: String,   // ed25519 secret
    pub verifying_key: String, // ed25519 public
    pub peers: HashMap<String, Peer>,
}

fn config_dir() -> Result<PathBuf, XmitError> {
    let home = std::env::var("HOME").map_err(|_| XmitError::Identity("HOME not set".into()))?;
    Ok(PathBuf::from(home).join(".xmit"))
}

fn identity_path() -> Result<PathBuf, XmitError> {
    Ok(config_dir()?.join("identity.json"))
}

pub fn init(username: &str) -> Result<Identity, XmitError> {
    let path = identity_path()?;
    if path.exists() {
        return Err(XmitError::Identity(format!(
            "identity already exists at {}. delete it to reinitialize.",
            path.display()
        )));
    }

    let (secret, public) = crypto::generate_keypair();
    let (signing, verifying) = crypto::generate_signing_keypair();

    let identity = Identity {
        username: username.to_string(),
        secret_key: crypto::encode_secret_key(&secret),
        public_key: crypto::encode_public_key(&public),
        signing_key: crypto::encode_signing_key(&signing),
        verifying_key: crypto::encode_verifying_key(&verifying),
        peers: HashMap::new(),
    };

    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    fs::write(&path, serde_json::to_string_pretty(&identity).unwrap())?;

    Ok(identity)
}

pub fn load() -> Result<Identity, XmitError> {
    let path = identity_path()?;
    if !path.exists() {
        return Err(XmitError::Identity(
            "no identity found. run `xmit init <username>` first.".into(),
        ));
    }
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(|e| XmitError::Identity(e.to_string()))
}

pub fn save(identity: &Identity) -> Result<(), XmitError> {
    let path = identity_path()?;
    fs::write(&path, serde_json::to_string_pretty(identity).unwrap())?;
    Ok(())
}

pub fn add_peer(
    username: &str,
    encryption_key: &str,
    verifying_key: &str,
) -> Result<(), XmitError> {
    let mut identity = load()?;
    crypto::decode_public_key(encryption_key)?;
    crypto::decode_verifying_key(verifying_key)?;
    identity.peers.insert(
        username.to_string(),
        Peer {
            encryption_key: encryption_key.to_string(),
            verifying_key: verifying_key.to_string(),
        },
    );
    save(&identity)
}

pub fn get_peer(username: &str) -> Result<Peer, XmitError> {
    let identity = load()?;
    identity
        .peers
        .get(username)
        .map(|p| Peer {
            encryption_key: p.encryption_key.clone(),
            verifying_key: p.verifying_key.clone(),
        })
        .ok_or_else(|| {
            XmitError::Identity(format!(
                "no trusted peer '{username}'. run `xmit trust {username}` first."
            ))
        })
}
