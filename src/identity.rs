use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::XmitError;

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub username: String,
    pub secret_key: String,
    pub public_key: String,
    pub peers: HashMap<String, String>, // username -> public_key
}

fn config_dir() -> Result<PathBuf, XmitError> {
    let dir = dirs::config_dir()
        .ok_or_else(|| XmitError::Identity("no config directory found".into()))?
        .join("xmit");
    Ok(dir)
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
    let identity = Identity {
        username: username.to_string(),
        secret_key: crypto::encode_secret_key(&secret),
        public_key: crypto::encode_public_key(&public),
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
    let identity: Identity =
        serde_json::from_str(&data).map_err(|e| XmitError::Identity(e.to_string()))?;
    Ok(identity)
}

pub fn save(identity: &Identity) -> Result<(), XmitError> {
    let path = identity_path()?;
    fs::write(&path, serde_json::to_string_pretty(identity).unwrap())?;
    Ok(())
}

pub fn add_peer(username: &str, public_key: &str) -> Result<(), XmitError> {
    let mut identity = load()?;
    // validate the key decodes
    crypto::decode_public_key(public_key)?;
    identity
        .peers
        .insert(username.to_string(), public_key.to_string());
    save(&identity)
}

pub fn get_peer_key(username: &str) -> Result<String, XmitError> {
    let identity = load()?;
    identity.peers.get(username).cloned().ok_or_else(|| {
        XmitError::Identity(format!(
            "no trusted peer '{username}'. run `xmit trust {username}` first."
        ))
    })
}
