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

    ensure_on_path();

    Ok(identity)
}

/// If the binary's directory isn't on PATH, append it to the user's shell rc.
fn ensure_on_path() {
    let bin_dir = match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        Some(d) => d,
        None => return,
    };

    let path_var = std::env::var("PATH").unwrap_or_default();
    if path_var.split(':').any(|p| std::path::Path::new(p) == bin_dir) {
        return;
    }

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let export_line = format!("\nexport PATH=\"{}:$PATH\"\n", bin_dir.display());

    // Try zshrc first (macOS default), fall back to bashrc
    let rc = std::path::Path::new(&home).join(".zshrc");
    let rc = if rc.exists() { rc } else { std::path::Path::new(&home).join(".bashrc") };

    // Don't duplicate if already present
    if let Ok(contents) = fs::read_to_string(&rc) {
        if contents.contains(&format!("{}", bin_dir.display())) {
            return;
        }
    }

    if fs::OpenOptions::new().append(true).create(true).open(&rc)
        .and_then(|mut f| std::io::Write::write_all(&mut f, export_line.as_bytes()))
        .is_ok()
    {
        eprintln!("added {} to PATH in {}", bin_dir.display(), rc.display());
        eprintln!("restart your shell or run: source {}", rc.display());
    }
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

pub fn add_peer(username: &str, encryption_key: &str, verifying_key: &str) -> Result<(), XmitError> {
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
