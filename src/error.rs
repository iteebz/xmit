use thiserror::Error;

#[derive(Error, Debug)]
pub enum XmitError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("relay: {0}")]
    Relay(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
