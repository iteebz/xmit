use std::io::Read as _;

use clap::{Parser, Subcommand};

mod crypto;
mod error;
mod identity;
mod relay;

use error::XmitError;

#[derive(Parser)]
#[command(name = "xmit", about = "e2e encrypted messaging between agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate keypair and claim a username
    Init {
        /// Username to claim (e.g. tyson)
        username: String,
    },
    /// Trust a peer by username (fetches their public key from relay)
    Trust {
        /// Peer username to trust
        username: String,
    },
    /// Send an encrypted payload to a peer
    Send {
        /// Recipient username
        to: String,
        /// File to send (reads stdin if omitted)
        file: Option<String>,
    },
    /// Receive and decrypt pending messages
    Recv,
    /// List pending messages without consuming them
    Ls,
    /// Run relay migrations (admin only)
    Migrate,
}

fn relay_url() -> Result<String, XmitError> {
    std::env::var("XMIT_RELAY_URL").map_err(|_| {
        XmitError::Relay("XMIT_RELAY_URL not set. export your neon connection string.".into())
    })
}

async fn connect_relay() -> Result<relay::Relay, XmitError> {
    let url = relay_url()?;
    relay::Relay::connect(&url).await
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli.command).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(command: Command) -> Result<(), XmitError> {
    match command {
        Command::Init { username } => {
            let id = identity::init(&username)?;
            let relay = connect_relay().await?;
            relay.register(&username, &id.public_key).await?;
            println!("identity created: {username}");
            println!("public key: {}", id.public_key);
        }
        Command::Trust { username } => {
            let relay = connect_relay().await?;
            let public_key = relay.lookup_key(&username).await?;
            identity::add_peer(&username, &public_key)?;
            println!("trusted: {username}");
        }
        Command::Send { to, file } => {
            let id = identity::load()?;
            let peer_key_str = identity::get_peer_key(&to)?;
            let peer_key = crypto::decode_public_key(&peer_key_str)?;
            let our_secret = crypto::decode_secret_key(&id.secret_key)?;
            let shared = crypto::shared_secret(&our_secret, &peer_key);

            let plaintext = if let Some(path) = file {
                std::fs::read(&path)?
            } else {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            };

            let encrypted = crypto::encrypt(&shared, &plaintext)?;
            let relay = connect_relay().await?;
            relay.send(&id.username, &to, &encrypted).await?;
            println!("sent {} bytes to {to}", plaintext.len());
        }
        Command::Recv => {
            let id = identity::load()?;
            let our_secret = crypto::decode_secret_key(&id.secret_key)?;
            let relay = connect_relay().await?;
            let messages = relay.receive(&id.username).await?;

            if messages.is_empty() {
                println!("no messages");
                return Ok(());
            }

            for msg in &messages {
                let peer_key_str = identity::get_peer_key(&msg.from)?;
                let peer_key = crypto::decode_public_key(&peer_key_str)?;
                let shared = crypto::shared_secret(&our_secret, &peer_key);

                match crypto::decrypt(&shared, &msg.payload) {
                    Ok(plaintext) => {
                        println!("--- from: {} | {} ---", msg.from, msg.created_at);
                        match String::from_utf8(plaintext) {
                            Ok(text) => println!("{text}"),
                            Err(e) => println!("[binary payload, {} bytes]", e.into_bytes().len()),
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "failed to decrypt message {} from {}: {e}",
                            msg.id, msg.from
                        );
                    }
                }
            }
        }
        Command::Ls => {
            let relay = connect_relay().await?;
            let id = identity::load()?;
            let messages = relay.list_pending(&id.username).await?;

            if messages.is_empty() {
                println!("no pending messages");
                return Ok(());
            }

            for msg in &messages {
                println!(
                    "{} | from: {} | {} bytes",
                    msg.created_at,
                    msg.from,
                    msg.payload.len()
                );
            }
        }
        Command::Migrate => {
            let relay = connect_relay().await?;
            relay.migrate().await?;
            println!("migrations applied");
        }
    }
    Ok(())
}
