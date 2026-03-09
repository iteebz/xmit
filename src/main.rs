use clap::{Parser, Subcommand};

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
    /// Trust a peer by username
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
    /// Receive pending messages
    Recv,
    /// List pending messages without consuming them
    Ls,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { username } => {
            println!("init: {username}");
        }
        Command::Trust { username } => {
            println!("trust: {username}");
        }
        Command::Send { to, file } => {
            let source = file.as_deref().unwrap_or("stdin");
            println!("send to {to} from {source}");
        }
        Command::Recv => {
            println!("recv");
        }
        Command::Ls => {
            println!("ls");
        }
    }
}
