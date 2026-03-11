use tokio_postgres::NoTls;

use crate::error::XmitError;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    encryption_key TEXT NOT NULL,
    verifying_key TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    from_username TEXT NOT NULL REFERENCES users(username),
    to_username TEXT NOT NULL REFERENCES users(username),
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    received BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_username, received);
";

pub struct Relay {
    client: tokio_postgres::Client,
}

impl Relay {
    pub async fn connect(database_url: &str) -> Result<Self, XmitError> {
        let use_tls = database_url.contains("sslmode=require") || database_url.contains("neon");

        let client = if use_tls {
            use rustls_platform_verifier::ConfigVerifierExt as _;
            let config = rustls::ClientConfig::with_platform_verifier().map_err(|e| XmitError::Relay(e.to_string()))?;
            let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
            let (client, connection) = tokio_postgres::connect(database_url, tls)
                .await
                .map_err(|e| XmitError::Relay(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("relay connection error: {e}");
                }
            });
            client
        } else {
            let (client, connection) = tokio_postgres::connect(database_url, NoTls)
                .await
                .map_err(|e| XmitError::Relay(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("relay connection error: {e}");
                }
            });
            client
        };

        Ok(Self { client })
    }

    pub async fn migrate(&self) -> Result<(), XmitError> {
        self.client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))
    }

    pub async fn register(&self, username: &str, encryption_key: &str, verifying_key: &str) -> Result<(), XmitError> {
        self.client
            .execute(
                "INSERT INTO users (username, encryption_key, verifying_key) VALUES ($1, $2, $3)
                 ON CONFLICT (username) DO UPDATE SET encryption_key = $2, verifying_key = $3",
                &[&username, &encryption_key, &verifying_key],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?;
        Ok(())
    }

    pub async fn lookup_keys(&self, username: &str) -> Result<(String, String), XmitError> {
        let row = self
            .client
            .query_opt(
                "SELECT encryption_key, verifying_key FROM users WHERE username = $1",
                &[&username],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?
            .ok_or_else(|| XmitError::Relay(format!("user '{username}' not found on relay")))?;
        Ok((row.get(0), row.get(1)))
    }

    pub async fn send(&self, from: &str, to: &str, payload: &str, signature: &str) -> Result<(), XmitError> {
        self.client
            .execute(
                "INSERT INTO messages (from_username, to_username, payload, signature) VALUES ($1, $2, $3, $4)",
                &[&from, &to, &payload, &signature],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?;
        Ok(())
    }

    pub async fn receive(&self, username: &str) -> Result<Vec<Message>, XmitError> {
        let rows = self
            .client
            .query(
                "UPDATE messages SET received = true
                 WHERE to_username = $1 AND received = false
                 RETURNING id, from_username, payload, signature, created_at::text",
                &[&username],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| Message {
                id: row.get::<_, i64>(0),
                from: row.get(1),
                payload: row.get(2),
                signature: row.get(3),
                created_at: row.get::<_, String>(4),
            })
            .collect())
    }

    pub async fn list_pending(&self, username: &str) -> Result<Vec<Message>, XmitError> {
        let rows = self
            .client
            .query(
                "SELECT id, from_username, payload, signature, created_at::text
                 FROM messages WHERE to_username = $1 AND received = false
                 ORDER BY created_at",
                &[&username],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|row| Message {
                id: row.get::<_, i64>(0),
                from: row.get(1),
                payload: row.get(2),
                signature: row.get(3),
                created_at: row.get::<_, String>(4),
            })
            .collect())
    }
}

pub struct Message {
    pub id: i64,
    pub from: String,
    pub payload: String,
    pub signature: String,
    pub created_at: String,
}
