use tokio_postgres::NoTls;

use crate::error::XmitError;

/// Schema bootstrap — run once per database.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    from_username TEXT NOT NULL REFERENCES users(username),
    to_username TEXT NOT NULL REFERENCES users(username),
    payload TEXT NOT NULL,
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

        if use_tls {
            use rustls_platform_verifier::ConfigVerifierExt as _;
            let config = rustls::ClientConfig::with_platform_verifier()
                .map_err(|e| XmitError::Relay(e.to_string()))?;
            let tls = tokio_postgres_rustls::MakeRustlsConnect::new(config);
            let (client, connection) = tokio_postgres::connect(database_url, tls)
                .await
                .map_err(|e| XmitError::Relay(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("relay connection error: {e}");
                }
            });
            Ok(Self { client })
        } else {
            let (client, connection) = tokio_postgres::connect(database_url, NoTls)
                .await
                .map_err(|e| XmitError::Relay(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("relay connection error: {e}");
                }
            });
            Ok(Self { client })
        }
    }

    pub async fn migrate(&self) -> Result<(), XmitError> {
        self.client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))
    }

    pub async fn register(&self, username: &str, public_key: &str) -> Result<(), XmitError> {
        self.client
            .execute(
                "INSERT INTO users (username, public_key) VALUES ($1, $2)
                 ON CONFLICT (username) DO UPDATE SET public_key = $2",
                &[&username, &public_key],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?;
        Ok(())
    }

    pub async fn lookup_key(&self, username: &str) -> Result<String, XmitError> {
        let row = self
            .client
            .query_opt(
                "SELECT public_key FROM users WHERE username = $1",
                &[&username],
            )
            .await
            .map_err(|e| XmitError::Relay(e.to_string()))?
            .ok_or_else(|| XmitError::Relay(format!("user '{username}' not found on relay")))?;
        Ok(row.get(0))
    }

    pub async fn send(
        &self,
        from: &str,
        to: &str,
        encrypted_payload: &str,
    ) -> Result<(), XmitError> {
        self.client
            .execute(
                "INSERT INTO messages (from_username, to_username, payload) VALUES ($1, $2, $3)",
                &[&from, &to, &encrypted_payload],
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
                 RETURNING id, from_username, payload, created_at::text",
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
                created_at: row.get::<_, String>(3),
            })
            .collect())
    }

    pub async fn list_pending(&self, username: &str) -> Result<Vec<Message>, XmitError> {
        let rows = self
            .client
            .query(
                "SELECT id, from_username, payload, created_at::text
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
                created_at: row.get::<_, String>(3),
            })
            .collect())
    }
}

pub struct Message {
    pub id: i64,
    pub from: String,
    pub payload: String,
    pub created_at: String,
}
