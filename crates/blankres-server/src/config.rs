//! Server configuration.
//!
//! Read from a TOML-ish JSON file and overridable by environment, because the two deployments
//! that matter — a developer's laptop and a container — want different sources.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to bind, e.g. `127.0.0.1:8080`. TLS is a reverse proxy's job.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Postgres connection string.
    pub database_url: String,
    /// Root of the blob store.
    #[serde(default = "default_storage")]
    pub storage_root: PathBuf,
    /// SHA-256 hashes of accepted fleet tokens. Hashed at rest so the config file is not itself a
    /// credential; `blankres-ingest hash-token` produces them.
    #[serde(default)]
    pub token_hashes: Vec<String>,
    /// How many stage-2 payloads to keep per signature before declining further ones. This single
    /// number is what turns a fleet-wide flood of cores into a handful.
    #[serde(default = "default_payload_quota")]
    pub payloads_per_signature: i64,
    /// Largest payload the server will accept, in bytes.
    #[serde(default = "default_max_bytes")]
    pub max_payload_bytes: u64,
    /// How long an upload token stays valid.
    #[serde(default = "default_token_ttl")]
    pub upload_token_ttl_secs: i64,
    /// Public base URL, used to build the `url` in an upload receipt.
    #[serde(default)]
    pub public_url: Option<String>,
}

fn default_bind() -> String {
    "127.0.0.1:8080".to_owned()
}

fn default_storage() -> PathBuf {
    PathBuf::from("/var/lib/blankres-ingest")
}

fn default_payload_quota() -> i64 {
    5
}

fn default_max_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

fn default_token_ttl() -> i64 {
    3600
}

impl Config {
    /// Load from a JSON file, then apply environment overrides.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
                    path: path.display().to_string(),
                    source,
                })?;
                serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
                    path: path.display().to_string(),
                    source,
                })?
            }
            None => Self {
                bind: default_bind(),
                database_url: String::new(),
                storage_root: default_storage(),
                token_hashes: Vec::new(),
                payloads_per_signature: default_payload_quota(),
                max_payload_bytes: default_max_bytes(),
                upload_token_ttl_secs: default_token_ttl(),
                public_url: None,
            },
        };

        if let Ok(url) = std::env::var("BLANKRES_DATABASE_URL") {
            config.database_url = url;
        } else if let Ok(url) = std::env::var("DATABASE_URL") {
            config.database_url = url;
        }
        if let Ok(bind) = std::env::var("BLANKRES_BIND") {
            config.bind = bind;
        }
        if let Ok(root) = std::env::var("BLANKRES_STORAGE_ROOT") {
            config.storage_root = PathBuf::from(root);
        }
        // Convenience for development: a plaintext token in the environment is hashed here so the
        // comparison path never has a plaintext branch.
        if let Ok(token) = std::env::var("BLANKRES_TOKEN") {
            config.token_hashes.push(hash_token(&token));
        }
        if let Ok(quota) = std::env::var("BLANKRES_PAYLOADS_PER_SIGNATURE") {
            if let Ok(quota) = quota.parse() {
                config.payloads_per_signature = quota;
            }
        }

        if config.database_url.is_empty() {
            return Err(ConfigError::MissingDatabaseUrl);
        }

        Ok(config)
    }
}

/// Hash a fleet token for storage and comparison.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"blankres-token-v1\0");
    hasher.update(token.trim().as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "no database url: set `database_url` in the config or DATABASE_URL in the environment"
    )]
    MissingDatabaseUrl,
}
