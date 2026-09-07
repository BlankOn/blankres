//! Client-side configuration, shared by the daemon and the front ends.

use std::path::{Path, PathBuf};

use blankres_client::Endpoint;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = "/etc/blankres/client.json";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/blankres";
pub const DEFAULT_CRASH_DIR: &str = "/var/crash";
/// Where reports go unless configured otherwise.
pub const DEFAULT_SERVER: &str = "https://kres.blankonlinux.id";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Where to report.
    pub endpoint: Endpoint,
    /// The one-time opt-in. Until this is true the daemon collects nothing and sends nothing:
    /// stage 1 is automatic, but only once the user has agreed to it at all.
    #[serde(default)]
    pub telemetry_enabled: bool,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_crash_dir")]
    pub crash_dir: PathBuf,
    /// How long to wait for the server to say whether it wants a payload before showing the
    /// crash to the user regardless. Short on purpose: this is a person waiting to find out why
    /// their program vanished, not a batch job.
    #[serde(default = "default_directive_timeout")]
    pub directive_timeout_secs: u64,
    /// How many crashes of one executable to report per hour before suppressing the rest. Guards
    /// against a program stuck in a crash loop burying everything else, at the cost of hiding
    /// repeated crashes of something genuinely broken. Raise it when testing.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_hour: u32,
    /// Watch the kernel journal for oopses as well as user-space crashes.
    #[serde(default = "default_true")]
    pub kernel_oops: bool,
    /// Delete the core dump when the server declines the payload. This is where the disk saving
    /// over apport actually happens, so turning it off should be deliberate.
    #[serde(default = "default_true")]
    pub delete_declined_cores: bool,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR)
}

fn default_crash_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CRASH_DIR)
}

fn default_directive_timeout() -> u64 {
    3
}

fn default_rate_limit() -> u32 {
    6
}

fn default_true() -> bool {
    true
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: Endpoint::new(DEFAULT_SERVER, ""),
            telemetry_enabled: false,
            directive_timeout_secs: default_directive_timeout(),
            rate_limit_per_hour: default_rate_limit(),
            state_dir: default_state_dir(),
            crash_dir: default_crash_dir(),
            kernel_oops: true,
            delete_declined_cores: true,
        }
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let mut config: Self =
            serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.display().to_string(),
                source,
            })?;

        // Environment overrides exist so a developer can point a packaged daemon at a local
        // server without editing a root-owned file.
        if let Ok(url) = std::env::var("BLANKRES_SERVER_URL") {
            config.endpoint.url = url;
        }
        if let Ok(token) = std::env::var("BLANKRES_TOKEN") {
            config.endpoint.token = token;
        }
        if std::env::var("BLANKRES_TELEMETRY").as_deref() == Ok("1") {
            config.telemetry_enabled = true;
        }
        if let Ok(limit) = std::env::var("BLANKRES_RATE_LIMIT_PER_HOUR") {
            if let Ok(limit) = limit.parse() {
                config.rate_limit_per_hour = limit;
            }
        }

        Ok(config)
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.state_dir.join("spool")
    }
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
}
