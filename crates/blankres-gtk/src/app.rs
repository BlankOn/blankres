//! Application wiring: configuration, the pending store, and the watch that surfaces new crashes.

use std::path::PathBuf;

use blankres_client::Endpoint;
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
use blankres_session::{current_uid, PendingStore};

/// Everything the window needs, resolved once at startup.
#[derive(Clone)]
pub struct AppContext {
    pub store: PendingStore,
    pub endpoint: Endpoint,
    pub config_path: PathBuf,
    pub telemetry_enabled: bool,
}

impl AppContext {
    /// Load configuration, falling back to defaults so the window can still explain itself on a
    /// machine where the daemon was never configured.
    pub fn load() -> Self {
        let config_path = std::env::var("BLANKRES_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG));

        let config = ClientConfig::load(&config_path).unwrap_or_default();

        Self {
            store: PendingStore::new(config.crash_dir.clone(), current_uid()),
            endpoint: config.endpoint.clone(),
            config_path,
            telemetry_enabled: config.telemetry_enabled,
        }
    }
}
