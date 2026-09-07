//! Application wiring: configuration, the pending store, and the watch that surfaces new crashes.

use std::path::PathBuf;

use blankres_client::Endpoint;
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
use blankres_i18n::Catalog;
use blankres_session::{current_uid, PendingStore};

/// Everything the window needs, resolved once at startup.
#[derive(Clone)]
pub struct AppContext {
    pub store: PendingStore,
    pub endpoint: Endpoint,
    pub config_path: PathBuf,
    pub telemetry_enabled: bool,
    /// Resolved once, so every string in one window comes from the same language.
    pub catalog: Catalog,
}

impl AppContext {
    /// Load configuration, falling back to defaults so the window can still explain itself on a
    /// machine where the daemon was never configured.
    pub fn load() -> Self {
        let config_path = std::env::var("BLANKRES_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG));

        // A configuration that cannot be read used to fall back silently, which pointed the
        // window at the default /var/crash and produced an empty list indistinguishable from
        // having nothing to report. Say so instead.
        let config = match ClientConfig::load(&config_path) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(
                    path = %config_path.display(),
                    error = %err,
                    "could not read the configuration; falling back to defaults"
                );
                ClientConfig::default()
            }
        };

        Self {
            store: PendingStore::new(config.crash_dir.clone(), current_uid()),
            endpoint: config.endpoint.clone(),
            config_path,
            telemetry_enabled: config.telemetry_enabled,
            catalog: Catalog::detect(),
        }
    }
}
