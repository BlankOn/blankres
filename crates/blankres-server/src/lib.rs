//! The blankres ingest server.
//!
//! Two endpoints, matching the two reporting stages: a cheap one that every crash reaches, and an
//! expensive one that only a server-issued capability opens. The interesting logic is a single
//! comparison in [`db::record_event`] — whether this signature already has enough stored cores —
//! and everything else is plumbing around keeping that decision honest.

pub mod config;
pub mod db;
pub mod routes;
pub mod storage;

pub use config::Config;
pub use routes::{router, AppState, SharedState};

use std::sync::Arc;

/// Connect, migrate, and build the application.
pub async fn build(config: Config) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let pool = db::connect(&config.database_url).await?;
    let storage = storage::LocalStorage::new(&config.storage_root).await?;
    let state: SharedState = Arc::new(AppState {
        pool,
        storage,
        config,
    });
    Ok(router(state))
}
