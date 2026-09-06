//! `blankres-apt-hook`: reports packages whose install or upgrade failed.
//!
//! Installed as an apt `Post-Invoke` hook, so it runs once after each apt run rather than
//! watching anything. There is no core dump for a package failure, so this only ever performs
//! stage 1 — it sends a small event and exits.

use std::path::PathBuf;

use blankres_client::Client;
use blankres_collect::pkg::{DpkgBackend, DpkgIndex, PackageBackend};
use blankres_collect::sys::RealFs;
use blankres_collect::system::{read_machine_id, system_info};
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
use blankres_daemon::state::State;
use blankres_hooks::{newest_timestamp, parse_dpkg_log, DPKG_LOG};
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(
    name = "blankres-apt-hook",
    version,
    about = "Report failed package operations"
)]
struct Cli {
    /// Path to the client configuration.
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// dpkg log to inspect.
    #[arg(long, default_value = DPKG_LOG)]
    dpkg_log: PathBuf,
    /// Report what would be sent without sending it.
    #[arg(long)]
    dry_run: bool,
}

/// Remembers how far into the dpkg log we have already reported.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HookState {
    #[serde(default)]
    last_reported: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blankres_hooks=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // A hook runs inside the user's apt invocation. If anything here is missing or misconfigured
    // it must exit quietly and successfully: breaking `apt install` to report a bug would be a
    // far worse failure than missing the report.
    let Ok(config) = ClientConfig::load(&cli.config) else {
        return Ok(());
    };
    if !config.telemetry_enabled {
        return Ok(());
    }

    let state_path = config.state_dir.join("apt-hook.json");
    let state: HookState = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();

    let Ok(log) = std::fs::read_to_string(&cli.dpkg_log) else {
        return Ok(());
    };
    let failures = parse_dpkg_log(&log, state.last_reported.as_deref());
    if failures.is_empty() {
        return Ok(());
    }

    let fs = RealFs;
    let system = system_info(&fs, kernel_version());
    // The salt lives in the daemon's state file; the hook reads it rather than minting its own,
    // so a package failure and a segfault on the same host report the same machine identity.
    let mut daemon_state = State::load(&config.state_path());
    let salt = daemon_state.salt();
    let _ = daemon_state.save(&config.state_path());
    let machine_id = read_machine_id(&fs, salt.as_bytes());
    let index = DpkgIndex::build_default(&fs);
    let packages = DpkgBackend::new(
        fs,
        index,
        blankres_collect::pkg::DPKG_INFO_DIR,
        std::path::Path::new(blankres_collect::pkg::DPKG_STATUS),
    );
    let now = now_secs();

    let events: Vec<_> = failures
        .iter()
        .map(|failure| {
            // The version comes from dpkg's own status file rather than the log line, so it
            // matches what every other report says about this package.
            let version = packages
                .owner(std::path::Path::new(&format!(
                    "/usr/bin/{}",
                    failure.package
                )))
                .and_then(|info| info.version);
            failure.to_event(version, system.clone(), machine_id.clone(), 1, now)
        })
        .collect();

    if cli.dry_run {
        for event in &events {
            println!("{}", serde_json::to_string_pretty(event)?);
        }
        return Ok(());
    }

    match Client::new(config.endpoint.clone()) {
        Ok(client) => match client.send_events(&events).await {
            Ok(_) => tracing::info!(count = events.len(), "reported package failures"),
            Err(err) => {
                tracing::warn!(error = %err, "could not report package failures");
                // Not advancing the cursor means the next apt run tries again.
                return Ok(());
            }
        },
        Err(err) => {
            tracing::warn!(error = %err, "could not build a client");
            return Ok(());
        }
    }

    if let Some(newest) = newest_timestamp(&failures) {
        let _ = std::fs::create_dir_all(&config.state_dir);
        let _ = std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&HookState {
                last_reported: Some(newest),
            })?,
        );
    }

    Ok(())
}

fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
