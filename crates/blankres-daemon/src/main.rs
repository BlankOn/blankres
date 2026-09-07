//! `blankresd`: the blankres crash reporting daemon.

use std::path::PathBuf;

use blankres_client::Client;
use blankres_collect::pkg::{DpkgBackend, DpkgIndex};
use blankres_collect::stage1::Stage1Collector;
use blankres_collect::stage2::Stage2Collector;
use blankres_collect::sys::RealFs;
use blankres_collect::system::{read_machine_id, system_info};
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
use blankres_daemon::journal::{JournalSource, JournalctlSource};
use blankres_daemon::oops::{starts_oops, OopsBuilder};
use blankres_daemon::reporter::{Outcome, Reporter};
use blankres_daemon::spool::Spool;
use blankres_daemon::state::State;
use clap::Parser;

#[derive(Parser)]
#[command(name = "blankresd", version, about = "blankres crash reporting daemon")]
struct Cli {
    /// Path to the client configuration.
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Process what is already in the journal and exit, instead of following it.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blankres_daemon=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = ClientConfig::load(&cli.config)?;

    if !config.telemetry_enabled {
        // The opt-in is a real gate, not a preference: with it off the daemon reads nothing and
        // sends nothing.
        tracing::warn!(
            "crash reporting is disabled; enable `telemetry_enabled` in {}",
            cli.config.display()
        );
        return Ok(());
    }

    let mut state = State::load(&config.state_path());
    // Generated on first run and persisted; it never leaves the machine.
    let salt = state.salt();
    state.save(&config.state_path()).ok();

    let fs = RealFs;
    let kernel_version = kernel_version();
    let system = system_info(&fs, kernel_version.clone());
    let machine_id = read_machine_id(&fs, salt.as_bytes());

    // The one expensive startup step: indexing dpkg's file lists so per-crash lookups are memory
    // reads rather than a fork of `dpkg-query`.
    let index = DpkgIndex::build_default(&fs);
    tracing::info!(paths = index.len(), "indexed dpkg file lists");

    let stage1 = Stage1Collector::new(
        fs,
        DpkgBackend::with_defaults(fs),
        system.clone(),
        machine_id.clone(),
    );
    let stage2 = Stage2Collector::new(fs, DpkgBackend::with_defaults(fs));

    let client = Client::new(config.endpoint.clone())?;
    let spool = Spool::new(config.spool_dir())?;
    let reporter = Reporter::new(stage1, stage2, client, config.clone(), spool);

    // Anything that failed to send while we were down goes first.
    reporter.drain_spool().await;

    let mut coredumps = JournalctlSource::coredumps(state.coredump_cursor.as_deref())?;
    let mut kernel = if config.kernel_oops {
        Some(JournalctlSource::kernel(state.kernel_cursor.as_deref())?)
    } else {
        None
    };

    tracing::info!(
        server = %config.endpoint.url,
        kernel_oops = config.kernel_oops,
        "blankresd watching the journal"
    );

    let mut oops: Option<OopsBuilder> = None;
    let mut shutdown = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }

            entry = coredumps.next_entry() => {
                let Some(entry) = entry else { break };
                if !entry.is_coredump() {
                    continue;
                }
                let record = entry.to_coredump_record();
                match reporter.handle_coredump(&record, &mut state).await {
                    Ok(outcome) => log_outcome(&outcome),
                    Err(err) => tracing::error!(error = %err, "handling crash"),
                }
                state.coredump_cursor = Some(entry.cursor);
                if let Err(err) = state.save(&config.state_path()) {
                    tracing::warn!(error = %err, "could not persist state");
                }
            }

            entry = async {
                match kernel.as_mut() {
                    Some(source) => source.next_entry().await,
                    // With kernel watching off, this branch must never resolve, or the select
                    // would spin.
                    None => std::future::pending().await,
                }
            } => {
                let Some(entry) = entry else { continue };
                let line = entry.message().to_owned();

                // Coalesce: an oops is a burst of lines, and one report per line is noise.
                match oops.as_mut() {
                    Some(builder) if builder.accepts(entry.timestamp) => builder.push(line),
                    Some(_) | None if starts_oops(&line) => {
                        if let Some(finished) = oops.take() {
                            flush_oops(&finished, &system, &machine_id, &mut state, &config).await;
                        }
                        oops = Some(OopsBuilder::new(entry.timestamp, line));
                    }
                    Some(_) => {
                        if let Some(finished) = oops.take() {
                            flush_oops(&finished, &system, &machine_id, &mut state, &config).await;
                        }
                    }
                    None => {}
                }

                state.kernel_cursor = Some(entry.cursor);
            }
        }

        if cli.once {
            break;
        }
    }

    if let Some(finished) = oops.take() {
        flush_oops(&finished, &system, &machine_id, &mut state, &config).await;
    }
    state.save(&config.state_path())?;
    coredumps.shutdown().await;
    if let Some(kernel) = kernel {
        kernel.shutdown().await;
    }

    Ok(())
}

/// Send a completed oops as a stage-1 event. There is never a payload for an oops — the journal
/// text is the whole of the evidence — so this path stops at stage 1 by construction.
async fn flush_oops(
    builder: &OopsBuilder,
    system: &blankres_report::event::SystemInfo,
    machine_id: &str,
    state: &mut State,
    config: &ClientConfig,
) {
    let probe = builder.to_event(system.clone(), machine_id.to_owned(), 0);
    if state.is_declined(&probe.signature.hash) {
        return;
    }
    let count = state.note_signature(&probe.signature.hash);
    let event = builder.to_event(system.clone(), machine_id.to_owned(), count);

    let Ok(client) = Client::new(config.endpoint.clone()) else {
        return;
    };
    match client.send_events(std::slice::from_ref(&event)).await {
        Ok(_) => tracing::info!(
            signature = %&event.signature.hash[..12],
            lines = builder.lines.len(),
            "reported kernel oops"
        ),
        Err(err) => {
            tracing::warn!(error = %err, "could not report oops; spooling");
            if let Ok(spool) = Spool::new(config.spool_dir()) {
                let _ = spool.push(&event);
            }
        }
    }
}

fn log_outcome(outcome: &Outcome) {
    match outcome {
        Outcome::Suppressed(reason) => tracing::debug!(%reason, "crash suppressed"),
        Outcome::ReportedCoreDropped { signature } => {
            tracing::info!(signature = %&signature[..12], "reported; core not wanted, removed")
        }
        Outcome::AwaitingConsent { signature, path } => tracing::info!(
            signature = %&signature[..12],
            path = %path.display(),
            "payload requested; awaiting user consent"
        ),
        Outcome::SpooledAwaitingConsent { signature, path } => tracing::info!(
            signature = %&signature[..12],
            path = %path.display(),
            "server unreachable; spooled and awaiting user consent"
        ),
    }
}

/// Kernel release string, read from `/proc/sys/kernel/osrelease` to avoid a libc dependency.
fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}
