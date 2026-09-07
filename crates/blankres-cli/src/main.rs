//! `blankres`: review and send crash reports from a terminal.
//!
//! The same consent rules as the desktop front end, because both drive
//! [`blankres_session::ReportSession`]. Nothing here can upload a payload the server did not ask
//! for, and nothing uploads without an explicit subcommand.

use std::path::PathBuf;

use blankres_client::Client;
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
use blankres_i18n::Catalog;
use blankres_session::{current_uid, human_size, Declined, PendingStore, ReportSession};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "blankres", version, about = "Review and send crash reports")]
struct Cli {
    /// Path to the client configuration.
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List crashes waiting for a decision.
    List,
    /// Show everything that would be transmitted for one crash.
    Show {
        /// Report file, or the program name if it is unambiguous.
        report: String,
    },
    /// Send a crash report to the server.
    Send {
        /// Report file, or the program name if it is unambiguous.
        report: String,
    },
    /// Delete a crash report without sending it.
    Discard {
        /// Report file, or the program name if it is unambiguous.
        report: String,
    },
    /// Delete it and never ask about this problem again.
    Ignore {
        /// Report file, or the program name if it is unambiguous.
        report: String,
    },
    /// Show the signatures this user has chosen to ignore.
    Ignored,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = ClientConfig::load(&cli.config)?;
    let store = PendingStore::new(&config.crash_dir, current_uid());
    let t = Catalog::detect();

    match cli.command {
        Command::List => list(&store, &t),
        Command::Show { report } => show(&store, &report, &t)?,
        Command::Send { report } => send(&store, &report, &config, &t).await?,
        Command::Discard { report } => {
            let entry = resolve(&store, &report, &t)?;
            ReportSession::with_catalog(&store, entry, t).discard();
            println!("{}", t.discarded());
        }
        Command::Ignore { report } => {
            let entry = resolve(&store, &report, &t)?;
            let session = ReportSession::with_catalog(&store, entry, t);
            session.decline_forever()?;
            println!("{}", t.discarded_and_ignored());
        }
        Command::Ignored => {
            let declined = Declined::load(&config.crash_dir, current_uid());
            if declined.signatures.is_empty() {
                println!("{}", t.no_ignored_problems());
            }
            for signature in &declined.signatures {
                println!("{signature}");
            }
        }
    }

    Ok(())
}

fn list(store: &PendingStore, t: &Catalog) {
    let entries = store.list();
    if entries.is_empty() {
        println!("{}", t.nothing_waiting());
        return;
    }

    println!(
        "{:<24} {:>10}  {}",
        t.column_program(),
        t.column_payload(),
        t.column_report()
    );
    for entry in entries {
        println!(
            "{:<24} {:>10}  {}",
            entry.program(),
            human_size(entry.transfer_size()),
            entry.path.display()
        );
    }
}

fn show(store: &PendingStore, report: &str, t: &Catalog) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve(store, report, t)?;
    let session = ReportSession::with_catalog(store, entry, *t);

    println!(
        "{}",
        t.headline_line(&session.entry().program(), &session.transfer_summary())
    );
    println!("\n{}\n", t.would_be_sent_heading());

    for (label, value) in session.disclosure() {
        if value.contains('\n') {
            println!("{label}:");
            for line in value.lines() {
                println!("    {line}");
            }
        } else {
            println!("{label}: {value}");
        }
    }

    if !session.is_actionable(blankres_session::now_secs()) {
        println!(
            "\nNote: the server is no longer waiting for this report; it can only be discarded."
        );
    }

    Ok(())
}

async fn send(
    store: &PendingStore,
    report: &str,
    config: &ClientConfig,
    t: &Catalog,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve(store, report, t)?;
    let session = ReportSession::with_catalog(store, entry, *t);

    let size = session.entry().transfer_size();
    println!(
        "{}",
        t.uploading_for(&human_size(size), &session.entry().program())
    );

    let client = Client::new(config.endpoint.clone())?;
    let receipt = session.send(&client).await?;
    println!("{}", t.sent_with_id(&receipt.id));
    if let Some(url) = receipt.url {
        println!("{url}");
    }

    Ok(())
}

/// Accept either a path or a program name, so `blankres send firefox` works.
fn resolve(
    store: &PendingStore,
    report: &str,
    t: &Catalog,
) -> Result<blankres_session::PendingEntry, Box<dyn std::error::Error>> {
    let path = PathBuf::from(report);
    if path.is_file() {
        return Ok(store.load(&path)?);
    }

    let matches: Vec<_> = store
        .list()
        .into_iter()
        .filter(|entry| entry.program() == report)
        .collect();

    match matches.len() {
        1 => Ok(matches.into_iter().next().expect("checked")),
        0 => Err(t.no_pending_report(report).into()),
        // Refusing beats guessing: sending the wrong crash is not recoverable.
        n => Err(t.ambiguous_report(n, report).into()),
    }
}
