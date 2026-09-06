//! `blankres`: review and send crash reports from a terminal.
//!
//! The same consent rules as the desktop front end, because both drive
//! [`blankres_session::ReportSession`]. Nothing here can upload a payload the server did not ask
//! for, and nothing uploads without an explicit subcommand.

use std::path::PathBuf;

use blankres_client::Client;
use blankres_daemon::config::{ClientConfig, DEFAULT_CONFIG};
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

    match cli.command {
        Command::List => list(&store),
        Command::Show { report } => show(&store, &report)?,
        Command::Send { report } => send(&store, &report, &config).await?,
        Command::Discard { report } => {
            let entry = resolve(&store, &report)?;
            ReportSession::new(&store, entry).discard();
            println!("Discarded.");
        }
        Command::Ignore { report } => {
            let entry = resolve(&store, &report)?;
            let session = ReportSession::new(&store, entry);
            session.decline_forever()?;
            println!("Discarded, and this problem will not be raised again.");
        }
        Command::Ignored => {
            let declined = Declined::load(&config.crash_dir, current_uid());
            if declined.signatures.is_empty() {
                println!("No ignored problems.");
            }
            for signature in &declined.signatures {
                println!("{signature}");
            }
        }
    }

    Ok(())
}

fn list(store: &PendingStore) {
    let entries = store.list();
    if entries.is_empty() {
        println!("No crash reports are waiting for a decision.");
        return;
    }

    println!("{:<24} {:>10}  REPORT", "PROGRAM", "PAYLOAD");
    for entry in entries {
        println!(
            "{:<24} {:>10}  {}",
            entry.program(),
            human_size(entry.transfer_size()),
            entry.path.display()
        );
    }
}

fn show(store: &PendingStore, report: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve(store, report)?;
    let session = ReportSession::new(store, entry);

    println!(
        "{} closed unexpectedly. {}.",
        session.entry().program(),
        session.transfer_summary()
    );
    println!("\nEverything below would be sent to the crash server:\n");

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
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve(store, report)?;
    let session = ReportSession::new(store, entry);

    let size = session.entry().transfer_size();
    println!(
        "Uploading {} for {}...",
        human_size(size),
        session.entry().program()
    );

    let client = Client::new(config.endpoint.clone())?;
    let receipt = session.send(&client).await?;
    println!("Sent. Report id {}", receipt.id);
    if let Some(url) = receipt.url {
        println!("{url}");
    }

    Ok(())
}

/// Accept either a path or a program name, so `blankres send firefox` works.
fn resolve(
    store: &PendingStore,
    report: &str,
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
        0 => Err(format!("no pending report for {report:?}; try `blankres list`").into()),
        // Refusing beats guessing: sending the wrong crash is not recoverable.
        n => Err(format!("{n} pending reports for {report:?}; name the file instead").into()),
    }
}
