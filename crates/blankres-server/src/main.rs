//! `blankres-ingest`: the crash report ingest server.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blankres-ingest",
    version,
    about = "blankres crash ingest server"
)]
struct Cli {
    /// Path to a JSON config file. Environment variables override it.
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server. This is the default.
    Serve,
    /// Print the hash of a fleet token, for pasting into `token_hashes`.
    HashToken {
        /// The token to hash.
        token: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // The binary is `blankres-ingest`, so its own messages are tagged
                // `blankres_ingest`, not `blankres_server`. Leaving it out of the filter silences
                // every line this file logs, startup included, which looks exactly like a server
                // that is not running.
                .unwrap_or_else(|_| {
                    "blankres_ingest=info,blankres_server=info,tower_http=info".into()
                }),
        )
        .init();

    let cli = Cli::parse();

    if let Some(Command::HashToken { token }) = &cli.command {
        println!("{}", blankres_server::config::hash_token(token));
        return Ok(());
    }

    let config = blankres_server::Config::load(cli.config.as_deref())?;
    let bind = config.bind.clone();
    let quota = config.payloads_per_signature;

    // Migrations run as part of `build`, at startup, before the listener is opened: the server
    // never serves traffic against a schema it has not brought up to date.
    let app = blankres_server::build(config).await?;

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        address = %listener.local_addr()?,
        payloads_per_signature = quota,
        "blankres ingest listening"
    );

    axum::serve(listener, app).await?;
    Ok(())
}
