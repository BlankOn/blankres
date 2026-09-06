//! `blankresd`: watches the journal, reports crashes as cheap telemetry, and collects a full
//! payload only when the server asks for one.

pub mod config;
pub mod journal;
pub mod oops;
pub mod reporter;
pub mod spool;
pub mod state;

pub use config::ClientConfig;
pub use journal::{JournalEntry, JournalSource, JournalctlSource};
pub use reporter::{Outcome, Reporter};
pub use spool::Spool;
pub use state::State;
