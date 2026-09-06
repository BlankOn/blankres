//! Crash data collection for blankres, split along the two-stage boundary.
//!
//! [`stage1`] builds the cheap telemetry event from the journal record alone. [`stage2`] assembles
//! the full payload, and runs only when the server has asked for one. The split is not an
//! optimization detail — it is the reason this reporter does not do to a machine what apport does.

pub mod budget;
pub mod pkg;
pub mod record;
pub mod stage1;
pub mod stage2;
pub mod sys;
pub mod system;

pub use budget::{Budget, Exhausted};
pub use pkg::{DpkgBackend, DpkgIndex, PackageBackend};
pub use record::{CoredumpRecord, RecordBuilder, COREDUMP_MESSAGE_ID};
pub use stage1::{Stage1Collector, Suppression};
pub use stage2::Stage2Collector;
pub use sys::{Filesystem, MemFs, NoSpawnRunner, ProcessRunner, RealFs, RealRunner};
pub use system::{pseudonymous_machine_id, read_machine_id, system_info};
