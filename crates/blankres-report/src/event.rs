//! Stage 1: the telemetry event and the server's payload directive.
//!
//! This is the schema every crash on every machine goes through, so it stays small and cheap to
//! build. It carries no core dump, no environment block and no command line — only what is needed
//! to count occurrences and decide whether the heavy payload is worth asking for.

use serde::{Deserialize, Serialize};

use crate::signature::Signature;

/// What kind of failure produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    /// A process died on a signal and `systemd-coredump` captured it.
    NativeCrash,
    /// A kernel oops, BUG or warning scraped from the journal.
    KernelOops,
    /// A dpkg maintainer script failed during install or upgrade.
    PackageFailure,
}

/// Identity of the package a crash came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The operating system the crash happened on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemInfo {
    pub distro: String,
    pub distro_version: String,
    pub architecture: String,
    pub kernel_version: String,
}

/// Stage 1 payload. Target size is well under 2 KB serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashEvent {
    /// Schema version, so the server can reject or migrate old clients explicitly.
    pub schema: u32,
    pub signature: Signature,
    pub kind: ReportKind,
    /// Unix seconds. Not monotonic and not to be trusted for ordering across machines.
    pub timestamp: u64,
    pub executable: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    #[serde(default)]
    pub package: PackageInfo,
    pub system: SystemInfo,
    /// Salted hash of `/etc/machine-id`. Stable for rate limiting and per-machine counts, but not
    /// reversible to the machine it came from.
    pub machine_id: String,
    /// How many times this signature has been seen on this machine, including this event.
    pub crash_count: u32,
    /// Client version, so a bad rollout can be identified server-side.
    pub client_version: String,
    /// Whether a core dump still exists locally. `false` means stage 2 is impossible for this
    /// event no matter what the server answers.
    pub core_available: bool,
    /// Compressed size of that core, so the server can decline one that is not worth the transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_size: Option<u64>,
}

/// Current value of [`CrashEvent::schema`].
pub const SCHEMA_VERSION: u32 = 1;

/// The server's answer to a stage-1 event: whether it wants the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadDirective {
    /// Server-assigned id for the event, used to correlate the stage-2 upload.
    pub id: String,
    /// When false the client deletes the core dump and stops. This is the common case.
    pub need_payload: bool,
    /// Capability for `POST /v1/reports`. Absent when `need_payload` is false, so a client cannot
    /// push an unsolicited payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_token: Option<String>,
    /// Hard cap the server will enforce on the upload; the client checks it before collecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Unix seconds after which `upload_token` is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl PayloadDirective {
    /// The "thanks, nothing further" answer.
    pub fn not_needed(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            need_payload: false,
            upload_token: None,
            max_bytes: None,
            expires_at: None,
        }
    }

    /// True when the directive can still be redeemed at `now` (unix seconds).
    pub fn is_actionable(&self, now: u64) -> bool {
        self.need_payload
            && self.upload_token.is_some()
            && self.expires_at.is_none_or(|expiry| now < expiry)
    }
}

/// A batch of events, as accepted by `POST /v1/events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<CrashEvent>,
}

/// One directive per submitted event, in the same order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectiveBatch {
    pub directives: Vec<PayloadDirective>,
}
