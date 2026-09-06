//! Host identity: distro, architecture, kernel, and the pseudonymous machine id.
//!
//! Read once at daemon start and reused for every event — none of it changes between crashes, and
//! re-reading it per crash would be pure waste on the hot path.

use std::path::Path;

use blankres_report::event::SystemInfo;
use sha2::{Digest as _, Sha256};

use crate::sys::Filesystem;

pub const OS_RELEASE: &str = "/etc/os-release";
pub const MACHINE_ID: &str = "/etc/machine-id";

/// Read `SystemInfo` from the host.
///
/// `kernel_version` is passed in rather than read, because obtaining it portably means `uname(2)`
/// and this crate stays free of libc for testability; the daemon supplies it.
pub fn system_info<F: Filesystem>(fs: &F, kernel_version: String) -> SystemInfo {
    let (distro, distro_version) = os_release(fs, Path::new(OS_RELEASE));
    SystemInfo {
        distro,
        distro_version,
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_version,
    }
}

/// Parse `NAME` and `VERSION_ID` out of an os-release file.
pub fn os_release<F: Filesystem>(fs: &F, path: &Path) -> (String, String) {
    let Ok(content) = fs.read_to_string(path) else {
        return ("unknown".to_owned(), "unknown".to_owned());
    };

    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "NAME" => name = Some(value),
            "VERSION_ID" => version = Some(value),
            _ => {}
        }
    }

    (
        name.unwrap_or_else(|| "unknown".to_owned()),
        version.unwrap_or_else(|| "unknown".to_owned()),
    )
}

/// Pseudonymous machine identifier.
///
/// `/etc/machine-id` is a stable host identifier that is world-readable and shared with other
/// subsystems (D-Bus derives from it), so it must never be transmitted raw: anyone holding the
/// crash database could confirm whether a particular machine appears in it simply by reading that
/// file on the machine. Hashing it under a per-installation salt that never leaves the host
/// removes that confirmation oracle. See `docs/machine-identifier.md` for the full rationale.
pub fn pseudonymous_machine_id(machine_id: &str, salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"blankres-machine-v1\0");
    hasher.update(salt);
    hasher.update([0]);
    hasher.update(machine_id.trim().as_bytes());
    hex::encode(hasher.finalize())
}

/// Read and hash the host's machine id.
pub fn read_machine_id<F: Filesystem>(fs: &F, salt: &[u8]) -> String {
    let raw = fs
        .read_to_string(Path::new(MACHINE_ID))
        .unwrap_or_else(|_| "unknown".to_owned());
    pseudonymous_machine_id(&raw, salt)
}
