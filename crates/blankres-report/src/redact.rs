//! Redaction of process metadata before it leaves the machine.
//!
//! Applied once here rather than at each call site, so a new collector cannot forget it. The
//! environment is handled by *allowlist*: anything not explicitly known-safe is dropped, because
//! the set of variables that carry secrets is open-ended and grows with every CI system and cloud
//! SDK. Command lines cannot be allowlisted the same way — they are the point of the report — so
//! they get pattern-based scrubbing instead.

use std::collections::BTreeMap;

/// Environment variables worth keeping: they explain the crash without identifying the user.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "LANG",
    "LANGUAGE",
    "SHELL",
    "TERM",
    "DISPLAY",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "GDK_BACKEND",
    "QT_QPA_PLATFORM",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "MALLOC_CHECK_",
    "MALLOC_PERTURB_",
];

/// Prefixes kept wholesale (locale settings, all of which are `LC_*`).
const ENV_ALLOWED_PREFIXES: &[&str] = &["LC_"];

/// Substrings that mark a value as secret wherever it appears.
const SECRET_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "session",
    "cookie",
    "bearer",
];

/// What replaces a redacted value, so the report shows that something was removed rather than
/// implying the variable was unset.
pub const REDACTED: &str = "<redacted>";

fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_MARKERS.iter().any(|m| lower.contains(m))
}

/// Filter an environment to the allowlist.
///
/// Returns the surviving variables plus the count of dropped ones, so the report can say
/// "31 variables withheld" instead of quietly presenting a partial environment as complete.
pub fn filter_environment(env: &BTreeMap<String, String>) -> (BTreeMap<String, String>, usize) {
    let mut kept = BTreeMap::new();
    let mut dropped = 0;

    for (name, value) in env {
        let allowed = ENV_ALLOWLIST.contains(&name.as_str())
            || ENV_ALLOWED_PREFIXES.iter().any(|p| name.starts_with(p));

        // The allowlist wins on name, but a value that looks like a credential is still dropped:
        // `LD_PRELOAD` pointing at a path with a token in it is not worth the risk.
        if allowed && !is_secret_name(name) {
            kept.insert(name.clone(), value.clone());
        } else {
            dropped += 1;
        }
    }

    (kept, dropped)
}

/// Parse and redact a NUL-separated environment block as found in `COREDUMP_ENVIRON`.
pub fn filter_environ_block(block: &str) -> (BTreeMap<String, String>, usize) {
    let env = block
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| entry.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    filter_environment(&env)
}

/// Scrub secrets out of a command line while keeping it readable.
///
/// Handles the two shapes that actually leak: `--token=abc` and `--token abc`. A bare positional
/// value cannot be judged and is left alone — over-redacting the command line would make most
/// crash reports useless.
pub fn scrub_command_line(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;

    for arg in argv {
        if redact_next {
            out.push(REDACTED.to_owned());
            redact_next = false;
            continue;
        }

        match arg.split_once('=') {
            Some((name, _)) if is_secret_name(name) => {
                out.push(format!("{name}={REDACTED}"));
            }
            _ => {
                if arg.starts_with('-') && is_secret_name(arg) {
                    // `--token abc`: the value is the next argument.
                    redact_next = true;
                }
                out.push(arg.clone());
            }
        }
    }

    out
}

/// Split and scrub a NUL-separated command line as found in `COREDUMP_CMDLINE`.
pub fn scrub_cmdline_block(block: &str) -> Vec<String> {
    let argv: Vec<String> = block
        .split(['\0', ' '])
        .filter(|a| !a.is_empty())
        .map(str::to_owned)
        .collect();
    scrub_command_line(&argv)
}
