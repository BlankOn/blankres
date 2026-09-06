//! Redaction must be the thing that cannot be forgotten: everything not known-safe is dropped.

use std::collections::BTreeMap;

use blankres_report::redact::{
    filter_environ_block, filter_environment, scrub_cmdline_block, scrub_command_line, REDACTED,
};

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn strips_a_planted_secret_from_the_environment() {
    let (kept, dropped) = filter_environment(&env(&[
        ("PATH", "/usr/bin"),
        ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI"),
        ("LANG", "en_US.UTF-8"),
    ]));
    assert!(!kept.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert_eq!(kept["PATH"], "/usr/bin");
    assert_eq!(kept["LANG"], "en_US.UTF-8");
    assert_eq!(dropped, 1);
}

#[test]
fn unknown_variables_are_dropped_even_when_they_look_harmless() {
    // The allowlist is the whole point: a variable nobody thought about must not survive.
    let (kept, dropped) = filter_environment(&env(&[("SOME_INTERNAL_HOSTNAME", "db-prod-3")]));
    assert!(kept.is_empty());
    assert_eq!(dropped, 1);
}

#[test]
fn locale_variables_are_kept_by_prefix() {
    let (kept, _) = filter_environment(&env(&[("LC_TIME", "de_DE.UTF-8")]));
    assert_eq!(kept["LC_TIME"], "de_DE.UTF-8");
}

#[test]
fn an_allowlisted_name_that_reads_as_a_secret_is_still_dropped() {
    let (kept, dropped) = filter_environment(&env(&[("LD_PRELOAD_TOKEN", "abc")]));
    assert!(kept.is_empty());
    assert_eq!(dropped, 1);
}

#[test]
fn parses_a_nul_separated_environ_block() {
    let (kept, dropped) = filter_environ_block("PATH=/usr/bin\0API_KEY=sekrit\0LANG=C\0");
    assert_eq!(kept.len(), 2);
    assert_eq!(dropped, 1);
}

#[test]
fn scrubs_both_command_line_secret_shapes() {
    let argv: Vec<String> = [
        "/usr/bin/foo",
        "--token=abc123",
        "--password",
        "hunter2",
        "input.txt",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let scrubbed = scrub_command_line(&argv);
    assert_eq!(scrubbed[1], format!("--token={REDACTED}"));
    assert_eq!(scrubbed[2], "--password");
    assert_eq!(scrubbed[3], REDACTED);
    // A positional argument is left alone; over-redacting makes reports useless.
    assert_eq!(scrubbed[4], "input.txt");
}

#[test]
fn splits_a_nul_separated_cmdline_block() {
    let scrubbed = scrub_cmdline_block("/usr/bin/foo\0--verbose\0");
    assert_eq!(scrubbed, vec!["/usr/bin/foo", "--verbose"]);
}
