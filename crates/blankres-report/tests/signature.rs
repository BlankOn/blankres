//! Signature tests. The central property is that the same bug hashes the same way across boots
//! (absolute addresses differ, module offsets do not) while different bugs do not collide.

use blankres_report::signature::{parse_journal_stack_trace, Frame, Precision, Signature};

/// A real-shaped systemd-coredump journal message. Addresses here are from one boot.
const MESSAGE_BOOT_A: &str = "\
Process 4242 (foo) of user 1000 dumped core.

Stack trace of thread 4242:
#0  0x00007f8a1b2c3d4e __pthread_kill_implementation (libc.so.6 + 0x8ab2c)
#1  0x00007f8a1b2ab476 raise (libc.so.6 + 0x42476)
#2  0x00007f8a1b2917f3 abort (libc.so.6 + 0x287f3)
#3  0x000055f6a1b2c400 parse_config (/usr/bin/foo + 0x11400)
#4  0x000055f6a1b2d910 main (/usr/bin/foo + 0x12910)
";

/// The same crash after a reboot: every absolute address moved, offsets are unchanged.
const MESSAGE_BOOT_B: &str = "\
Process 9137 (foo) of user 1000 dumped core.

Stack trace of thread 9137:
#0  0x00007fd3c4e5f6a1 __pthread_kill_implementation (libc.so.6 + 0x8ab2c)
#1  0x00007fd3c4e37dc9 raise (libc.so.6 + 0x42476)
#2  0x00007fd3c4e1e146 abort (libc.so.6 + 0x287f3)
#3  0x00005610ffab2c00 parse_config (/usr/bin/foo + 0x11400)
#4  0x00005610ffab3110 main (/usr/bin/foo + 0x12910)
";

fn sig(message: &str) -> Signature {
    let frames = parse_journal_stack_trace(message);
    Signature::from_frames(&frames, Some(6), "/usr/bin/foo")
}

#[test]
fn identical_across_boots_despite_aslr() {
    let a = sig(MESSAGE_BOOT_A);
    let b = sig(MESSAGE_BOOT_B);
    assert_eq!(
        a.hash, b.hash,
        "signature must not depend on absolute addresses"
    );
    assert_eq!(a.precision, Precision::Precise);
}

#[test]
fn distinct_bugs_in_one_binary_do_not_collide() {
    let other = MESSAGE_BOOT_A.replace("parse_config", "render_frame");
    assert_ne!(sig(MESSAGE_BOOT_A).hash, sig(&other).hash);
}

#[test]
fn abort_machinery_is_skipped_so_every_abort_is_not_one_bucket() {
    // The top three frames are raise/abort noise; the signature must start at parse_config.
    let signature = sig(MESSAGE_BOOT_A);
    assert_eq!(
        signature.frames.first().map(String::as_str),
        Some("parse_config")
    );
}

#[test]
fn multiarch_path_changes_do_not_alter_the_signature() {
    let moved = MESSAGE_BOOT_A.replace("(libc.so.6 +", "(/usr/lib/x86_64-linux-gnu/libc.so.6 +");
    assert_eq!(sig(MESSAGE_BOOT_A).hash, sig(&moved).hash);
}

#[test]
fn only_the_crashing_thread_is_read() {
    let with_second_thread = format!(
        "{MESSAGE_BOOT_A}\nStack trace of thread 4243:\n#0  0x00007f00 poll (libc.so.6 + 0x1)\n"
    );
    assert_eq!(
        parse_journal_stack_trace(MESSAGE_BOOT_A).len(),
        parse_journal_stack_trace(&with_second_thread).len()
    );
}

#[test]
fn unsymbolized_frames_still_produce_a_precise_signature() {
    let message = "\
Stack trace of thread 1:
#0  0x00007f8a1b2c3d4e n/a (/usr/bin/foo + 0x11400)
#1  0x00007f8a1b2ab476 n/a (/usr/bin/foo + 0x12910)
";
    let frames = parse_journal_stack_trace(message);
    assert_eq!(frames.len(), 2);
    let signature = Signature::from_frames(&frames, Some(11), "/usr/bin/foo");
    assert_eq!(signature.precision, Precision::Precise);
    assert_eq!(signature.frames[0], "foo+0x11400");
}

#[test]
fn a_message_with_no_trace_yields_no_frames() {
    let message = "Process 4242 (foo) of user 1000 dumped core.";
    assert!(parse_journal_stack_trace(message).is_empty());
}

#[test]
fn coarse_signature_separates_package_versions() {
    // Without frames, a bug and its fix must not share a bucket.
    let before = Signature::coarse("/usr/bin/foo", Some(11), Some("1.0-1"));
    let after = Signature::coarse("/usr/bin/foo", Some(11), Some("1.0-2"));
    assert_ne!(before.hash, after.hash);
    assert_eq!(before.precision, Precision::Coarse);
}

#[test]
fn empty_frames_fall_back_to_coarse() {
    let signature = Signature::from_frames(&[], Some(11), "/usr/bin/foo");
    assert_eq!(signature.precision, Precision::Coarse);
}

#[test]
fn frame_offsets_are_parsed_as_hex() {
    let frames = parse_journal_stack_trace(MESSAGE_BOOT_A);
    assert_eq!(
        frames[0],
        Frame {
            function: Some("__pthread_kill_implementation".to_owned()),
            module: Some("libc.so.6".to_owned()),
            module_offset: Some(0x8ab2c),
        }
    );
}
