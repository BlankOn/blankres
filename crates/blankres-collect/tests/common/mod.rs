#![allow(dead_code)]

//! Shared fixtures: a small but realistic dpkg tree and a coredump record.

use blankres_collect::pkg::{DpkgBackend, DpkgIndex};
use blankres_collect::record::{CoredumpRecord, RecordBuilder};
use blankres_collect::sys::MemFs;
use std::path::Path;

pub const INFO_DIR: &str = "/var/lib/dpkg/info";
pub const STATUS: &str = "/var/lib/dpkg/status";
pub const CORE_PATH: &str = "/var/lib/systemd/coredump/core.foo.1000.zst";

pub const STACK_TRACE: &str = "\
Process 4242 (foo) of user 1000 dumped core.

Stack trace of thread 4242:
#0  0x00007f8a1b2c3d4e parse_config (/usr/bin/foo + 0x11400)
#1  0x00007f8a1b2ab476 main (/usr/bin/foo + 0x12910)
";

pub const PROC_MAPS: &str = "\
55f6a1b2b000-55f6a1b2c000 r-xp 00000000 08:02 262401 /usr/bin/foo
7f8a1b200000-7f8a1b228000 r-xp 00000000 08:02 131521 /usr/lib/x86_64-linux-gnu/libc.so.6
7f8a1b400000-7f8a1b401000 rw-p 00000000 00:00 0
7f8a1b500000-7f8a1b501000 r--p 00000000 00:05 1234 /memfd:mozilla-ipc (deleted)
";

/// A dpkg tree where `foo` owns `/usr/bin/foo` and `libc6` owns the mapped libc.
pub fn dpkg_fs() -> MemFs {
    let mut fs = MemFs::new();
    fs.insert(
        format!("{INFO_DIR}/foo.list"),
        "/usr\n/usr/bin\n/usr/bin/foo\n",
    );
    fs.insert(
        format!("{INFO_DIR}/libc6:amd64.list"),
        "/usr/lib/x86_64-linux-gnu/libc.so.6\n",
    );
    // The real MD5 of the file contents below, so an unmodified file verifies clean.
    fs.insert(
        format!("{INFO_DIR}/foo.md5sums"),
        "3149472b8bd514897696ef0d31325c61  usr/bin/foo\n",
    );
    fs.insert("/usr/bin/foo", "correct contents\n");
    fs.insert("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc\n");
    fs.insert(
        STATUS,
        "Package: foo\nVersion: 1.0-1\nSource: foo-src (1.0)\nStatus: install ok installed\n\n\
         Package: libc6\nVersion: 2.39-0ubuntu8\nStatus: install ok installed\n\n",
    );
    fs.insert("/etc/os-release", "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n");
    fs.insert("/etc/machine-id", "0123456789abcdef0123456789abcdef\n");
    // A core dump on disk. Its *contents* must never be read by the collectors.
    fs.insert(CORE_PATH, vec![0u8; 4096]);
    fs
}

pub fn backend(fs: MemFs) -> DpkgBackend<MemFs> {
    let index = DpkgIndex::build(&fs, Path::new(INFO_DIR), Path::new(STATUS));
    DpkgBackend::new(fs, index, INFO_DIR, Path::new(STATUS))
}

pub fn record() -> CoredumpRecord {
    RecordBuilder::new()
        .field("EXE", "/usr/bin/foo")
        .field("PID", "4242")
        .field("UID", "1000")
        .field("SIGNAL", "11 (SIGSEGV)")
        .field("CMDLINE", "/usr/bin/foo\0--token=abc123\0--verbose\0")
        .field(
            "ENVIRON",
            "PATH=/usr/bin\0AWS_SECRET_ACCESS_KEY=sekrit\0LANG=C\0",
        )
        .field("PROC_MAPS", PROC_MAPS)
        .field("PROC_STATUS", "Name:\tfoo\nState:\tR (running)\n")
        .field("FILENAME", CORE_PATH)
        .message(STACK_TRACE)
        .timestamp(1_788_000_000)
        .cursor("s=abc;i=1")
        .build()
}
