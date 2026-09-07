//! User-facing strings.
//!
//! Every string a person reads lives here, in one place, so the desktop window and the terminal
//! client cannot disagree about what they promise the user. Translations are typed methods rather
//! than a key/template lookup: a mistyped placeholder in a `.po` file fails at runtime, in front
//! of the user, whereas a wrong argument here fails at compile time.
//!
//! Em dashes are deliberately absent. They render inconsistently across the fonts and terminals
//! this text has to survive, and a hyphen or a full stop reads the same. A test enforces it.

/// Languages this build speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    English,
    Indonesian,
}

impl Lang {
    /// Pick a language from the environment, following the usual precedence.
    ///
    /// Falls back to English for anything unrecognized: showing a user English is a small
    /// annoyance, and guessing wrong at a language they cannot read is a larger one.
    pub fn detect() -> Self {
        for var in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() && value != "C" && value != "POSIX" {
                    return Self::from_locale(&value);
                }
            }
        }
        Self::English
    }

    /// Map a locale string such as `id_ID.UTF-8` to a language.
    pub fn from_locale(locale: &str) -> Self {
        let code = locale
            .split(['.', '_', '@'])
            .next()
            .unwrap_or(locale)
            .to_ascii_lowercase();
        match code.as_str() {
            "id" | "in" => Self::Indonesian,
            _ => Self::English,
        }
    }
}

/// Chooses between the two strings of a translated message.
macro_rules! pick {
    ($self:ident, $en:expr, $id:expr) => {
        match $self.lang {
            Lang::English => $en,
            Lang::Indonesian => $id,
        }
    };
}

/// The translated strings, bound to one language.
#[derive(Debug, Clone, Copy, Default)]
pub struct Catalog {
    lang: Lang,
}

impl Catalog {
    pub fn new(lang: Lang) -> Self {
        Self { lang }
    }

    /// A catalog for the language the environment asks for.
    pub fn detect() -> Self {
        Self::new(Lang::detect())
    }

    pub fn lang(&self) -> Lang {
        self.lang
    }

    // -- window chrome ----------------------------------------------------------------------

    pub fn app_title(&self) -> &'static str {
        pick!(
            self,
            "BlanKres Crash Reporting",
            "Pelaporan Kerusakan BlanKres"
        )
    }

    pub fn nothing_to_report(&self) -> &'static str {
        pick!(self, "Nothing to report", "Tidak ada yang dilaporkan")
    }

    pub fn nothing_to_report_detail(&self) -> &'static str {
        pick!(
            self,
            "No crashes are waiting for your decision.",
            "Tidak ada kerusakan yang menunggu keputusan Anda."
        )
    }

    pub fn settings_tooltip(&self) -> &'static str {
        pick!(
            self,
            "Crash reporting settings",
            "Pengaturan pelaporan kerusakan"
        )
    }

    // -- the headline -----------------------------------------------------------------------

    pub fn closed_unexpectedly(&self, program: &str) -> String {
        pick!(
            self,
            format!("{program} closed unexpectedly"),
            format!("{program} berhenti secara tidak terduga")
        )
    }

    /// The sentence that states what pressing Send actually transfers.
    pub fn upload_warning(&self, size: &str) -> String {
        pick!(
            self,
            format!("Sending this uploads {size}, including a snapshot of the program's memory."),
            format!(
                "Mengirim laporan ini mengunggah {size}, termasuk cuplikan memori program tersebut."
            )
        )
    }

    pub fn expired(&self) -> &'static str {
        pick!(
            self,
            "The server is no longer waiting for this report. You can only discard it.",
            "Server tidak lagi menunggu laporan ini. Anda hanya dapat membuangnya."
        )
    }

    pub fn what_would_be_sent(&self) -> &'static str {
        pick!(self, "What would be sent", "Apa yang akan dikirim")
    }

    pub fn what_would_be_sent_detail(&self) -> &'static str {
        pick!(
            self,
            "Every field below is included in the upload.",
            "Setiap kolom di bawah ini disertakan dalam unggahan."
        )
    }

    // -- actions ----------------------------------------------------------------------------

    pub fn send_report(&self) -> &'static str {
        pick!(self, "Send report", "Kirim laporan")
    }

    pub fn dont_send(&self) -> &'static str {
        pick!(self, "Don't send", "Jangan kirim")
    }

    pub fn never_for_this_problem(&self) -> &'static str {
        pick!(self, "Never for this problem", "Jangan untuk masalah ini")
    }

    pub fn uploading(&self) -> &'static str {
        pick!(self, "Uploading...", "Mengunggah...")
    }

    // -- outcomes ---------------------------------------------------------------------------

    pub fn report_discarded(&self) -> &'static str {
        pick!(self, "Report discarded.", "Laporan dibuang.")
    }

    pub fn problem_ignored(&self) -> &'static str {
        pick!(
            self,
            "This problem will not be raised again.",
            "Masalah ini tidak akan ditanyakan lagi."
        )
    }

    pub fn could_not_record_decision(&self) -> &'static str {
        pick!(
            self,
            "Could not record the decision.",
            "Tidak dapat menyimpan keputusan."
        )
    }

    pub fn report_sent(&self, id: &str) -> String {
        pick!(
            self,
            format!("Report sent. Id {id}"),
            format!("Laporan terkirim. Id {id}")
        )
    }

    pub fn could_not_send(&self, error: &str) -> String {
        pick!(
            self,
            format!("Could not send: {error}"),
            format!("Tidak dapat mengirim: {error}")
        )
    }

    pub fn upload_ended_unexpectedly(&self) -> &'static str {
        pick!(
            self,
            "Upload ended unexpectedly.",
            "Unggahan berakhir secara tidak terduga."
        )
    }

    // -- settings ---------------------------------------------------------------------------

    pub fn automatic_statistics(&self) -> &'static str {
        pick!(
            self,
            "Automatic crash statistics",
            "Statistik kerusakan otomatis"
        )
    }

    pub fn automatic_statistics_detail(&self) -> &'static str {
        pick!(
            self,
            "When a program crashes, a short report is sent automatically: the program, the \
             package version and a fingerprint of where it crashed. It contains no memory \
             contents, no command line and no environment.",
            "Ketika sebuah program rusak, laporan singkat dikirim secara otomatis: nama program, \
             versi paket, dan sidik jari lokasi kerusakannya. Laporan ini tidak memuat isi \
             memori, baris perintah, maupun variabel lingkungan."
        )
    }

    pub fn send_statistics(&self) -> &'static str {
        pick!(self, "Send crash statistics", "Kirim statistik kerusakan")
    }

    pub fn set_by_administrator(&self, path: &str) -> String {
        pick!(
            self,
            format!("Set by an administrator in {path}"),
            format!("Diatur oleh administrator di {path}")
        )
    }

    pub fn memory_snapshots(&self) -> &'static str {
        pick!(self, "Memory snapshots", "Cuplikan memori")
    }

    pub fn memory_snapshots_detail(&self) -> &'static str {
        pick!(
            self,
            "A full memory snapshot is only ever uploaded when the crash server asks for one and \
             you agree to it in this window. It is never sent automatically.",
            "Cuplikan memori lengkap hanya diunggah bila server kerusakan memintanya dan Anda \
             menyetujuinya di jendela ini. Cuplikan tidak pernah dikirim secara otomatis."
        )
    }

    // -- disclosure rows --------------------------------------------------------------------

    pub fn label_program(&self) -> &'static str {
        pick!(self, "Program", "Program")
    }

    pub fn label_signal(&self) -> &'static str {
        pick!(self, "Signal", "Sinyal")
    }

    pub fn label_package(&self) -> &'static str {
        pick!(self, "Package", "Paket")
    }

    pub fn label_operating_system(&self) -> &'static str {
        pick!(self, "Operating system", "Sistem operasi")
    }

    pub fn label_kernel(&self) -> &'static str {
        pick!(self, "Kernel", "Kernel")
    }

    pub fn label_signature(&self) -> &'static str {
        pick!(self, "Crash signature", "Sidik jari kerusakan")
    }

    pub fn label_command_line(&self) -> &'static str {
        pick!(self, "Command line", "Baris perintah")
    }

    pub fn label_stack_trace(&self) -> &'static str {
        pick!(self, "Stack trace", "Jejak tumpukan")
    }

    pub fn label_environment(&self) -> &'static str {
        pick!(self, "Environment", "Lingkungan")
    }

    pub fn label_environment_named(&self, name: &str) -> String {
        pick!(
            self,
            format!("Environment: {name}"),
            format!("Lingkungan: {name}")
        )
    }

    pub fn label_modified_file(&self) -> &'static str {
        pick!(self, "Modified file", "Berkas yang diubah")
    }

    pub fn label_attachment(&self, name: &str) -> String {
        pick!(
            self,
            format!("Attachment: {name}"),
            format!("Lampiran: {name}")
        )
    }

    pub fn label_not_collected(&self, name: &str) -> String {
        pick!(
            self,
            format!("Not collected: {name}"),
            format!("Tidak dikumpulkan: {name}")
        )
    }

    pub fn unknown(&self) -> &'static str {
        pick!(self, "unknown", "tidak diketahui")
    }

    pub fn not_from_a_package(&self) -> &'static str {
        pick!(self, "not from a package", "bukan dari sebuah paket")
    }

    /// How the core dump is described. Deliberately concrete: "core dump" means nothing to most
    /// people, and the whole point of this row is informed consent.
    pub fn memory_snapshot_of_size(&self, size: &str) -> String {
        pick!(
            self,
            format!("{size}, a snapshot of the program's memory"),
            format!("{size}, cuplikan memori program tersebut")
        )
    }

    pub fn bytes_of_text(&self, bytes: usize) -> String {
        pick!(
            self,
            format!("{bytes} bytes of text"),
            format!("{bytes} bita teks")
        )
    }

    pub fn variables_withheld(&self, count: usize) -> String {
        pick!(
            self,
            format!("{count} more variables withheld to avoid sending credentials"),
            format!("{count} variabel lain ditahan agar kredensial tidak ikut terkirim")
        )
    }

    pub fn from_package(&self, path: &str, package: &str) -> String {
        pick!(
            self,
            format!("{path} (from {package})"),
            format!("{path} (dari {package})")
        )
    }

    pub fn includes_size(&self, size: &str) -> String {
        pick!(
            self,
            format!("Includes {size}"),
            format!("Menyertakan {size}")
        )
    }

    pub fn no_attachments(&self) -> &'static str {
        pick!(self, "No attachments", "Tidak ada lampiran")
    }

    // -- terminal client --------------------------------------------------------------------

    pub fn nothing_waiting(&self) -> &'static str {
        pick!(
            self,
            "No crash reports are waiting for a decision.",
            "Tidak ada laporan kerusakan yang menunggu keputusan."
        )
    }

    pub fn column_program(&self) -> &'static str {
        pick!(self, "PROGRAM", "PROGRAM")
    }

    pub fn column_payload(&self) -> &'static str {
        pick!(self, "PAYLOAD", "MUATAN")
    }

    pub fn column_report(&self) -> &'static str {
        pick!(self, "REPORT", "LAPORAN")
    }

    pub fn headline_line(&self, program: &str, summary: &str) -> String {
        pick!(
            self,
            format!("{program} closed unexpectedly. {summary}."),
            format!("{program} berhenti secara tidak terduga. {summary}.")
        )
    }

    pub fn would_be_sent_heading(&self) -> &'static str {
        pick!(
            self,
            "Everything below would be sent to the crash server:",
            "Semua yang tercantum di bawah ini akan dikirim ke server kerusakan:"
        )
    }

    pub fn expired_note(&self) -> &'static str {
        pick!(
            self,
            "Note: the server is no longer waiting for this report; it can only be discarded.",
            "Catatan: server tidak lagi menunggu laporan ini; laporan hanya dapat dibuang."
        )
    }

    pub fn uploading_for(&self, size: &str, program: &str) -> String {
        pick!(
            self,
            format!("Uploading {size} for {program}..."),
            format!("Mengunggah {size} untuk {program}...")
        )
    }

    pub fn sent_with_id(&self, id: &str) -> String {
        pick!(
            self,
            format!("Sent. Report id {id}"),
            format!("Terkirim. Id laporan {id}")
        )
    }

    pub fn discarded(&self) -> &'static str {
        pick!(self, "Discarded.", "Dibuang.")
    }

    pub fn discarded_and_ignored(&self) -> &'static str {
        pick!(
            self,
            "Discarded, and this problem will not be raised again.",
            "Dibuang, dan masalah ini tidak akan ditanyakan lagi."
        )
    }

    pub fn no_ignored_problems(&self) -> &'static str {
        pick!(
            self,
            "No ignored problems.",
            "Tidak ada masalah yang diabaikan."
        )
    }

    pub fn no_pending_report(&self, name: &str) -> String {
        pick!(
            self,
            format!("no pending report for {name:?}; try `blankres list`"),
            format!("tidak ada laporan tertunda untuk {name:?}; coba `blankres list`")
        )
    }

    pub fn ambiguous_report(&self, count: usize, name: &str) -> String {
        pick!(
            self,
            format!("{count} pending reports for {name:?}; name the file instead"),
            format!("ada {count} laporan tertunda untuk {name:?}; sebutkan nama berkasnya")
        )
    }
}

/// Every string the catalog can produce, for tests that must check all of them.
pub fn all_strings(catalog: &Catalog) -> Vec<String> {
    let c = catalog;
    vec![
        c.app_title().to_owned(),
        c.nothing_to_report().to_owned(),
        c.nothing_to_report_detail().to_owned(),
        c.settings_tooltip().to_owned(),
        c.closed_unexpectedly("firefox"),
        c.upload_warning("412.0 MB"),
        c.expired().to_owned(),
        c.what_would_be_sent().to_owned(),
        c.what_would_be_sent_detail().to_owned(),
        c.send_report().to_owned(),
        c.dont_send().to_owned(),
        c.never_for_this_problem().to_owned(),
        c.uploading().to_owned(),
        c.report_discarded().to_owned(),
        c.problem_ignored().to_owned(),
        c.could_not_record_decision().to_owned(),
        c.report_sent("abc"),
        c.could_not_send("timeout"),
        c.upload_ended_unexpectedly().to_owned(),
        c.automatic_statistics().to_owned(),
        c.automatic_statistics_detail().to_owned(),
        c.send_statistics().to_owned(),
        c.set_by_administrator("/etc/blankres/client.json"),
        c.memory_snapshots().to_owned(),
        c.memory_snapshots_detail().to_owned(),
        c.label_program().to_owned(),
        c.label_signal().to_owned(),
        c.label_package().to_owned(),
        c.label_operating_system().to_owned(),
        c.label_kernel().to_owned(),
        c.label_signature().to_owned(),
        c.label_command_line().to_owned(),
        c.label_stack_trace().to_owned(),
        c.label_environment().to_owned(),
        c.label_environment_named("LANG"),
        c.label_modified_file().to_owned(),
        c.label_attachment("core-dump"),
        c.label_not_collected("apt-term-log"),
        c.unknown().to_owned(),
        c.not_from_a_package().to_owned(),
        c.memory_snapshot_of_size("412.0 MB"),
        c.bytes_of_text(114),
        c.variables_withheld(37),
        c.from_package("/usr/bin/foo", "foo"),
        c.includes_size("412.0 MB"),
        c.no_attachments().to_owned(),
        c.nothing_waiting().to_owned(),
        c.column_program().to_owned(),
        c.column_payload().to_owned(),
        c.column_report().to_owned(),
        c.headline_line("firefox", "Includes 412.0 MB"),
        c.would_be_sent_heading().to_owned(),
        c.expired_note().to_owned(),
        c.uploading_for("412.0 MB", "firefox"),
        c.sent_with_id("abc"),
        c.discarded().to_owned(),
        c.discarded_and_ignored().to_owned(),
        c.no_ignored_problems().to_owned(),
        c.no_pending_report("firefox"),
        c.ambiguous_report(2, "firefox"),
    ]
}
