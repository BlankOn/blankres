//! Translation checks. The two that matter are that no language is missing a string and that no
//! string carries punctuation we have decided against: both are the kind of thing that otherwise
//! only surfaces in front of a user.

use blankres_i18n::{all_strings, Catalog, Lang};

fn languages() -> [Catalog; 2] {
    [Catalog::new(Lang::English), Catalog::new(Lang::Indonesian)]
}

#[test]
fn no_string_contains_an_em_or_en_dash() {
    for catalog in languages() {
        for text in all_strings(&catalog) {
            assert!(
                !text.contains('\u{2014}') && !text.contains('\u{2013}'),
                "{:?} string contains a dash we do not use: {text:?}",
                catalog.lang()
            );
        }
    }
}

#[test]
fn no_string_is_empty() {
    for catalog in languages() {
        for text in all_strings(&catalog) {
            assert!(
                !text.trim().is_empty(),
                "{:?} has an empty string",
                catalog.lang()
            );
        }
    }
}

#[test]
fn indonesian_is_actually_translated() {
    // A catalog that silently falls through to English would pass every other test here.
    let english = all_strings(&Catalog::new(Lang::English));
    let indonesian = all_strings(&Catalog::new(Lang::Indonesian));
    assert_eq!(english.len(), indonesian.len());

    let differing = english
        .iter()
        .zip(&indonesian)
        .filter(|(en, id)| en != id)
        .count();
    // A handful legitimately match: "Program", "Kernel", the column headings.
    assert!(
        differing > english.len() * 3 / 4,
        "only {differing} of {} strings differ; the translation looks incomplete",
        english.len()
    );
}

#[test]
fn placeholders_survive_translation() {
    // The values interpolated into a message are the part a user acts on, so losing one in
    // translation is worse than not translating the sentence at all.
    for catalog in languages() {
        assert!(catalog.closed_unexpectedly("firefox").contains("firefox"));
        assert!(catalog.upload_warning("412.0 MB").contains("412.0 MB"));
        assert!(catalog.report_sent("abc-123").contains("abc-123"));
        assert!(catalog.could_not_send("timed out").contains("timed out"));
        assert!(catalog.variables_withheld(37).contains("37"));
        assert!(catalog.memory_snapshot_of_size("1.5 GB").contains("1.5 GB"));
        assert!(catalog
            .set_by_administrator("/etc/blankres/client.json")
            .contains("/etc/blankres/client.json"));
        assert!(catalog
            .from_package("/usr/bin/foo", "foo")
            .contains("/usr/bin/foo"));
        assert!(catalog.uploading_for("2 MB", "firefox").contains("firefox"));
    }
}

#[test]
fn the_product_name_is_kept_in_both_languages() {
    for catalog in languages() {
        assert!(
            catalog.app_title().contains("BlanKres"),
            "the product name should not be translated away: {:?}",
            catalog.app_title()
        );
    }
}

#[test]
fn locales_map_to_languages() {
    assert_eq!(Lang::from_locale("id_ID.UTF-8"), Lang::Indonesian);
    assert_eq!(Lang::from_locale("id"), Lang::Indonesian);
    // `in` is the obsolete ISO code for Indonesian and still appears in the wild.
    assert_eq!(Lang::from_locale("in_ID"), Lang::Indonesian);
    assert_eq!(Lang::from_locale("en_US.UTF-8"), Lang::English);
    assert_eq!(Lang::from_locale("de_DE.UTF-8"), Lang::English);
    // Not a language we speak, so English rather than a guess.
    assert_eq!(Lang::from_locale("jv_ID"), Lang::English);
}

#[test]
fn the_indonesian_memory_warning_still_says_what_is_being_sent() {
    // This is the sentence the whole consent decision rests on. If it ever stops mentioning
    // memory, the dialog is no longer asking an honest question.
    let id = Catalog::new(Lang::Indonesian);
    assert!(id.upload_warning("412.0 MB").contains("memori"));
    assert!(id.memory_snapshot_of_size("412.0 MB").contains("memori"));
    assert!(id.memory_snapshots_detail().contains("memori"));
}
