//! `blankres-gtk`: the desktop consent window.
//!
//! Runs in the user's session, unprivileged. It appears only for crashes the server has actually
//! asked for a payload for, which on a well-populated crash database is a small fraction of them.

mod app;
mod ui;

use adw::prelude::*;
use gtk4::glib;
use libadwaita as adw;

const APP_ID: &str = "org.blankres.CrashReporter";

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blankres_gtk=info".into()),
        )
        .init();

    let application = adw::Application::builder().application_id(APP_ID).build();

    application.connect_activate(|application| {
        let context = app::AppContext::load();
        tracing::info!(
            crash_dir = %context.store.dir().display(),
            telemetry = context.telemetry_enabled,
            "opening crash reporter"
        );

        let window = ui::build_window(application, context);
        window.present();
    });

    application.run()
}
