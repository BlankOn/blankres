//! `blankres-gtk`: the desktop consent window.
//!
//! Runs in the user's session, unprivileged. It appears only for crashes the server has actually
//! asked for a payload for, which on a well-populated crash database is a small fraction of them.

mod app;
mod ui;

use adw::prelude::*;
use gtk4::gio;
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

    // NON_UNIQUE matters here. By default a second launch hands its activation to the process
    // that is already running and exits within milliseconds, so the new process's configuration
    // is discarded and the existing window keeps showing whatever crash directory it was started
    // with. That is silent and looks exactly like having no crashes to report. Single-instance
    // behaviour is not needed: the systemd user unit will not start a second copy while one is
    // active, and a window launched by hand should show the reports its own configuration names.
    let application = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();

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
