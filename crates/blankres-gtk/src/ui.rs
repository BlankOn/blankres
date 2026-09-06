//! The consent window.
//!
//! This window exists for one reason: a core dump is a copy of the crashed process's memory, and
//! it can contain documents, keystrokes, session cookies and private keys. Nobody can meaningfully
//! agree to send that on the strength of "an error report". So the window states the size in
//! plain language and shows, verbatim, every field that would be transmitted — and nothing leaves
//! the machine until the user presses Send.
//!
//! Stage 1 never reaches this window. By the time it opens, the server has already said it wants
//! a payload for this particular signature.

use adw::prelude::*;
use blankres_client::Client;
use blankres_session::{human_size, PendingEntry, ReportSession};
use gtk4 as gtk;
use gtk4::glib;
use libadwaita as adw;

use crate::app::AppContext;

/// Outcome of an upload, passed back to the GTK thread.
pub enum UploadResult {
    Sent { id: String },
    Failed { message: String },
}

/// Build the window for the given pending reports.
pub fn build_window(app: &adw::Application, context: AppContext) -> adw::ApplicationWindow {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("Crash Reporting")
        .default_width(720)
        .default_height(640)
        .build();

    let toasts = adw::ToastOverlay::new();
    let layout = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let header = adw::HeaderBar::new();
    let settings = gtk::Button::builder()
        .icon_name("emblem-system-symbolic")
        .tooltip_text("Crash reporting settings")
        .build();
    settings.connect_clicked({
        let window = window.clone();
        let context = context.clone();
        move |_| present_settings(&window, &context)
    });
    header.pack_end(&settings);
    layout.append(&header);

    let entries = context.store.list();
    if entries.is_empty() {
        layout.append(&empty_state());
    } else {
        layout.append(&report_view(&window, &toasts, &context, entries));
    }

    toasts.set_child(Some(&layout));
    window.set_content(Some(&toasts));
    window
}

fn empty_state() -> gtk::Widget {
    let status = adw::StatusPage::builder()
        .icon_name("emblem-ok-symbolic")
        .title("Nothing to report")
        .description("No crashes are waiting for your decision.")
        .vexpand(true)
        .build();
    status.upcast()
}

/// The main view: one page per pending crash, most recent first.
fn report_view(
    window: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
    context: &AppContext,
    entries: Vec<PendingEntry>,
) -> gtk::Widget {
    let stack = adw::ViewStack::new();

    for (index, entry) in entries.into_iter().enumerate() {
        let program = entry.program();
        let page = crash_page(window, toasts, context, entry);
        let name = format!("crash-{index}");
        stack.add_titled(&page, Some(&name), &program);
    }

    let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
    // Only show the switcher when there is more than one crash to choose between.
    if stack.pages().n_items() > 1 {
        let switcher = adw::ViewSwitcherBar::builder()
            .stack(&stack)
            .reveal(true)
            .build();
        container.append(&stack);
        container.append(&switcher);
    } else {
        container.append(&stack);
    }
    container.set_vexpand(true);
    container.upcast()
}

fn crash_page(
    window: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
    context: &AppContext,
    entry: PendingEntry,
) -> gtk::Widget {
    let session = ReportSession::new(&context.store, entry.clone());
    let program = entry.program();
    let size = entry.transfer_size();
    let expired = !session.is_actionable(blankres_session::now_secs());

    let page = adw::PreferencesPage::new();

    // Headline. The size is stated here rather than buried in the details, because it is the
    // number that decides whether someone consents.
    let banner = adw::PreferencesGroup::new();
    let headline = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk::Align::Center)
        .build();

    let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
    icon.set_pixel_size(48);
    headline.append(&icon);

    let title = gtk::Label::new(Some(&format!("{program} closed unexpectedly")));
    title.add_css_class("title-2");
    title.set_wrap(true);
    title.set_justify(gtk::Justification::Center);
    headline.append(&title);

    // The size belongs in the headline, not in the details: it is what someone actually weighs
    // when deciding whether to send a snapshot of their own memory.
    let subtitle = gtk::Label::new(Some(&if expired {
        "The server is no longer waiting for this report. You can only discard it.".to_owned()
    } else {
        format!(
            "Sending this uploads {}, including a snapshot of the program's memory.",
            human_size(size)
        )
    }));
    subtitle.add_css_class("dim-label");
    subtitle.set_wrap(true);
    subtitle.set_max_width_chars(56);
    subtitle.set_justify(gtk::Justification::Center);
    headline.append(&subtitle);

    banner.add(&headline);
    page.add(&banner);

    // Everything that would be transmitted, in full.
    let details = adw::PreferencesGroup::builder()
        .title("What would be sent")
        .description("Every field below is included in the upload.")
        .build();

    for (label, value) in session.disclosure() {
        details.add(&disclosure_row(&label, &value));
    }
    page.add(&details);

    // Actions live in a pinned footer, not in the scrolling page. The disclosure list is long by
    // design, and controls the user must reach should never depend on scrolling to the end of it.
    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .halign(gtk::Align::End)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let progress = gtk::ProgressBar::builder()
        .visible(false)
        .show_text(true)
        .text("Uploading…")
        .build();

    let ignore = gtk::Button::with_label("Never for this problem");
    let discard = gtk::Button::with_label("Don't send");
    let send = gtk::Button::with_label("Send report");
    send.add_css_class("suggested-action");
    send.set_sensitive(!expired);

    buttons.append(&ignore);
    buttons.append(&discard);
    buttons.append(&send);

    let footer = gtk::Box::new(gtk::Orientation::Vertical, 6);
    footer.append(&progress);
    footer.append(&buttons);
    footer.add_css_class("toolbar");

    wire_actions(
        window, toasts, context, &entry, &send, &discard, &ignore, &progress,
    );

    let view = adw::ToolbarView::new();
    view.set_content(Some(&page));
    view.add_bottom_bar(&footer);
    view.upcast()
}

/// One label/value row. Multi-line values get a selectable text view so a stack trace stays
/// readable and copyable rather than being squeezed into a subtitle.
fn disclosure_row(label: &str, value: &str) -> gtk::Widget {
    if value.contains('\n') {
        let expander = adw::ExpanderRow::builder().title(label).build();
        let text = gtk::TextView::builder()
            .editable(false)
            .monospace(true)
            .cursor_visible(false)
            .left_margin(12)
            .right_margin(12)
            .top_margin(6)
            .bottom_margin(6)
            .build();
        text.buffer().set_text(value);

        let scroller = gtk::ScrolledWindow::builder()
            .height_request(180)
            .hscrollbar_policy(gtk::PolicyType::Automatic)
            .child(&text)
            .build();

        let row = adw::ActionRow::new();
        row.set_child(Some(&scroller));
        expander.add_row(&row);
        expander.upcast()
    } else {
        let row = adw::ActionRow::builder()
            .title(label)
            .subtitle(value)
            .subtitle_selectable(true)
            .build();
        row.add_css_class("property");
        row.upcast()
    }
}

#[allow(clippy::too_many_arguments)]
fn wire_actions(
    window: &adw::ApplicationWindow,
    toasts: &adw::ToastOverlay,
    context: &AppContext,
    entry: &PendingEntry,
    send: &gtk::Button,
    discard: &gtk::Button,
    ignore: &gtk::Button,
    progress: &gtk::ProgressBar,
) {
    // "Don't send": discard this one, stay willing to be asked next time.
    discard.connect_clicked({
        let store = context.store.clone();
        let entry = entry.clone();
        let toasts = toasts.clone();
        move |button| {
            ReportSession::new(&store, entry.clone()).discard();
            button.set_sensitive(false);
            toasts.add_toast(adw::Toast::new("Report discarded."));
            disable_siblings(button);
        }
    });

    // "Never for this problem": record the signature so the daemon stops raising it. The daemon
    // runs as root and this window does not, which is why the decision is written into the user's
    // own crash directory rather than the daemon's state file.
    ignore.connect_clicked({
        let store = context.store.clone();
        let entry = entry.clone();
        let toasts = toasts.clone();
        move |button| {
            let session = ReportSession::new(&store, entry.clone());
            let message = match session.decline_forever() {
                Ok(()) => "This problem will not be raised again.",
                Err(_) => "Could not record the decision.",
            };
            toasts.add_toast(adw::Toast::new(message));
            disable_siblings(button);
        }
    });

    send.connect_clicked({
        let store = context.store.clone();
        let entry = entry.clone();
        let toasts = toasts.clone();
        let progress = progress.clone();
        let endpoint = context.endpoint.clone();
        let window = window.clone();
        move |button| {
            button.set_sensitive(false);
            progress.set_visible(true);
            progress.pulse();

            let (sender, receiver) = async_channel::bounded(1);

            // The upload runs on a worker thread: a multi-hundred-megabyte transfer on the GTK
            // main loop would freeze the window for its duration.
            std::thread::spawn({
                let store = store.clone();
                let entry = entry.clone();
                let endpoint = endpoint.clone();
                move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            let _ = sender.send_blocking(UploadResult::Failed {
                                message: err.to_string(),
                            });
                            return;
                        }
                    };

                    let result = runtime.block_on(async move {
                        let client = Client::new(endpoint)?;
                        ReportSession::new(&store, entry).send(&client).await
                    });

                    let _ = sender.send_blocking(match result {
                        Ok(receipt) => UploadResult::Sent { id: receipt.id },
                        Err(err) => UploadResult::Failed {
                            message: err.to_string(),
                        },
                    });
                }
            });

            // Keep the progress bar moving while the transfer runs.
            let pulse = glib::timeout_add_local(std::time::Duration::from_millis(120), {
                let progress = progress.clone();
                move || {
                    progress.pulse();
                    glib::ControlFlow::Continue
                }
            });

            glib::spawn_future_local({
                let progress = progress.clone();
                let toasts = toasts.clone();
                let button = button.clone();
                let window = window.clone();
                async move {
                    let result = receiver.recv().await;
                    pulse.remove();
                    progress.set_visible(false);

                    match result {
                        Ok(UploadResult::Sent { id }) => {
                            toasts.add_toast(adw::Toast::new(&format!("Report sent. Id {id}")));
                            disable_siblings(&button);
                            let _ = window;
                        }
                        Ok(UploadResult::Failed { message }) => {
                            toasts
                                .add_toast(adw::Toast::new(&format!("Could not send: {message}")));
                            button.set_sensitive(true);
                        }
                        Err(_) => {
                            toasts.add_toast(adw::Toast::new("Upload ended unexpectedly."));
                            button.set_sensitive(true);
                        }
                    }
                }
            });
        }
    });
}

/// Once a decision is made the other buttons are meaningless; leaving them live would invite a
/// second action on a report that no longer exists.
fn disable_siblings(button: &gtk::Button) {
    let Some(parent) = button.parent() else {
        return;
    };
    let mut child = parent.first_child();
    while let Some(widget) = child {
        widget.set_sensitive(false);
        child = widget.next_sibling();
    }
}

/// The settings window: what the machine sends automatically, and how to change it.
///
/// The stage-1 opt-in is a system-wide setting owned by the root daemon, so an unprivileged
/// session usually cannot toggle it. Rather than presenting a switch that silently fails, the
/// window reflects whether the config file is actually writable and says who can change it.
fn present_settings(parent: &adw::ApplicationWindow, context: &AppContext) {
    let window = adw::PreferencesWindow::builder()
        .transient_for(parent)
        .modal(true)
        .title("Crash Reporting")
        .default_width(560)
        .default_height(420)
        .build();

    let page = adw::PreferencesPage::new();

    let group = adw::PreferencesGroup::builder()
        .title("Automatic crash statistics")
        .description(
            "When a program crashes, a short report — the program, the package version and a \
             fingerprint of where it crashed — is sent automatically. It contains no memory \
             contents, no command line and no environment.",
        )
        .build();

    let writable = is_writable(&context.config_path);
    let toggle = adw::SwitchRow::builder()
        .title("Send crash statistics")
        .subtitle(if writable {
            context.config_path.display().to_string()
        } else {
            format!(
                "Set by an administrator in {}",
                context.config_path.display()
            )
        })
        .active(context.telemetry_enabled)
        .sensitive(writable)
        .build();

    toggle.connect_active_notify({
        let path = context.config_path.clone();
        move |row| {
            if let Err(err) = set_telemetry(&path, row.is_active()) {
                tracing::warn!(error = %err, "could not update the configuration");
            }
        }
    });
    group.add(&toggle);
    page.add(&group);

    let explain = adw::PreferencesGroup::builder()
        .title("Memory snapshots")
        .description(
            "A full memory snapshot is only ever uploaded when the crash server asks for one and \
             you agree to it in this window. It is never sent automatically.",
        )
        .build();
    page.add(&explain);

    window.add(&page);
    window.present();
}

fn is_writable(path: &std::path::Path) -> bool {
    // The honest check is whether we can actually open it for writing; permission bits alone
    // would mislead under group membership or a read-only mount.
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// Flip the opt-in in the configuration file, leaving every other field untouched.
fn set_telemetry(path: &std::path::Path, enabled: bool) -> std::io::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text)?;
    value["telemetry_enabled"] = serde_json::Value::Bool(enabled);
    std::fs::write(path, serde_json::to_vec_pretty(&value)?)
}
