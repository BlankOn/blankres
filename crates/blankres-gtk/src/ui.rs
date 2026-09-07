//! The consent window.
//!
//! This window exists for one reason: a core dump is a copy of the crashed process's memory, and
//! it can contain documents, keystrokes, session cookies and private keys. Nobody can meaningfully
//! agree to send that on the strength of "an error report". So the window states the size in
//! plain language and shows, verbatim, every field that would be transmitted. Nothing leaves
//! the machine until the user presses Send.
//!
//! Stage 1 never reaches this window. By the time it opens, the server has already said it wants
//! a payload for this particular signature.

use adw::prelude::*;
use blankres_client::Client;
use blankres_i18n::Catalog;
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
        .title(context.catalog.app_title())
        .default_width(720)
        .default_height(640)
        .build();

    let toasts = adw::ToastOverlay::new();
    let layout = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let header = adw::HeaderBar::new();
    let settings = gtk::Button::builder()
        .icon_name("emblem-system-symbolic")
        .tooltip_text(context.catalog.settings_tooltip())
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
        layout.append(&empty_state(&context.catalog));
    } else {
        layout.append(&report_view(&window, &toasts, &context, entries));
    }

    toasts.set_child(Some(&layout));
    window.set_content(Some(&toasts));

    // Closing the window means the same thing as "Don't send". A consent dialog that is dismissed
    // has not consented, and the alternative is worse than it sounds: reports left on disk keep
    // the crash directory non-empty, and the systemd path unit that opens this window only fires
    // when that directory goes from empty to non-empty. Leaving them would quietly stop every
    // future crash from being shown.
    window.connect_close_request({
        let store = context.store.clone();
        move |_| {
            // Read the directory again rather than trusting a list captured at startup: anything
            // already sent or discarded is gone, and must not be "discarded" a second time.
            for entry in store.list() {
                ReportSession::new(&store, entry).discard();
            }
            glib::Propagation::Proceed
        }
    });

    window
}

fn empty_state(catalog: &Catalog) -> gtk::Widget {
    let status = adw::StatusPage::builder()
        .icon_name("emblem-ok-symbolic")
        .title(catalog.nothing_to_report())
        .description(catalog.nothing_to_report_detail())
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
    let catalog = context.catalog;
    let session = ReportSession::with_catalog(&context.store, entry.clone(), catalog);
    let program = entry.program();
    let size = entry.transfer_size();
    let expired = !session.is_actionable(blankres_session::now_secs());
    let awaiting = entry.pending.awaiting_directive;

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

    let title = gtk::Label::new(Some(&catalog.closed_unexpectedly(&program)));
    title.add_css_class("title-2");
    title.set_wrap(true);
    title.set_justify(gtk::Justification::Center);
    headline.append(&title);

    // The size belongs in the headline, not in the details: it is what someone actually weighs
    // when deciding whether to send a snapshot of their own memory.
    let subtitle = gtk::Label::new(Some(&if expired {
        catalog.expired().to_owned()
    } else if awaiting {
        catalog.awaiting_server(&human_size(size))
    } else {
        catalog.upload_warning(&human_size(size))
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
        .title(catalog.what_would_be_sent())
        .description(catalog.what_would_be_sent_detail())
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
        .text(catalog.uploading())
        .build();

    let ignore = gtk::Button::with_label(catalog.never_for_this_problem());
    let send = gtk::Button::with_label(catalog.send_report());
    let discard = gtk::Button::with_label(catalog.dont_send());
    send.set_sensitive(!expired);

    // "Don't send" is the default, and sits rightmost where the default belongs. Uploading a
    // snapshot of your own process memory should be a deliberate act, so the safe choice is the
    // one that happens on Enter or a reflexive click, and the irreversible one is never the
    // button that is already focused.
    discard.add_css_class("suggested-action");
    discard.set_receives_default(true);
    window.set_default_widget(Some(&discard));

    buttons.append(&ignore);
    buttons.append(&send);
    buttons.append(&discard);

    let footer = gtk::Box::new(gtk::Orientation::Vertical, 6);
    footer.append(&progress);
    footer.append(&buttons);
    footer.add_css_class("toolbar");

    wire_actions(
        window, toasts, context, &entry, &send, &discard, &ignore, &progress,
    );

    discard.grab_focus();

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
        let catalog = context.catalog;
        move |button| {
            ReportSession::new(&store, entry.clone()).discard();
            button.set_sensitive(false);
            toasts.add_toast(adw::Toast::new(catalog.report_discarded()));
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
        let catalog = context.catalog;
        move |button| {
            let session = ReportSession::new(&store, entry.clone());
            let message = match session.decline_forever() {
                Ok(()) => catalog.problem_ignored(),
                Err(_) => catalog.could_not_record_decision(),
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
        let catalog = context.catalog;
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
                let catalog = catalog;
                async move {
                    let result = receiver.recv().await;
                    pulse.remove();
                    progress.set_visible(false);

                    match result {
                        Ok(UploadResult::Sent { id }) => {
                            toasts.add_toast(adw::Toast::new(&catalog.report_sent(&id)));
                            disable_siblings(&button);
                            let _ = window;
                        }
                        Ok(UploadResult::Failed { message }) => {
                            toasts
                                .add_toast(adw::Toast::new(&format!("Could not send: {message}")));
                            button.set_sensitive(true);
                        }
                        Err(_) => {
                            toasts.add_toast(adw::Toast::new(catalog.upload_ended_unexpectedly()));
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
        .title(context.catalog.app_title())
        .default_width(560)
        .default_height(420)
        .build();

    let page = adw::PreferencesPage::new();

    let group = adw::PreferencesGroup::builder()
        .title(context.catalog.automatic_statistics())
        .description(context.catalog.automatic_statistics_detail())
        .build();

    let writable = is_writable(&context.config_path);
    let toggle = adw::SwitchRow::builder()
        .title(context.catalog.send_statistics())
        .subtitle(if writable {
            context.config_path.display().to_string()
        } else {
            context
                .catalog
                .set_by_administrator(&context.config_path.display().to_string())
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
        .title(context.catalog.memory_snapshots())
        .description(context.catalog.memory_snapshots_detail())
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
