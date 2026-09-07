//! The public dashboard.
//!
//! A read-only listing of the most recent crashes, styled after the IRGSH chief dashboard so the
//! BlankOn services look like one system. The table refreshes itself through htmx rather than a
//! full page reload.
//!
//! Everything rendered here comes from clients, which are not trusted: an executable path or a
//! package name is whatever the reporting machine said it was. All of it is escaped.

use axum::extract::State;
use axum::response::Html;
use chrono::{DateTime, Utc};
use sqlx::Row as _;

use crate::routes::SharedState;

/// How many crashes the dashboard shows.
pub const RECENT_LIMIT: i64 = 50;

/// One row of the dashboard.
struct Row {
    received_at: DateTime<Utc>,
    executable: String,
    package: Option<String>,
    package_version: Option<String>,
    signal: Option<i32>,
    kind: String,
    distro: String,
    distro_version: String,
    architecture: String,
    signature: String,
    signature_events: i64,
    payloads: i64,
}

async fn recent(state: &SharedState) -> Result<Vec<Row>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT e.received_at, e.executable, e.package, e.package_version, e.signal, e.kind,
               e.distro, e.distro_version, e.architecture, e.signature,
               s.events AS signature_events, s.payloads
          FROM events e
          JOIN signatures s ON s.hash = e.signature
         ORDER BY e.received_at DESC
         LIMIT $1
        "#,
    )
    .bind(RECENT_LIMIT)
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Row {
            received_at: row.get("received_at"),
            executable: row.get("executable"),
            package: row.get("package"),
            package_version: row.get("package_version"),
            signal: row.get("signal"),
            kind: row.get("kind"),
            distro: row.get("distro"),
            distro_version: row.get("distro_version"),
            architecture: row.get("architecture"),
            signature: row.get("signature"),
            signature_events: row.get("signature_events"),
            payloads: row.get("payloads"),
        })
        .collect())
}

/// Escape text for HTML. Report fields are attacker-controlled, so this is not optional.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// "3m ago", so the reader can see at a glance whether anything is arriving.
fn relative(then: DateTime<Utc>) -> String {
    let seconds = (Utc::now() - then).num_seconds().max(0);
    match seconds {
        0..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86400),
    }
}

fn signal_label(signal: Option<i32>, kind: &str) -> String {
    match kind {
        "kerneloops" => "kernel oops".to_owned(),
        "packagefailure" => "package failure".to_owned(),
        _ => match signal {
            Some(number) => blankres_report::signal_name(number as u32)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("signal {number}")),
            None => "unknown".to_owned(),
        },
    }
}

/// The table body, served on its own so htmx can refresh it without reloading the page.
pub async fn reports_fragment(State(state): State<SharedState>) -> Html<String> {
    let rows = match recent(&state).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "listing recent crashes");
            return Html(
                "<tr><td colspan=\"7\" class=\"empty-cell\">Could not read the crash \
                 database.</td></tr>"
                    .to_owned(),
            );
        }
    };

    if rows.is_empty() {
        return Html(
            "<tr><td colspan=\"7\" class=\"empty-cell\">No crashes reported yet.</td></tr>"
                .to_owned(),
        );
    }

    let mut html = String::new();
    for row in rows {
        let package = match (&row.package, &row.package_version) {
            (Some(name), Some(version)) => format!("{} {}", esc(name), esc(version)),
            (Some(name), None) => esc(name),
            _ => "<span class=\"metric\">not packaged</span>".to_owned(),
        };

        // A stored payload is the difference between a crash we can debug and one we can only
        // count, so it is worth showing at a glance.
        let payload = if row.payloads > 0 {
            format!(
                "<span class=\"badge badge-payload\">{}</span>",
                row.payloads
            )
        } else {
            "<span class=\"metric\">none</span>".to_owned()
        };

        html.push_str(&format!(
            "<tr>\
             <td class=\"nowrap\" title=\"{full_time}\">{ago}</td>\
             <td class=\"mono\">{executable}</td>\
             <td>{package}</td>\
             <td class=\"nowrap\">{signal}</td>\
             <td class=\"nowrap\">{distro} {distro_version} <span class=\"metric\">{arch}</span></td>\
             <td class=\"mono nowrap\"><a href=\"/v1/signatures/{signature}\">{short}</a> \
             <span class=\"metric\">x{events}</span></td>\
             <td class=\"nowrap\">{payload}</td>\
             </tr>",
            full_time = esc(&row.received_at.to_rfc3339()),
            ago = esc(&relative(row.received_at)),
            executable = esc(&row.executable),
            package = package,
            signal = esc(&signal_label(row.signal, &row.kind)),
            distro = esc(&row.distro),
            distro_version = esc(&row.distro_version),
            arch = esc(&row.architecture),
            signature = esc(&row.signature),
            short = esc(&row.signature[..12.min(row.signature.len())]),
            events = row.signature_events,
            payload = payload,
        ));
    }

    Html(html)
}

/// The dashboard itself.
pub async fn dashboard(State(state): State<SharedState>) -> Html<String> {
    let Html(rows) = reports_fragment(State(state)).await;
    Html(
        PAGE.replace("{{ROWS}}", &rows)
            .replace("{{LIMIT}}", &RECENT_LIMIT.to_string()),
    )
}

/// Styling follows the IRGSH chief dashboard, which in turn follows blankonlinux.id: 30px/700
/// page title, muted uppercase section labels, hairline borders at 10px radius, 10px/16px rows.
const PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>BlanKres - BlankOn Crash Reporting System</title>
    <script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js"></script>
    <style>
        :root {
            --fg: #09090b;
            --muted: #737373;
            --hairline: rgba(204, 204, 204, 0.5);
            --surface: #f5f5f5;
            --primary: #171717;
            --radius: 10px;
            --sans:
                -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu',
                'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
            --mono:
                ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
                'Liberation Mono', 'Courier New', monospace;
        }
        *, *::before, *::after { box-sizing: border-box; }
        body {
            font-family: var(--sans);
            font-size: 14px;
            line-height: 20px;
            color: var(--fg);
            margin: 0;
            background-color: #fff;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .page { width: 100%; max-width: 1400px; margin: 0 auto; padding: 48px 16px 64px; }
        .header { margin-bottom: 40px; }
        .header h1 { font-size: 30px; line-height: 36px; font-weight: 700; margin: 0; }
        .header .subtitle {
            font-size: 16px; line-height: 24px; color: var(--muted); margin: 12px 0 0 0;
        }
        .source-link { margin: 8px 0 0 0; }
        .source-link a {
            display: inline-flex; align-items: center; gap: 6px;
            overflow-wrap: anywhere; text-decoration: underline; text-underline-offset: 4px;
        }
        .ext-icon { width: 14px; height: 14px; flex: none; color: rgba(115, 115, 115, 0.7); }
        .section-title {
            font-size: 14px; line-height: 20px; font-weight: 600; letter-spacing: 0.35px;
            text-transform: uppercase; color: var(--muted); margin: 40px 0 12px 0;
            display: flex; align-items: baseline; gap: 12px;
        }
        .section-title .note { text-transform: none; letter-spacing: 0; font-weight: 400; }
        .table-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        table {
            width: 100%; border-collapse: separate; border-spacing: 0; background: #fff;
            border: 1px solid var(--hairline); border-radius: var(--radius); overflow: hidden;
        }
        th {
            background: var(--surface); color: var(--muted); padding: 10px 16px; text-align: left;
            font-size: 12px; line-height: 16px; font-weight: 600; letter-spacing: 0.35px;
            text-transform: uppercase; border-bottom: 1px solid var(--hairline); white-space: nowrap;
        }
        td {
            padding: 10px 16px; border-bottom: 1px solid var(--hairline);
            font-size: 14px; line-height: 20px; vertical-align: top;
        }
        tbody tr:last-child td { border-bottom: 0; }
        tbody tr:hover { background-color: var(--surface); }
        a { color: var(--muted); }
        a:hover { color: var(--primary); }
        .mono { font-family: var(--mono); }
        .nowrap { white-space: nowrap; }
        .metric { color: var(--muted); }
        .empty-cell { color: var(--muted); text-align: center; padding: 40px; }
        .badge {
            display: inline-block; padding: 2px 8px; border-radius: 6px;
            font-size: 12px; line-height: 16px; font-weight: 500;
        }
        .badge-payload { background: #2196F3; color: #fff; }
        @media (max-width: 640px) {
            .page { padding: 32px 16px 48px; }
            table { min-width: 860px; }
        }
    </style>
</head>
<body>
    <div class="page">
        <div class="header">
            <h1>BlanKres</h1>
            <p class="subtitle">BlankOn Crash Reporting System</p>
            <p class="source-link"><a href="https://github.com/BlankOn/blankres" target="_blank" rel="noopener noreferrer">https://github.com/BlankOn/blankres<svg class="ext-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg></a></p>
        </div>

        <div class="section-title">
            Recent crashes
            <span class="note">newest {{LIMIT}}, refreshed every 15 seconds</span>
        </div>
        <div class="table-scroll">
            <table>
                <thead>
                    <tr>
                        <th>When</th>
                        <th>Program</th>
                        <th>Package</th>
                        <th>Reason</th>
                        <th>System</th>
                        <th>Signature</th>
                        <th>Payloads</th>
                    </tr>
                </thead>
                <tbody hx-get="/fragments/reports" hx-trigger="every 15s" hx-swap="innerHTML">
{{ROWS}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"##;
