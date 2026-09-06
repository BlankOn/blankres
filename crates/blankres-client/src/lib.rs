//! Client for the blankres reporting protocol.
//!
//! Shared by the daemon (which sends stage-1 events), the CLI and the GTK front end (which send
//! stage-2 payloads), so the protocol lives in one place and consent cannot be bypassed by one
//! caller taking a shortcut.

use std::time::Duration;

use blankres_report::event::{CrashEvent, DirectiveBatch, EventBatch, PayloadDirective};
use blankres_report::report::{Attachment, Report};
use reqwest::multipart::{Form, Part};
use reqwest::Body;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("server rejected the request: {status} {body}")]
    Rejected {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("server returned {returned} directives for {sent} events")]
    DirectiveMismatch { sent: usize, returned: usize },
    #[error("this report has no upload token; the server did not ask for a payload")]
    NoUploadToken,
    #[error("payload is {size} bytes, over the server's limit of {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Where to report and how to authenticate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Base URL, e.g. `https://crashes.example.org`.
    pub url: String,
    /// Bearer token identifying this fleet.
    pub token: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_timeout_secs() -> u64 {
    30
}

impl Endpoint {
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: token.into(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

/// Receipt for an accepted stage-2 payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadReceipt {
    pub id: String,
    #[serde(default)]
    pub url: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    endpoint: Endpoint,
}

impl Client {
    pub fn new(endpoint: Endpoint) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(endpoint.timeout_secs))
            .user_agent(concat!("blankres/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, endpoint })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Stage 1. Send events and get one directive per event, in order.
    ///
    /// Batched because a machine coming back online may have a spool to drain, and because the
    /// per-request overhead would otherwise dominate a 1 KB body.
    pub async fn send_events(
        &self,
        events: &[CrashEvent],
    ) -> Result<Vec<PayloadDirective>, ClientError> {
        let batch = EventBatch {
            events: events.to_vec(),
        };

        let response = self
            .http
            .post(format!("{}/v1/events", self.endpoint.url))
            .bearer_auth(&self.endpoint.token)
            .json(&batch)
            .send()
            .await?;

        let response = check(response).await?;
        let DirectiveBatch { directives } = response.json().await?;

        // The client pairs directives with events positionally, so a length mismatch would
        // silently attach the wrong upload token to the wrong crash.
        if directives.len() != events.len() {
            return Err(ClientError::DirectiveMismatch {
                sent: events.len(),
                returned: directives.len(),
            });
        }

        Ok(directives)
    }

    /// Stage 2. Upload a payload against the token the server issued.
    ///
    /// The core dump is streamed from disk in the compressed frames systemd wrote; it is never
    /// read into memory, so uploading a 4 GB core costs a buffer, not 4 GB of RSS.
    pub async fn upload_report(
        &self,
        report: &Report,
        directive: &PayloadDirective,
    ) -> Result<UploadReceipt, ClientError> {
        let Some(token) = directive.upload_token.as_deref() else {
            return Err(ClientError::NoUploadToken);
        };

        let size = report.transfer_size();
        if let Some(limit) = directive.max_bytes {
            if size > limit {
                return Err(ClientError::TooLarge { size, limit });
            }
        }

        let metadata = serde_json::to_vec(report).expect("report serializes");
        let mut form = Form::new().part(
            "metadata",
            Part::bytes(metadata)
                .file_name("metadata.json")
                .mime_str("application/json")
                .expect("static mime"),
        );

        for attachment in &report.attachments {
            form = form.part(attachment.name().to_owned(), part_for(attachment).await?);
        }

        let response = self
            .http
            .post(format!("{}/v1/reports", self.endpoint.url))
            .bearer_auth(&self.endpoint.token)
            .header("x-blankres-upload-token", token)
            .multipart(form)
            .send()
            .await?;

        Ok(check(response).await?.json().await?)
    }

    /// Read back a stored report's metadata. Used by the end-to-end checks.
    pub async fn fetch_report(&self, id: &str) -> Result<serde_json::Value, ClientError> {
        let response = self
            .http
            .get(format!("{}/v1/reports/{id}", self.endpoint.url))
            .bearer_auth(&self.endpoint.token)
            .send()
            .await?;
        Ok(check(response).await?.json().await?)
    }

    /// Statistics for one signature, for verifying dedup behaviour.
    pub async fn fetch_signature(&self, hash: &str) -> Result<serde_json::Value, ClientError> {
        let response = self
            .http
            .get(format!("{}/v1/signatures/{hash}", self.endpoint.url))
            .bearer_auth(&self.endpoint.token)
            .send()
            .await?;
        Ok(check(response).await?.json().await?)
    }
}

/// Build a multipart part, streaming files rather than buffering them.
async fn part_for(attachment: &Attachment) -> Result<Part, ClientError> {
    match attachment {
        Attachment::Inline { name, content } => Ok(Part::text(content.clone())
            .file_name(format!("{name}.txt"))
            .mime_str("text/plain")
            .expect("static mime")),
        Attachment::File {
            name,
            path,
            size,
            compression,
        } => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|source| ClientError::Io {
                    path: path.display().to_string(),
                    source,
                })?;
            let stream = ReaderStream::new(file);
            let mime = match compression.as_deref() {
                Some("zstd") => "application/zstd",
                _ => "application/octet-stream",
            };
            Ok(Part::stream_with_length(Body::wrap_stream(stream), *size)
                .file_name(name.clone())
                .mime_str(mime)
                .expect("static mime"))
        }
    }
}

async fn check(response: reqwest::Response) -> Result<reqwest::Response, ClientError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    Err(ClientError::Rejected { status, body })
}
