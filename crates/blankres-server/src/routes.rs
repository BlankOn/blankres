//! HTTP surface: two ingest endpoints matching the two reporting stages, plus read-back.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use blankres_report::event::{DirectiveBatch, EventBatch, PayloadDirective};
use rand::RngCore as _;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::{hash_token, Config};
use crate::db;
use crate::storage::{write_metadata, LocalStorage, Storage as _};
use tower_http::trace::TraceLayer;

pub struct AppState {
    pub pool: PgPool,
    pub storage: LocalStorage,
    pub config: Config,
}

pub type SharedState = Arc<AppState>;

pub fn router(state: SharedState) -> Router {
    Router::new()
        // The dashboard is deliberately unauthenticated: a browser cannot present a bearer
        // token, and a status page nobody can open is not a status page. It shows crash
        // metadata only, never a payload.
        .route("/", get(crate::web::dashboard))
        .route("/fragments/reports", get(crate::web::reports_fragment))
        .route("/healthz", get(healthz))
        .route("/v1/events", post(post_events))
        .route("/v1/reports", post(post_report))
        .route("/v1/reports/{id}", get(get_report))
        .route("/v1/signatures/{hash}", get(get_signature))
        // Multipart bodies are streamed field by field, so the global body limit is disabled here
        // and the real ceiling is the per-upload `max_bytes` from the directive.
        .layer(DefaultBodyLimit::disable())
        // One line per request. Without it the only thing this service ever logs is that it
        // started, which is indistinguishable from it doing nothing at all.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        path = %request.uri().path(),
                    )
                })
                .on_response(
                    |response: &axum::http::Response<_>,
                     latency: std::time::Duration,
                     _span: &tracing::Span| {
                        tracing::info!(
                            status = response.status().as_u16(),
                            latency_ms = latency.as_millis(),
                            "handled"
                        );
                    },
                ),
        )
        .with_state(state)
}

/// An error that is safe to return to a client.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "database error");
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error".to_owned(),
        )
    }
}

async fn healthz(State(state): State<SharedState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(err) => {
            tracing::error!(error = %err, "health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "database unavailable" })),
            )
        }
    }
}

/// Check the fleet token. Compared by hash so the configured value is not itself a credential.
///
/// With no tokens configured the endpoint is open and every request is accepted, with or without
/// an `Authorization` header. See [`Config::is_open`]; the server announces the mode at startup.
fn authorize(headers: &HeaderMap, config: &Config) -> Result<(), ApiError> {
    if config.is_open() {
        return Ok(());
    }

    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".to_owned()))?;

    let presented = hash_token(presented);
    if config.token_hashes.iter().any(|known| known == &presented) {
        return Ok(());
    }
    Err(ApiError(
        StatusCode::UNAUTHORIZED,
        "unrecognized token".to_owned(),
    ))
}

/// Stage 1. The endpoint every crash on every machine hits, so it stays a couple of queries.
async fn post_events(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(batch): Json<EventBatch>,
) -> Result<Json<DirectiveBatch>, ApiError> {
    authorize(&headers, &state.config)?;

    let mut directives = Vec::with_capacity(batch.events.len());

    for event in &batch.events {
        let outcome =
            db::record_event(&state.pool, event, state.config.payloads_per_signature).await?;

        if !outcome.need_payload {
            directives.push(PayloadDirective::not_needed(outcome.event_id.to_string()));
            continue;
        }

        // Issue a single-use capability rather than letting any authenticated client push a core.
        let token = random_token();
        let max_bytes = event
            .core_size
            .map(|size| size.saturating_add(1024 * 1024))
            .unwrap_or(state.config.max_payload_bytes)
            .min(state.config.max_payload_bytes);

        let expires_at = db::issue_upload_token(
            &state.pool,
            &hash_token(&token),
            outcome.event_id,
            &event.signature.hash,
            max_bytes,
            state.config.upload_token_ttl_secs,
        )
        .await?;

        directives.push(PayloadDirective {
            id: outcome.event_id.to_string(),
            need_payload: true,
            upload_token: Some(token),
            max_bytes: Some(max_bytes),
            expires_at: Some(expires_at.timestamp() as u64),
        });
    }

    Ok(Json(DirectiveBatch { directives }))
}

/// Stage 2. Streams every part to disk; nothing is buffered in memory.
async fn post_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    authorize(&headers, &state.config)?;

    let upload_token = headers
        .get("x-blankres-upload-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "missing upload token; payloads must be requested by the server".to_owned(),
            )
        })?;

    let redeemed = db::redeem_upload_token(&state.pool, &hash_token(upload_token))
        .await?
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "upload token is unknown, expired or already used".to_owned(),
            )
        })?;

    let limit = (redeemed.max_bytes as u64).min(state.config.max_payload_bytes);
    let mut metadata: Option<serde_json::Value> = None;
    let mut blobs = serde_json::Map::new();
    let mut total_bytes = 0u64;

    while let Some(mut field) = multipart.next_field().await.map_err(|err| {
        ApiError(
            StatusCode::BAD_REQUEST,
            format!("malformed multipart body: {err}"),
        )
    })? {
        let name = field.name().unwrap_or_default().to_owned();

        let mut writer = state.storage.begin().await.map_err(|err| {
            tracing::error!(error = %err, "opening blob");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage error".to_owned(),
            )
        })?;

        // The metadata part is small and needed in memory; every other part goes straight to disk.
        let mut metadata_bytes = Vec::new();

        loop {
            let chunk = match field.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(err) => {
                    writer.abort().await;
                    return Err(ApiError(
                        StatusCode::BAD_REQUEST,
                        format!("truncated upload: {err}"),
                    ));
                }
            };

            total_bytes += chunk.len() as u64;
            if total_bytes > limit {
                writer.abort().await;
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("payload exceeds the {limit} byte limit for this upload"),
                ));
            }

            if name == "metadata" {
                metadata_bytes.extend_from_slice(&chunk);
                continue;
            }

            if let Err(err) = writer.write(&chunk, limit).await {
                writer.abort().await;
                return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("{err}")));
            }
        }

        if name == "metadata" {
            writer.abort().await;
            metadata = Some(serde_json::from_slice(&metadata_bytes).map_err(|err| {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    format!("metadata is not valid JSON: {err}"),
                )
            })?);
            continue;
        }

        let blob = writer.finish().await.map_err(|err| {
            tracing::error!(error = %err, "finishing blob");
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage error".to_owned(),
            )
        })?;
        blobs.insert(name, json!({ "sha256": blob.sha256, "size": blob.size }));
    }

    let metadata = metadata.ok_or_else(|| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "no metadata part in the upload".to_owned(),
        )
    })?;

    let report_id = Uuid::new_v4();
    let blobs = serde_json::Value::Object(blobs);

    db::record_report(
        &state.pool,
        report_id,
        redeemed.event_id,
        &redeemed.signature,
        total_bytes,
        &metadata,
        &blobs,
    )
    .await?;

    // Best effort: the database is the record of truth, the sidecar is for operators poking at
    // the store directly.
    if let Err(err) = write_metadata(
        &state.config.storage_root,
        &report_id.to_string(),
        &metadata,
    )
    .await
    {
        tracing::warn!(error = %err, "could not write metadata sidecar");
    }

    let url = state
        .config
        .public_url
        .as_ref()
        .map(|base| format!("{base}/v1/reports/{report_id}"));

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": report_id.to_string(), "url": url })),
    )
        .into_response())
}

async fn get_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &state.config)?;
    let id = Uuid::parse_str(&id)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "malformed report id".to_owned()))?;

    db::fetch_report(&state.pool, id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such report".to_owned()))
}

async fn get_signature(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&headers, &state.config)?;

    db::fetch_signature(&state.pool, &hash)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such signature".to_owned()))
}

/// A 256-bit upload capability.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
