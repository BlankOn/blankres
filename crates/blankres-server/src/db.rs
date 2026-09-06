//! Database access, and the payload decision that the whole two-stage design rests on.

use blankres_report::event::CrashEvent;
use chrono::{DateTime, TimeZone as _, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row as _;
use uuid::Uuid;

/// Connect and bring the schema up to date.
///
/// Migrations run here, at startup, rather than as a separate deploy step: the server is the only
/// thing that writes this schema, so it is the only thing that needs to know how to create it.
pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(database_url)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Apply the embedded migrations.
pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))
}

/// What the server decided about one event.
#[derive(Debug, Clone)]
pub struct EventOutcome {
    pub event_id: Uuid,
    pub need_payload: bool,
    /// Total events recorded for this signature, across the fleet.
    pub signature_events: i64,
    /// Payloads already stored for this signature.
    pub signature_payloads: i64,
}

fn to_datetime(unix_secs: u64) -> DateTime<Utc> {
    Utc.timestamp_opt(unix_secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Record a stage-1 event and decide whether its payload is wanted.
///
/// The decision is deliberately boring: ask for a core only while we have fewer than `quota` for
/// this signature, the signature is not suppressed, and the client actually has a core to send.
/// Everything expensive downstream hangs off this one comparison.
pub async fn record_event(
    pool: &PgPool,
    event: &CrashEvent,
    quota: i64,
) -> Result<EventOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let frames = serde_json::to_value(&event.signature.frames).unwrap_or(serde_json::Value::Null);
    let precision = match event.signature.precision {
        blankres_report::signature::Precision::Precise => "precise",
        blankres_report::signature::Precision::Coarse => "coarse",
    };

    // Upsert the signature and read back its counters in one round trip. `FOR UPDATE` semantics
    // come from the upsert itself: concurrent events for one signature serialize on this row,
    // which is what keeps the quota from being overshot by a crash storm.
    let row = sqlx::query(
        r#"
        INSERT INTO signatures (hash, precision, events, executable, package, frames)
        VALUES ($1, $2, 1, $3, $4, $5)
        ON CONFLICT (hash) DO UPDATE
            SET events = signatures.events + 1,
                last_seen = now()
        RETURNING events, payloads, suppressed
        "#,
    )
    .bind(&event.signature.hash)
    .bind(precision)
    .bind(&event.executable)
    .bind(event.package.name.as_deref())
    .bind(&frames)
    .fetch_one(&mut *tx)
    .await?;

    let signature_events: i64 = row.get("events");
    let signature_payloads: i64 = row.get("payloads");
    let suppressed: bool = row.get("suppressed");

    let need_payload = event.core_available && !suppressed && signature_payloads < quota;

    let event_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO events (
            id, signature, occurred_at, kind, executable, signal, package, package_version,
            distro, distro_version, architecture, kernel_version, machine_id, crash_count,
            client_version, core_available, core_size, payload_wanted
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        "#,
    )
    .bind(event_id)
    .bind(&event.signature.hash)
    .bind(to_datetime(event.timestamp))
    .bind(format!("{:?}", event.kind).to_lowercase())
    .bind(&event.executable)
    .bind(event.signal.map(|s| s as i32))
    .bind(event.package.name.as_deref())
    .bind(event.package.version.as_deref())
    .bind(&event.system.distro)
    .bind(&event.system.distro_version)
    .bind(&event.system.architecture)
    .bind(&event.system.kernel_version)
    .bind(&event.machine_id)
    .bind(event.crash_count as i32)
    .bind(&event.client_version)
    .bind(event.core_available)
    .bind(event.core_size.map(|s| s as i64))
    .bind(need_payload)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(EventOutcome {
        event_id,
        need_payload,
        signature_events,
        signature_payloads,
    })
}

/// Store an issued upload token. Only the hash is kept, so a database leak does not hand out
/// upload capabilities.
pub async fn issue_upload_token(
    pool: &PgPool,
    token_hash: &str,
    event_id: Uuid,
    signature: &str,
    max_bytes: u64,
    ttl_secs: i64,
) -> Result<DateTime<Utc>, sqlx::Error> {
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);
    sqlx::query(
        r#"
        INSERT INTO upload_tokens (token_hash, event_id, signature, max_bytes, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_hash)
    .bind(event_id)
    .bind(signature)
    .bind(max_bytes as i64)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(expires_at)
}

/// A redeemed upload capability.
#[derive(Debug, Clone)]
pub struct RedeemedToken {
    pub event_id: Uuid,
    pub signature: String,
    pub max_bytes: i64,
}

/// Redeem an upload token, atomically and once.
///
/// The `redeemed_at IS NULL` guard in the UPDATE is what makes this single-use: two concurrent
/// uploads with the same token cannot both win, so a leaked token cannot be replayed to fill the
/// blob store.
pub async fn redeem_upload_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<RedeemedToken>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        UPDATE upload_tokens
           SET redeemed_at = now()
         WHERE token_hash = $1
           AND redeemed_at IS NULL
           AND expires_at > now()
        RETURNING event_id, signature, max_bytes
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| RedeemedToken {
        event_id: row.get("event_id"),
        signature: row.get("signature"),
        max_bytes: row.get("max_bytes"),
    }))
}

/// Record a stored payload and count it against the signature's quota.
pub async fn record_report(
    pool: &PgPool,
    report_id: Uuid,
    event_id: Uuid,
    signature: &str,
    total_bytes: u64,
    metadata: &serde_json::Value,
    blobs: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        INSERT INTO reports (id, event_id, signature, total_bytes, metadata, blobs)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(report_id)
    .bind(event_id)
    .bind(signature)
    .bind(total_bytes as i64)
    .bind(metadata)
    .bind(blobs)
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE signatures SET payloads = payloads + 1 WHERE hash = $1")
        .bind(signature)
        .execute(&mut *tx)
        .await?;

    tx.commit().await
}

/// Metadata read-back.
pub async fn fetch_report(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, signature, received_at, total_bytes, metadata, blobs FROM reports WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        serde_json::json!({
            "id": row.get::<Uuid, _>("id").to_string(),
            "signature": row.get::<String, _>("signature"),
            "received_at": row.get::<DateTime<Utc>, _>("received_at").to_rfc3339(),
            "total_bytes": row.get::<i64, _>("total_bytes"),
            "metadata": row.get::<serde_json::Value, _>("metadata"),
            "blobs": row.get::<serde_json::Value, _>("blobs"),
        })
    }))
}

/// Signature statistics, for verifying that dedup is doing what it claims.
pub async fn fetch_signature(
    pool: &PgPool,
    hash: &str,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT hash, precision, events, payloads, suppressed, first_seen, last_seen,
               executable, package, frames
          FROM signatures WHERE hash = $1
        "#,
    )
    .bind(hash)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|row| {
        serde_json::json!({
            "hash": row.get::<String, _>("hash"),
            "precision": row.get::<String, _>("precision"),
            "events": row.get::<i64, _>("events"),
            "payloads": row.get::<i64, _>("payloads"),
            "suppressed": row.get::<bool, _>("suppressed"),
            "first_seen": row.get::<DateTime<Utc>, _>("first_seen").to_rfc3339(),
            "last_seen": row.get::<DateTime<Utc>, _>("last_seen").to_rfc3339(),
            "executable": row.get::<Option<String>, _>("executable"),
            "package": row.get::<Option<String>, _>("package"),
            "frames": row.get::<Option<serde_json::Value>, _>("frames"),
        })
    }))
}
