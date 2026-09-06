//! Content-addressed blob storage.
//!
//! Blobs are named by their SHA-256, which deduplicates identical cores for free and makes the
//! integrity check in the end-to-end test trivial: the stored name *is* the expected digest.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("writing blob: {0}")]
    Io(#[from] std::io::Error),
    #[error("payload exceeded the {limit} byte limit")]
    TooLarge { limit: u64 },
}

/// A stored blob.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Blob {
    pub sha256: String,
    pub size: u64,
}

/// Where payloads land. A trait so an S3 backend can drop in without touching the routes.
#[allow(async_fn_in_trait)]
pub trait Storage: Send + Sync {
    /// Begin a streaming write.
    async fn begin(&self) -> Result<BlobWriter, StorageError>;
}

/// Local filesystem storage rooted at a directory.
#[derive(Debug, Clone)]
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub async fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        tokio::fs::create_dir_all(root.join("blobs")).await?;
        tokio::fs::create_dir_all(root.join("incoming")).await?;
        Ok(Self { root })
    }

    pub fn blob_path(&self, sha256: &str) -> PathBuf {
        self.root.join("blobs").join(&sha256[..2]).join(sha256)
    }
}

impl Storage for LocalStorage {
    async fn begin(&self) -> Result<BlobWriter, StorageError> {
        let temp = self
            .root
            .join("incoming")
            .join(uuid::Uuid::new_v4().to_string());
        let file = tokio::fs::File::create(&temp).await?;
        Ok(BlobWriter {
            root: self.root.clone(),
            temp,
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
        })
    }
}

/// An in-progress blob write.
///
/// Hashes as it writes, so a large core is never held in memory and never read a second time to
/// compute its digest.
pub struct BlobWriter {
    root: PathBuf,
    temp: PathBuf,
    file: Option<tokio::fs::File>,
    hasher: Sha256,
    written: u64,
}

impl BlobWriter {
    /// Append a chunk, refusing to exceed `limit`.
    pub async fn write(&mut self, chunk: &[u8], limit: u64) -> Result<(), StorageError> {
        if self.written + chunk.len() as u64 > limit {
            return Err(StorageError::TooLarge { limit });
        }
        self.hasher.update(chunk);
        self.written += chunk.len() as u64;
        if let Some(file) = self.file.as_mut() {
            file.write_all(chunk).await?;
        }
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Move the finished blob to its content address.
    pub async fn finish(mut self) -> Result<Blob, StorageError> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            file.sync_all().await?;
        }

        let sha256 = hex::encode(self.hasher.finalize_reset());
        let final_path = self.root.join("blobs").join(&sha256[..2]).join(&sha256);
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // An identical blob already stored means this core is a duplicate; drop ours rather than
        // rewriting it.
        if tokio::fs::metadata(&final_path).await.is_ok() {
            let _ = tokio::fs::remove_file(&self.temp).await;
        } else {
            tokio::fs::rename(&self.temp, &final_path).await?;
        }

        Ok(Blob {
            sha256,
            size: self.written,
        })
    }

    /// Abandon the write and remove the temporary file.
    pub async fn abort(mut self) {
        self.file.take();
        let _ = tokio::fs::remove_file(&self.temp).await;
    }
}

/// Write report metadata alongside the blobs, so the store is readable without the database.
pub async fn write_metadata(
    root: &Path,
    id: &str,
    metadata: &serde_json::Value,
) -> Result<(), StorageError> {
    let dir = root.join("reports");
    tokio::fs::create_dir_all(&dir).await?;
    let body = serde_json::to_vec_pretty(metadata).unwrap_or_default();
    tokio::fs::write(dir.join(format!("{id}.json")), body).await?;
    Ok(())
}
