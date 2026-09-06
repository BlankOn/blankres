//! Reader for apport's `.crash` format, so existing reports on a machine being migrated are not
//! stranded and so real-world files can be used as test fixtures.
//!
//! The format is Debian control (RFC822-ish): `Key: value` lines, with continuations indented by
//! one space. A continuation line of exactly one space followed by base64 marks a binary value,
//! which is base64-decoded and then zlib-inflated.
//!
//! Read support only. We do not write this format; our own canonical JSON is the output.

use std::collections::BTreeMap;
use std::io::Read;

use base64::Engine as _;
use flate2::read::ZlibDecoder;

#[derive(Debug, thiserror::Error)]
pub enum ApportError {
    #[error("malformed line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("invalid base64 in field {field}: {source}")]
    Base64 {
        field: String,
        #[source]
        source: base64::DecodeError,
    },
    #[error("could not decompress field {field}: {source}")]
    Decompress {
        field: String,
        #[source]
        source: std::io::Error,
    },
}

/// One field of a `.crash` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    /// A decoded binary value, e.g. an embedded core dump.
    Binary(Vec<u8>),
}

impl Value {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            Value::Binary(_) => None,
        }
    }
}

/// Parse a `.crash` file into its fields.
pub fn parse(input: &str) -> Result<BTreeMap<String, Value>, ApportError> {
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut current: Option<(String, Vec<String>, bool)> = None;

    for (index, line) in input.lines().enumerate() {
        // Continuation: a leading space. Everything else starts a new field.
        if let Some(rest) = line.strip_prefix(' ') {
            let Some((_, chunks, is_binary)) = current.as_mut() else {
                return Err(ApportError::Malformed {
                    line: index + 1,
                    reason: "continuation before any field".to_owned(),
                });
            };
            // apport writes `.` for an intentionally blank line in a text value.
            if !*is_binary && rest == "." {
                chunks.push(String::new());
            } else {
                chunks.push(rest.to_owned());
            }
            continue;
        }

        if line.trim().is_empty() {
            continue;
        }

        if let Some(finished) = current.take() {
            let (name, value) = finish_field(finished)?;
            fields.insert(name, value);
        }

        let (name, rest) = line.split_once(':').ok_or_else(|| ApportError::Malformed {
            line: index + 1,
            reason: "expected `Key: value`".to_owned(),
        })?;
        let rest = rest.trim_start();

        // `Key: base64` announces a binary value whose data follows on continuation lines.
        let is_binary = rest == "base64";
        let mut chunks = Vec::new();
        if !is_binary && !rest.is_empty() {
            chunks.push(rest.to_owned());
        }
        current = Some((name.trim().to_owned(), chunks, is_binary));
    }

    if let Some(finished) = current {
        let (name, value) = finish_field(finished)?;
        fields.insert(name, value);
    }

    Ok(fields)
}

fn finish_field(
    (name, chunks, is_binary): (String, Vec<String>, bool),
) -> Result<(String, Value), ApportError> {
    if !is_binary {
        return Ok((name, Value::Text(chunks.join("\n"))));
    }

    // Binary values are chunked base64; apport's first chunk is a gzip-style header it writes
    // separately, so decode everything and inflate the concatenation.
    let engine = base64::engine::general_purpose::STANDARD;
    let mut compressed = Vec::new();
    for chunk in &chunks {
        let decoded = engine
            .decode(chunk.trim())
            .map_err(|source| ApportError::Base64 {
                field: name.clone(),
                source,
            })?;
        compressed.extend_from_slice(&decoded);
    }

    let mut decoder = ZlibDecoder::new(compressed.as_slice());
    let mut plain = Vec::new();
    decoder
        .read_to_end(&mut plain)
        .map_err(|source| ApportError::Decompress {
            field: name.clone(),
            source,
        })?;

    Ok((name, Value::Binary(plain)))
}
