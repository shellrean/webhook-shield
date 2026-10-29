use thiserror::Error;

/// Standard `Result` alias for all operations within the `webhook-shield` crate.
pub type Result<T> = std::result::Result<T, HookError>;

/// Errors that can occur during webhook signing, signature verification, or HTTP dispatch.
#[derive(Debug, Error)]
pub enum HookError {
    /// The provided signing secret is empty.
    #[error("signing secret must not be empty")]
    EmptySecret,

    /// The signature header does not conform to the expected `t=<timestamp>,v1=<hex>` format.
    #[error("malformed signature header: {0}")]
    MalformedSignatureHeader(String),

    /// Failed to decode a hexadecimal signature value.
    #[error("invalid hex in signature: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// The computed HMAC-SHA256 signature did not match any candidate signature in the header.
    #[error("signature verification failed: mismatch")]
    InvalidSignature,

    /// The webhook timestamp is outside the allowed tolerance window (replay attack protection).
    #[error(
        "webhook timestamp out of tolerance (drift: {drift_secs}s, tolerance: {tolerance_secs}s)"
    )]
    TimestampOutOfTolerance {
        drift_secs: u64,
        tolerance_secs: u64,
    },

    /// Failed to serialize or deserialize the JSON payload.
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The receiving server returned a non-retryable 4xx HTTP status code (excluding 408 and 429).
    #[error("permanent HTTP failure from receiver (HTTP {status}): {body}")]
    PermanentHttpFailure { status: u16, body: String },

    /// All delivery attempts (initial + retries) have been exhausted.
    #[error("webhook delivery failed after {attempts} attempts: {last_error}")]
    DeliveryExhausted { attempts: u32, last_error: String },

    /// Underlying HTTP client configuration or transport error.
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),
}
