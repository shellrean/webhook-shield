use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Standard HTTP header name for the unique webhook event ID.
pub const HEADER_WEBHOOK_ID: &str = "X-Webhook-Id";

/// Standard HTTP header name for the Unix timestamp when the webhook was signed.
pub const HEADER_WEBHOOK_TIMESTAMP: &str = "X-Webhook-Timestamp";

/// Standard HTTP header name for the HMAC signature (`t=<ts>,v1=<hex>`).
pub const HEADER_WEBHOOK_SIGNATURE: &str = "X-Webhook-Signature";

/// Standard envelope structure for a webhook event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookEvent<T> {
    /// Unique identifier for this event (can be used as an idempotency key by receivers).
    pub id: String,
    /// Event type or topic name, e.g., `"payment.succeeded"` or `"order.created"`.
    pub event_type: String,
    /// Unix timestamp (in seconds) when the event was created.
    pub timestamp: u64,
    /// Event payload data.
    pub data: T,
}

impl<T> WebhookEvent<T> {
    /// Creates a new `WebhookEvent` with an auto-generated UUID v4 identifier and the current Unix timestamp.
    pub fn new(event_type: impl Into<String>, data: T) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: format!("evt_{}", Uuid::new_v4().simple()),
            event_type: event_type.into(),
            timestamp: now,
            data,
        }
    }

    /// Creates a `WebhookEvent` with a custom ID and timestamp (useful for deterministic testing).
    pub fn with_metadata(
        id: impl Into<String>,
        event_type: impl Into<String>,
        timestamp: u64,
        data: T,
    ) -> Self {
        Self {
            id: id.into(),
            event_type: event_type.into(),
            timestamp,
            data,
        }
    }
}
