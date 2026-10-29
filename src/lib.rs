//! # `webhook-shield`
//!
//! A resilient asynchronous Rust library for dispatching and verifying **Webhooks**.
//!
//! ## Key Features
//! - **HMAC-SHA256 Signing & Constant-Time Verification**: Signs `<timestamp>.<payload>` and verifies signatures in constant time to prevent timing attacks.
//! - **Replay Attack Protection**: Enforces a configurable timestamp drift tolerance window (default: 5 minutes).
//! - **Zero-Downtime Secret Rotation**: `WebhookVerifier` supports multiple active secrets (primary + fallback) during key rotation.
//! - **Resilient Async Dispatcher**: Asynchronous HTTP delivery with exponential backoff, jitter, `Retry-After` header support (`429`/`503`), and automatic classification between transient errors and permanent `4xx` client failures.
//!
//! ## Quick Start
//!
//! ```rust
//! use webhook_shield::{WebhookVerifier, sign_payload};
//!
//! let secret = b"whsec_super_secret_key";
//! let payload = br#"{"event":"order.paid","amount":150000}"#;
//! let timestamp = 1_700_000_000;
//!
//! // 1. Generate the signature header on the sender side
//! let sig_header = sign_payload(secret, timestamp, payload).unwrap();
//! assert!(sig_header.starts_with("t=1700000000,v1="));
//!
//! // 2. Verify on the receiver side (at timestamp 1_700_000_120, 120s drift <= 300s tolerance)
//! let verifier = WebhookVerifier::new(secret).unwrap();
//! let verified_ts = verifier.verify_at(payload, &sig_header, 1_700_000_120).unwrap();
//! assert_eq!(verified_ts, timestamp);
//! ```

pub mod dispatcher;
pub mod error;
pub mod payload;
pub mod signature;
pub mod verifier;

pub use dispatcher::{DeliveryReceipt, RetryPolicy, WebhookDispatcher};
pub use error::{HookError, Result};
pub use payload::{
    HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, HEADER_WEBHOOK_TIMESTAMP, WebhookEvent,
};
pub use signature::{
    ParsedSignature, compute_mac, parse_signature_header, sign_payload, verify_mac_constant_time,
};
pub use verifier::{DEFAULT_TOLERANCE_SECS, WebhookVerifier};
