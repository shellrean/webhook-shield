use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{HookError, Result};
use crate::signature::{parse_signature_header, verify_mac_constant_time};

/// Default timestamp drift tolerance (5 minutes / 300 seconds) for replay attack protection.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// Webhook verifier for authenticating HMAC-SHA256 signatures and preventing replay attacks.
///
/// Supports multi-secret verification so you can perform zero-downtime secret rotation
/// (e.g., configuring a new primary secret while retaining the previous secret as a fallback).
#[derive(Debug, Clone)]
pub struct WebhookVerifier {
    secrets: Vec<Vec<u8>>,
    tolerance: Option<Duration>,
}

impl WebhookVerifier {
    /// Creates a new `WebhookVerifier` with a primary secret and the default 5-minute (300s) tolerance window.
    pub fn new(primary_secret: impl AsRef<[u8]>) -> Result<Self> {
        let secret_bytes = primary_secret.as_ref().to_vec();
        if secret_bytes.is_empty() {
            return Err(HookError::EmptySecret);
        }

        Ok(Self {
            secrets: vec![secret_bytes],
            tolerance: Some(Duration::from_secs(DEFAULT_TOLERANCE_SECS)),
        })
    }

    /// Adds a fallback secret to support zero-downtime key rotation transitions.
    pub fn with_fallback_secret(mut self, fallback_secret: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = fallback_secret.as_ref().to_vec();
        if bytes.is_empty() {
            return Err(HookError::EmptySecret);
        }
        self.secrets.push(bytes);
        Ok(self)
    }

    /// Sets the maximum allowed timestamp drift between the header timestamp and the reference time.
    pub fn with_tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = Some(tolerance);
        self
    }

    /// Disables timestamp tolerance validation (only recommended for testing).
    pub fn without_tolerance(mut self) -> Self {
        self.tolerance = None;
        self
    }

    /// Verifies the payload and signature header against the current system time (`SystemTime::now()`).
    ///
    /// Returns the verified Unix timestamp from the webhook header if valid.
    pub fn verify(&self, payload: &[u8], signature_header: &str) -> Result<u64> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.verify_at(payload, signature_header, now_secs)
    }

    /// Verifies the payload and signature header against a custom reference timestamp (`now_secs`).
    ///
    /// Useful for deterministic unit tests without relying on the system clock.
    pub fn verify_at(&self, payload: &[u8], signature_header: &str, now_secs: u64) -> Result<u64> {
        let parsed = parse_signature_header(signature_header)?;

        // 1. Verify signature in constant time against all configured secrets
        let mut matched = false;
        for secret in &self.secrets {
            for candidate_sig in &parsed.signatures {
                if verify_mac_constant_time(secret, parsed.timestamp, payload, candidate_sig)? {
                    matched = true;
                    break;
                }
            }
            if matched {
                break;
            }
        }

        if !matched {
            return Err(HookError::InvalidSignature);
        }

        // 2. Enforce timestamp tolerance window (Replay Attack Protection)
        if let Some(tolerance) = self.tolerance {
            let drift_secs = now_secs.abs_diff(parsed.timestamp);
            let tolerance_secs = tolerance.as_secs();
            if drift_secs > tolerance_secs {
                return Err(HookError::TimestampOutOfTolerance {
                    drift_secs,
                    tolerance_secs,
                });
            }
        }

        Ok(parsed.timestamp)
    }

    /// Verifies the signature and deserializes the JSON payload into type `T`.
    pub fn verify_and_parse<T: DeserializeOwned>(
        &self,
        payload: &[u8],
        signature_header: &str,
    ) -> Result<T> {
        self.verify(payload, signature_header)?;
        let parsed = serde_json::from_slice(payload)?;
        Ok(parsed)
    }
}
