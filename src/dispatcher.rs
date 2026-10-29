use rand::Rng;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER};
use serde::Serialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::{HookError, Result};
use crate::payload::{
    HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, HEADER_WEBHOOK_TIMESTAMP, WebhookEvent,
};
use crate::signature::sign_payload;

/// Retry policy with exponential backoff and optional jitter for webhook delivery.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts after the initial attempt fails (default: 3).
    pub max_retries: u32,
    /// Initial wait duration before the first retry (default: 200ms).
    pub initial_backoff: Duration,
    /// Maximum wait duration between retries (default: 15 seconds).
    pub max_backoff: Duration,
    /// Multiplier factor for exponential backoff (default: 2.0).
    pub backoff_multiplier: f64,
    /// Whether to apply randomized equal jitter to prevent thundering herds.
    pub use_jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(15),
            backoff_multiplier: 2.0,
            use_jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Computes the backoff duration for a 0-indexed `retry_attempt`.
    pub fn compute_delay(&self, retry_attempt: u32) -> Duration {
        let factor = self.backoff_multiplier.powi(retry_attempt as i32);
        let raw_secs = (self.initial_backoff.as_secs_f64() * factor)
            .min(self.max_backoff.as_secs_f64());

        let final_secs = if self.use_jitter {
            // Equal jitter: between 50% and 100% of raw_secs
            let mut rng = rand::rng();
            let jitter_factor: f64 = rng.random_range(0.5..=1.0);
            raw_secs * jitter_factor
        } else {
            raw_secs
        };

        Duration::from_secs_f64(final_secs)
    }
}

/// Delivery receipt returned when a webhook is accepted by the destination endpoint.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    /// Unique identifier of the delivered webhook (`X-Webhook-Id`).
    pub webhook_id: String,
    /// HTTP status code returned by the receiving server (e.g., `200` or `202`).
    pub status_code: u16,
    /// Total number of attempts made until success (`1` means succeeded on the first try).
    pub attempts: u32,
    /// Total elapsed wall-clock time from the first attempt until completion.
    pub elapsed: Duration,
}

/// Asynchronous webhook dispatcher handling automatic HMAC-SHA256 signing,
/// standard headers, `Retry-After` parsing, and exponential backoff.
#[derive(Debug, Clone)]
pub struct WebhookDispatcher {
    client: Client,
    secret: Vec<u8>,
    retry_policy: RetryPolicy,
}

impl WebhookDispatcher {
    /// Creates a new `WebhookDispatcher` with the given signing secret and a default 10-second HTTP timeout.
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self> {
        let secret_bytes = secret.as_ref().to_vec();
        if secret_bytes.is_empty() {
            return Err(HookError::EmptySecret);
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("webhook-shield-rs/", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            client,
            secret: secret_bytes,
            retry_policy: RetryPolicy::default(),
        })
    }

    /// Configures a custom `RetryPolicy`.
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Configures a custom `reqwest::Client` (e.g., for custom timeouts, TLS certs, or proxies).
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }

    /// Serializes and dispatches a structured `WebhookEvent<T>` to `endpoint_url`.
    pub async fn dispatch_event<T: Serialize>(
        &self,
        endpoint_url: &str,
        event: &WebhookEvent<T>,
    ) -> Result<DeliveryReceipt> {
        let payload_bytes = serde_json::to_vec(event)?;
        self.send_raw(
            endpoint_url,
            &payload_bytes,
            Some(&event.id),
            Some(event.timestamp),
        )
        .await
    }

    /// Serializes any `Serialize` value as JSON and dispatches it with an HMAC-SHA256 signature.
    pub async fn send_json<T: Serialize>(
        &self,
        endpoint_url: &str,
        payload: &T,
    ) -> Result<DeliveryReceipt> {
        let payload_bytes = serde_json::to_vec(payload)?;
        self.send_raw(endpoint_url, &payload_bytes, None, None).await
    }

    /// Sends raw payload bytes with an HMAC-SHA256 signature and automatic retry handling.
    pub async fn send_raw(
        &self,
        endpoint_url: &str,
        payload_bytes: &[u8],
        custom_id: Option<&str>,
        custom_timestamp: Option<u64>,
    ) -> Result<DeliveryReceipt> {
        let start = Instant::now();
        let webhook_id = custom_id
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("wh_{}", Uuid::new_v4().simple()));

        let max_attempts = self.retry_policy.max_retries + 1;
        let mut last_error_msg = String::new();

        for attempt in 1..=max_attempts {
            let timestamp = custom_timestamp.unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

            let signature_header = sign_payload(&self.secret, timestamp, payload_bytes)?;

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            if let Ok(val) = HeaderValue::from_str(&webhook_id) {
                headers.insert(HEADER_WEBHOOK_ID, val);
            }
            if let Ok(val) = HeaderValue::from_str(&timestamp.to_string()) {
                headers.insert(HEADER_WEBHOOK_TIMESTAMP, val);
            }
            if let Ok(val) = HeaderValue::from_str(&signature_header) {
                headers.insert(HEADER_WEBHOOK_SIGNATURE, val);
            }

            let response_result = self
                .client
                .post(endpoint_url)
                .headers(headers)
                .body(payload_bytes.to_vec())
                .send()
                .await;

            match response_result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(DeliveryReceipt {
                            webhook_id,
                            status_code: status.as_u16(),
                            attempts: attempt,
                            elapsed: start.elapsed(),
                        });
                    }

                    // Respect the Retry-After header if present (in seconds)
                    let retry_after = parse_retry_after(resp.headers(), self.retry_policy.max_backoff);
                    let status_code = status.as_u16();
                    let body_text = resp.text().await.unwrap_or_default();

                    // Only retry on 408 Request Timeout, 429 Too Many Requests, or 5xx Server Errors
                    let is_retryable = status_code == 408
                        || status_code == 429
                        || (500..=599).contains(&status_code);

                    if !is_retryable {
                        return Err(HookError::PermanentHttpFailure {
                            status: status_code,
                            body: body_text,
                        });
                    }

                    last_error_msg = format!("HTTP {status_code}: {body_text}");

                    if attempt < max_attempts {
                        let delay = retry_after
                            .unwrap_or_else(|| self.retry_policy.compute_delay(attempt - 1));
                        tokio::time::sleep(delay).await;
                    }
                }
                Err(network_err) => {
                    last_error_msg = network_err.to_string();
                    if attempt < max_attempts {
                        let delay = self.retry_policy.compute_delay(attempt - 1);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(HookError::DeliveryExhausted {
            attempts: max_attempts,
            last_error: last_error_msg,
        })
    }
}

/// Parses the `Retry-After` HTTP header (in seconds) and caps it at `max_backoff`.
fn parse_retry_after(headers: &HeaderMap, max_backoff: Duration) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?;
    let secs = raw.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(secs).min(max_backoff))
}
