# Webhook Shield

**Send and receive HTTP webhooks in Rust without worrying about dropped deliveries, forged requests, or replay attacks.**

---

## What is Webhook Shield?

When two backend systems talk via webhooks, there are always two sides:
1. **The Sender (Provider)**: Your app needs to send an HTTP POST notification to another server (for example, notifying a merchant when an invoice is paid).
2. **The Receiver (Consumer)**: Your server exposes an HTTP endpoint that accepts incoming webhook POST requests and needs to make sure they are authentic.

**Webhook Shield** is a lightweight Rust library that handles both sides for you:
- **If you are sending webhooks**, Webhook Shield signs your JSON payload with HMAC-SHA256, attaches standard tracking headers, and automatically retries failed deliveries using exponential backoff and jitter.
- **If you are receiving webhooks**, Webhook Shield verifies the cryptographic signature in constant time, checks the timestamp so attackers cannot replay old requests, and deserializes the JSON body directly into your Rust struct.

---

## Why Use Webhook Shield?

Writing a basic HTTP POST with reqwest takes five lines of code, but making webhooks production-ready requires solving several hidden problems:

| Problem in Production | What Happens Without Webhook Shield | How Webhook Shield Solves It |
| :--- | :--- | :--- |
| **Receiver server is temporarily down or overloaded** | Your single HTTP POST fails and the event is lost forever. | Automatically retries on network timeouts, HTTP 408, 429, and 5xx errors using exponential backoff + random jitter. |
| **Receiver rate-limits your requests (HTTP 429)** | Fixed-interval retries hammer the server and get your IP blocked. | Reads the receiver's Retry-After HTTP header and waits the exact requested duration before retrying. |
| **Receiver returns a permanent error (HTTP 400 / 404)** | Naive retry loops waste time retrying requests that will never succeed. | Fails fast on 4xx client errors so you can log or alert immediately. |
| **Anyone can send fake POST requests to your webhook URL** | Attackers trigger fake orders or payment confirmations on your server. | Authenticates every request with HMAC-SHA256 in constant time (immune to timing attacks). |
| **An attacker intercepts a valid webhook and resends it later** | Your server processes the same event twice (Replay Attack). | Binds the signature to the timestamp and rejects webhooks older than 5 minutes (configurable). |
| **You need to rotate your signing secret** | Updating the secret immediately breaks webhooks that are currently in transit. | Supports verifying against both a new primary secret and an old fallback secret at the same time. |

---

## How It Works

```text
+----------- SENDER -----------+                  +---------- RECEIVER ----------+
|                              |   HTTP POST      |                              |
|  1. Serialize JSON event     | -------------->  |  1. Read raw body & header   |
|  2. Sign <timestamp>.<body>  |  X-Webhook-Id    |  2. Verify HMAC in const-time|
|  3. Retry on 5xx / 429 / net |  X-Webhook-Sig   |  3. Check timestamp window   |
|                              |                  |  4. Parse JSON into struct   |
+------------------------------+                  +------------------------------+
       (WebhookDispatcher)                               (WebhookVerifier)
```

---

## Installation

Add Webhook Shield to your Cargo.toml:

```toml
[dependencies]
webhook-shield = "0.1.0"
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.40", features = ["full"] }
```

---

## How to Use

You can use Webhook Shield as a **Sender**, a **Receiver**, or **both**.

### Use Case 1: You Want to SEND Webhooks

Use WebhookDispatcher when your service needs to send signed events to an external URL.

```rust
use serde::Serialize;
use webhook_shield::{WebhookDispatcher, WebhookEvent};

// 1. Define the data you want to send
#[derive(Serialize)]
struct InvoicePaid {
    invoice_id: String,
    amount_cents: u64,
}

#[tokio::main]
async fn main() -> webhook_shield::Result<()> {
    // 2. Initialize the dispatcher with your shared signing secret
    let dispatcher = WebhookDispatcher::new(b"whsec_my_signing_secret")?;

    // 3. Wrap your data in a WebhookEvent (automatically adds a unique ID and timestamp)
    let event = WebhookEvent::new(
        "invoice.paid",
        InvoicePaid {
            invoice_id: "INV-2026-001".to_string(),
            amount_cents: 25000,
        },
    );

    // 4. Send the webhook (automatically signs and retries if the server is busy)
    let receipt = dispatcher
        .dispatch_event("https://customer-app.com/webhooks", &event)
        .await?;

    println!(
        "Success! Webhook {} delivered with HTTP {} on attempt #{}",
        receipt.webhook_id, receipt.status_code, receipt.attempts
    );

    Ok(())
}
```

#### Customizing Retry Behavior

By default, Webhook Shield retries up to 3 times with exponential backoff and jitter. You can customize this with RetryPolicy:

```rust
use std::time::Duration;
use webhook_shield::{RetryPolicy, WebhookDispatcher};

let dispatcher = WebhookDispatcher::new(b"whsec_my_signing_secret")?
    .with_retry_policy(RetryPolicy {
        max_retries: 5,
        initial_backoff: Duration::from_millis(500),
        max_backoff: Duration::from_secs(30),
        backoff_multiplier: 2.0,
        use_jitter: true,
    });
```

---

### Use Case 2: You Want to RECEIVE and VERIFY Webhooks

When another service (or your own WebhookDispatcher) sends an HTTP POST to your server, read the raw request bytes and the X-Webhook-Signature header, then pass them to WebhookVerifier.

```rust
use serde::Deserialize;
use std::time::Duration;
use webhook_shield::{HookError, WebhookEvent, WebhookVerifier};

// 1. Define the struct matching the incoming JSON data
#[derive(Debug, Deserialize)]
struct InvoicePaid {
    invoice_id: String,
    amount_cents: u64,
}

fn on_webhook_received(raw_body: &[u8], signature_header: &str) {
    // 2. Create a verifier with your shared secret (rejects requests older than 5 minutes)
    let verifier = WebhookVerifier::new(b"whsec_my_signing_secret")
        .unwrap()
        .with_tolerance(Duration::from_secs(300));

    // 3. Verify the signature, check the timestamp, and parse JSON in one call
    match verifier.verify_and_parse::<WebhookEvent<InvoicePaid>>(raw_body, signature_header) {
        Ok(event) => {
            println!(
                "Authentic webhook received! Event: {}, Invoice: {}",
                event.event_type, event.data.invoice_id
            );
        }
        Err(HookError::InvalidSignature) => {
            eprintln!("Rejected: Signature does not match (possible forgery)");
        }
        Err(HookError::TimestampOutOfTolerance { drift_secs, .. }) => {
            eprintln!("Rejected: Webhook is too old ({drift_secs}s drift, possible replay attack)");
        }
        Err(other_err) => {
            eprintln!("Rejected: {other_err}");
        }
    }
}
```

---

### Use Case 3: Rotating Secrets Without Downtime

When you need to replace an old secret key in production, add the old secret as a fallback. Webhook Shield will accept webhooks signed with either the new secret or the old secret until all senders have updated their configuration:

```rust
use webhook_shield::WebhookVerifier;

let verifier = WebhookVerifier::new(b"whsec_new_2026_secret")?
    .with_fallback_secret(b"whsec_old_2025_secret")?;

// Valid if signed by EITHER the new secret OR the old secret
verifier.verify(raw_body, signature_header)?;
```

---

## Try It Yourself in 10 Seconds

Clone the repository and run the included end-to-end simulation. It starts a local background HTTP server, dispatches a signed webhook event, and verifies it on the receiver side:

```bash
cargo run --example end_to_end
```

Expected output:

```text
[Dispatcher] Sending webhook to http://127.0.0.1:57458/webhook...
[Server] Received Webhook ID : evt_8ede26934eec491f9c2e4687ac7297d5
[Server] Signature Header    : t=1793242607,v1=aff281d11b780654935180ccb9b132644ac0436b1a0426d19178eccef1b501e4
[Server] Verification Succeeded! Event 'order.created' for Order ORD-2026-881 (Total: 125000 cents)
[Dispatcher] Delivery succeeded! Status: HTTP 202, Attempts: 1, Elapsed: 781.542µs
```

To run all unit, integration, and documentation tests:

```bash
cargo test
```

---

## License

Licensed under either of MIT or Apache-2.0 at your option.
