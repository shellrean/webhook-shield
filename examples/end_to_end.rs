use webhook_shield::{
    HEADER_WEBHOOK_ID, HEADER_WEBHOOK_SIGNATURE, RetryPolicy, WebhookDispatcher, WebhookEvent,
    WebhookVerifier,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Serialize, Deserialize)]
struct OrderCreated {
    order_id: String,
    customer: String,
    total_cents: u64,
}

#[tokio::main]
async fn main() -> webhook_shield::Result<()> {
    let shared_secret = b"whsec_demo_secret_key_2026";

    // 1. Spawn a simulated receiving HTTP server in the background
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.unwrap();
        let raw_http = String::from_utf8_lossy(&buf[..n]);

        let (headers, body) = raw_http.split_once("\r\n\r\n").unwrap();
        let mut sig_header = String::new();
        let mut webhook_id = String::new();

        for line in headers.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case(HEADER_WEBHOOK_SIGNATURE) {
                    sig_header = v.trim().to_string();
                } else if k.trim().eq_ignore_ascii_case(HEADER_WEBHOOK_ID) {
                    webhook_id = v.trim().to_string();
                }
            }
        }

        println!("[Server] Received Webhook ID : {webhook_id}");
        println!("[Server] Signature Header    : {sig_header}");

        // Verify signature and deserialize payload using WebhookVerifier
        let verifier = WebhookVerifier::new(shared_secret).unwrap();
        let event: WebhookEvent<OrderCreated> = verifier
            .verify_and_parse(body.as_bytes(), &sig_header)
            .expect("Invalid webhook signature!");

        println!(
            "[Server] Verification Succeeded! Event '{}' for Order {} (Total: {} cents)",
            event.event_type, event.data.order_id, event.data.total_cents
        );

        let response = "HTTP/1.1 202 Accepted\r\nContent-Length: 8\r\n\r\nAccepted";
        socket.write_all(response.as_bytes()).await.unwrap();
    });

    // 2. Dispatch the event using WebhookDispatcher
    let dispatcher = WebhookDispatcher::new(shared_secret)?.with_retry_policy(RetryPolicy {
        max_retries: 2,
        initial_backoff: Duration::from_millis(100),
        ..Default::default()
    });

    let event = WebhookEvent::new(
        "order.created",
        OrderCreated {
            order_id: "ORD-2026-881".into(),
            customer: "Alice Smith".into(),
            total_cents: 125_000,
        },
    );

    let endpoint = format!("http://{addr}/webhook");
    println!("[Dispatcher] Sending webhook to {endpoint}...");
    let receipt = dispatcher.dispatch_event(&endpoint, &event).await?;

    println!(
        "[Dispatcher] Delivery succeeded! Status: HTTP {}, Attempts: {}, Elapsed: {:?}",
        receipt.status_code, receipt.attempts, receipt.elapsed
    );

    server_task.await.unwrap();
    Ok(())
}
