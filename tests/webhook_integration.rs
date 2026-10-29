use webhook_shield::{
    HEADER_WEBHOOK_SIGNATURE, HookError, RetryPolicy, WebhookDispatcher, WebhookEvent,
    WebhookVerifier, sign_payload,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PaymentPayload {
    order_id: String,
    amount_cents: u64,
    status: String,
}

#[test]
fn test_sign_and_verify_success() {
    let secret = b"whsec_test_secret_12345";
    let payload = br#"{"order_id":"ORD-001","amount_cents":250000}"#;
    let ts = 1_700_000_000;

    let sig_header = sign_payload(secret, ts, payload).expect("should sign payload");
    let verifier = WebhookVerifier::new(secret).expect("valid verifier");

    // Verify 60 seconds after signing (within the default 300-second tolerance window)
    let verified_ts = verifier
        .verify_at(payload, &sig_header, ts + 60)
        .expect("signature should be valid");
    assert_eq!(verified_ts, ts);
}

#[test]
fn test_reject_tampered_payload_or_wrong_secret() {
    let secret = b"whsec_correct_secret";
    let payload = br#"{"order_id":"ORD-001","amount_cents":250000}"#;
    let ts = 1_700_000_000;

    let sig_header = sign_payload(secret, ts, payload).unwrap();
    let verifier = WebhookVerifier::new(secret).unwrap();

    // Payload modified by a single digit
    let tampered = br#"{"order_id":"ORD-001","amount_cents":950000}"#;
    let err = verifier
        .verify_at(tampered, &sig_header, ts + 10)
        .unwrap_err();
    assert!(matches!(err, HookError::InvalidSignature));

    // Wrong signing secret
    let wrong_verifier = WebhookVerifier::new(b"whsec_wrong_secret").unwrap();
    let err2 = wrong_verifier
        .verify_at(payload, &sig_header, ts + 10)
        .unwrap_err();
    assert!(matches!(err2, HookError::InvalidSignature));
}

#[test]
fn test_replay_attack_protection() {
    let secret = b"whsec_replay_test";
    let payload = br#"{"event":"user.login"}"#;
    let ts = 1_700_000_000;

    let sig_header = sign_payload(secret, ts, payload).unwrap();
    let verifier = WebhookVerifier::new(secret)
        .unwrap()
        .with_tolerance(Duration::from_secs(300));

    // 1. Expired timestamp (600s later > 300s tolerance)
    let err = verifier
        .verify_at(payload, &sig_header, ts + 600)
        .unwrap_err();
    assert!(matches!(
        err,
        HookError::TimestampOutOfTolerance {
            drift_secs: 600,
            tolerance_secs: 300
        }
    ));

    // 2. Far-future timestamp (400s ahead > 300s tolerance)
    let err_future = verifier
        .verify_at(payload, &sig_header, ts - 400)
        .unwrap_err();
    assert!(matches!(
        err_future,
        HookError::TimestampOutOfTolerance {
            drift_secs: 400,
            tolerance_secs: 300
        }
    ));
}

#[test]
fn test_secret_rotation_fallback() {
    let old_secret = b"whsec_old_2025";
    let new_secret = b"whsec_new_2026";
    let payload = br#"{"status":"rotated"}"#;
    let ts = 1_700_000_000;

    // Sender still signing with old_secret
    let sig_old = sign_payload(old_secret, ts, payload).unwrap();
    // Sender signing with new_secret
    let sig_new = sign_payload(new_secret, ts, payload).unwrap();

    // Verifier prioritizes new_secret while accepting old_secret as fallback
    let verifier = WebhookVerifier::new(new_secret)
        .unwrap()
        .with_fallback_secret(old_secret)
        .unwrap();

    assert!(verifier.verify_at(payload, &sig_old, ts + 5).is_ok());
    assert!(verifier.verify_at(payload, &sig_new, ts + 5).is_ok());
}

#[tokio::test]
async fn test_dispatcher_retries_503_then_succeeds_and_verifies() {
    let secret = b"whsec_end_to_end_secret";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_clone = Arc::clone(&hit_count);

    // Spawn a lightweight mock HTTP server that returns HTTP 503 twice and succeeds (HTTP 200) on attempt 3
    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let current_hit = hit_count_clone.fetch_add(1, Ordering::SeqCst) + 1;

            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let raw_req = String::from_utf8_lossy(&buf[..n]).to_string();

            if current_hit < 3 {
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\n\r\noverloaded!";
                let _ = socket.write_all(response.as_bytes()).await;
            } else {
                // Extract the signature header and body from the HTTP request to verify on the server
                let (headers_part, body_part) = raw_req.split_once("\r\n\r\n").unwrap();
                let sig_header = headers_part
                    .lines()
                    .find_map(|line| {
                        let (k, v) = line.split_once(':')?;
                        if k.trim()
                            .eq_ignore_ascii_case(HEADER_WEBHOOK_SIGNATURE)
                        {
                            Some(v.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .expect("X-Webhook-Signature header must be present");

                let verifier = WebhookVerifier::new(secret).unwrap();
                let parsed: WebhookEvent<PaymentPayload> = verifier
                    .verify_and_parse(body_part.as_bytes(), &sig_header)
                    .expect("server must successfully verify and parse the webhook");

                assert_eq!(parsed.event_type, "payment.settled");
                assert_eq!(parsed.data.order_id, "INV-2026-99");

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = socket.write_all(response.as_bytes()).await;
                break;
            }
        }
    });

    let policy = RetryPolicy {
        max_retries: 3,
        initial_backoff: Duration::from_millis(15),
        max_backoff: Duration::from_millis(100),
        backoff_multiplier: 2.0,
        use_jitter: false,
    };

    let dispatcher = WebhookDispatcher::new(secret)
        .unwrap()
        .with_retry_policy(policy);

    let event = WebhookEvent::new(
        "payment.settled",
        PaymentPayload {
            order_id: "INV-2026-99".to_string(),
            amount_cents: 500_000,
            status: "PAID".to_string(),
        },
    );

    let url = format!("http://{addr}/webhooks");
    let receipt = dispatcher
        .dispatch_event(&url, &event)
        .await
        .expect("delivery should succeed on the 3rd attempt");

    assert_eq!(receipt.status_code, 200);
    assert_eq!(receipt.attempts, 3);
    assert_eq!(hit_count.load(Ordering::SeqCst), 3);

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_dispatcher_fails_fast_on_400_bad_request() {
    let secret = b"whsec_fail_fast";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_clone = Arc::clone(&hit_count);

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            hit_count_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\ninvalid payload";
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let dispatcher = WebhookDispatcher::new(secret).unwrap();
    let url = format!("http://{addr}/webhooks");

    let err = dispatcher
        .send_json(&url, &serde_json::json!({"hello": "world"}))
        .await
        .unwrap_err();

    // Must fail immediately with PermanentHttpFailure without retrying
    assert!(matches!(
        err,
        HookError::PermanentHttpFailure { status: 400, .. }
    ));
    assert_eq!(hit_count.load(Ordering::SeqCst), 1);
}
