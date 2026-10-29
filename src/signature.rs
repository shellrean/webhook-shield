use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{HookError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Representation of a parsed signature header (`t=<timestamp>,v1=<signature>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignature {
    /// Unix timestamp (in seconds) embedded in the signature header.
    pub timestamp: u64,
    /// Candidate `v1` signatures (supports multiple signatures during key rotation).
    pub signatures: Vec<Vec<u8>>,
}

/// Generates a signature header string formatted as `t=<timestamp>,v1=<hex_hmac>`.
///
/// The canonical signed message format is `<timestamp>.<payload_bytes>`, cryptographically
/// binding the payload to its creation timestamp.
pub fn sign_payload(secret: &[u8], timestamp: u64, payload: &[u8]) -> Result<String> {
    let raw_mac = compute_mac(secret, timestamp, payload)?;
    let hex_sig = hex::encode(raw_mac);
    Ok(format!("t={timestamp},v1={hex_sig}"))
}

/// Computes the raw HMAC-SHA256 bytes over `<timestamp>.<payload>`.
pub fn compute_mac(secret: &[u8], timestamp: u64, payload: &[u8]) -> Result<Vec<u8>> {
    if secret.is_empty() {
        return Err(HookError::EmptySecret);
    }

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| HookError::EmptySecret)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verifies whether `candidate_signature` matches the HMAC-SHA256 of `<timestamp>.<payload>`
/// using a constant-time comparison to prevent timing side-channel attacks.
pub fn verify_mac_constant_time(
    secret: &[u8],
    timestamp: u64,
    payload: &[u8],
    candidate_signature: &[u8],
) -> Result<bool> {
    if secret.is_empty() {
        return Err(HookError::EmptySecret);
    }

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| HookError::EmptySecret)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);

    Ok(mac.verify_slice(candidate_signature).is_ok())
}

/// Parses a signature header formatted as `t=1700000000,v1=abcdef...`
/// (supports multiple `v1=` tags in a single header for key rotation).
pub fn parse_signature_header(header: &str) -> Result<ParsedSignature> {
    let mut timestamp: Option<u64> = None;
    let mut signatures = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let Some((key, value)) = part.split_once('=') else {
            return Err(HookError::MalformedSignatureHeader(
                "header segment is missing '=' delimiter".to_string(),
            ));
        };

        match key.trim() {
            "t" => {
                let parsed_ts = value.trim().parse::<u64>().map_err(|_| {
                    HookError::MalformedSignatureHeader(format!(
                        "invalid timestamp value: '{}'",
                        value.trim()
                    ))
                })?;
                timestamp = Some(parsed_ts);
            }
            "v1" => {
                let decoded = hex::decode(value.trim())?;
                signatures.push(decoded);
            }
            _ => {
                // Ignore unknown scheme versions (e.g., v0) for forward compatibility
            }
        }
    }

    let timestamp = timestamp.ok_or_else(|| {
        HookError::MalformedSignatureHeader("missing 't=' timestamp component".to_string())
    })?;

    if signatures.is_empty() {
        return Err(HookError::MalformedSignatureHeader(
            "missing 'v1=' signature component".to_string(),
        ));
    }

    Ok(ParsedSignature {
        timestamp,
        signatures,
    })
}
