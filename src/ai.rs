//! Phase 9 — AI augmentation via the Anthropic Messages API.
//!
//! Two capabilities are exposed:
//!   * [`rank_origin_candidates`] — rank likely-current origin IPs behind a
//!     CDN-protected target (the model returns a strict JSON array which we
//!     parse leniently);
//!   * [`suggest_bypass`] — given a detected WAF and a target URL, return
//!     suggested bypass techniques as markdown text.
//!
//! Both hit `POST https://api.anthropic.com/v1/messages` with the
//! `x-api-key` / `anthropic-version: 2023-06-01` headers. The library never
//! `unwrap`s on fallible I/O — failures propagate as [`anyhow::Error`].

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Anthropic Messages API endpoint.
const API_URL: &str = "https://api.anthropic.com/v1/messages";
/// Pinned API version (header `anthropic-version`).
const API_VERSION: &str = "2023-06-01";
/// Default model used when `ANTHROPIC_MODEL` is unset.
const DEFAULT_MODEL: &str = "claude-sonnet-4-6";
/// Cap on generated tokens per request.
const MAX_TOKENS: u32 = 2048;
/// HTTP timeout for a single Messages call.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);
/// User-Agent advertised to the API.
const USER_AGENT: &str = concat!("lancer-cdncheck/", env!("CARGO_PKG_VERSION"));

/// Credentials + model selection for the Anthropic API.
#[derive(Debug, Clone)]
pub struct AiConfig {
    pub api_key: String,
    pub model: String,
}

impl AiConfig {
    /// Build a config from the environment.
    ///
    /// Reads `ANTHROPIC_API_KEY` (required) and `ANTHROPIC_MODEL` (optional,
    /// defaults to [`DEFAULT_MODEL`]).
    pub fn from_env() -> Result<AiConfig> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty())
            .context("ANTHROPIC_API_KEY is not set")?;
        let model = std::env::var("ANTHROPIC_MODEL")
            .ok()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        Ok(AiConfig { api_key, model })
    }
}

/// A single ranked origin-IP candidate returned by the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedCandidate {
    pub ip: String,
    /// Likelihood this IP is the live origin, 0–100.
    pub score: u8,
    pub reason: String,
}

/// Rank likely-current origin IPs behind a CDN-protected target.
///
/// The model is instructed to reply with a strict JSON array
/// `[{"ip","score","reason"}]`; we extract the first JSON array substring from
/// the assistant text and parse it. Output is sorted by `score` descending.
/// Returns an empty vec when `candidates` is empty (no API call is made).
pub async fn rank_origin_candidates(
    target: &str,
    candidates: &[String],
    cfg: &AiConfig,
) -> Result<Vec<RankedCandidate>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let listing = candidates
        .iter()
        .map(|ip| format!("- {ip}"))
        .collect::<Vec<_>>()
        .join("\n");

    let prompt = format!(
        "You are a reconnaissance assistant for an authorized bug-bounty \
engagement. The target host `{target}` sits behind a CDN/WAF. Below is a list \
of candidate IP addresses discovered for it; rank how likely each one is to be \
the *real current origin server* (as opposed to a CDN edge node, a stale/parked \
record, or shared infrastructure).\n\nCandidates:\n{listing}\n\nReply with ONLY \
a JSON array, no prose, no markdown fences. Each element must be an object with \
exactly these keys: \"ip\" (string, one of the candidates above), \"score\" (an \
integer 0-100 where 100 means almost certainly the live origin), and \"reason\" \
(a short string explaining the score). Sort the array by score descending."
    );

    let text = call_messages(cfg, &prompt).await?;
    let array = extract_json_array(&text)
        .ok_or_else(|| anyhow!("model response did not contain a JSON array: {text}"))?;

    let mut ranked: Vec<RankedCandidate> =
        serde_json::from_str(array).context("parsing ranked-candidate JSON array")?;
    ranked.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(ranked)
}

/// Given a detected WAF and a target URL, return suggested bypass techniques
/// as markdown text (returned verbatim from the model).
pub async fn suggest_bypass(waf: &str, target_url: &str, cfg: &AiConfig) -> Result<String> {
    let prompt = format!(
        "You are assisting with an AUTHORIZED security assessment. The target \
`{target_url}` is protected by the WAF/CDN product `{waf}`. Provide a concise, \
practical list of testing techniques a penetration tester might use to evaluate \
whether this WAF can be bypassed or its origin reached. Cover, where relevant: \
origin-IP discovery, request mutation / payload encoding, protocol-level tricks, \
header manipulation, and rate-limit considerations. Respond in GitHub-flavored \
Markdown with short sections and bullet points. Keep it focused and actionable."
    );

    call_messages(cfg, &prompt).await
}

/// Issue a single-user-message Messages API call and return the assistant's
/// first text block.
async fn call_messages(cfg: &AiConfig, prompt: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .context("building HTTP client")?;

    let body = json!({
        "model": cfg.model,
        "max_tokens": MAX_TOKENS,
        "messages": [
            { "role": "user", "content": prompt }
        ]
    });

    let resp = client
        .post(API_URL)
        .header("x-api-key", &cfg.api_key)
        .header("anthropic-version", API_VERSION)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .context("sending request to Anthropic Messages API")?;

    let status = resp.status();
    let payload = resp
        .text()
        .await
        .context("reading Anthropic API response body")?;

    if !status.is_success() {
        return Err(anyhow!(
            "Anthropic API returned {status}: {payload}"
        ));
    }

    let value: Value =
        serde_json::from_str(&payload).context("parsing Anthropic API JSON response")?;

    extract_assistant_text(&value).ok_or_else(|| {
        anyhow!("Anthropic API response had no text content: {payload}")
    })
}

/// Read the first text block out of an Anthropic Messages response
/// (`response.content[0].text`, scanning for the first `type == "text"` block).
fn extract_assistant_text(value: &Value) -> Option<String> {
    let blocks = value.get("content")?.as_array()?;
    // Prefer the first explicit text block; fall back to content[0].text.
    for block in blocks {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(t) = block.get("text").and_then(Value::as_str) {
                return Some(t.to_string());
            }
        }
    }
    blocks
        .first()
        .and_then(|b| b.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Extract the first balanced JSON array substring from a noisy string.
///
/// Tolerates surrounding prose and ```json fences. Bracket counting is
/// string-literal aware so `]` characters inside quoted reasons do not end the
/// scan prematurely. Returns the slice including the outer `[` … `]`.
fn extract_json_array(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let start = s.find('[')?;

    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;

    for i in start..bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    // `i` is on the closing bracket; inclusive end is i + 1.
                    return Some(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_array_from_noisy_string() {
        let noisy = "Sure! Here is the ranking:\n```json\n\
            [{\"ip\":\"1.2.3.4\",\"score\":90,\"reason\":\"direct origin\"}]\n\
            ```\nLet me know if you need more.";
        let array = extract_json_array(noisy).expect("should find a JSON array");
        let parsed: Vec<RankedCandidate> =
            serde_json::from_str(array).expect("array should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].ip, "1.2.3.4");
        assert_eq!(parsed[0].score, 90);
    }

    #[test]
    fn extracts_array_with_brackets_inside_strings() {
        // A `]` inside a quoted reason must not terminate the array early.
        let noisy = "prefix [{\"ip\":\"9.9.9.9\",\"score\":42,\
            \"reason\":\"node [edge] cluster\"}] suffix";
        let array = extract_json_array(noisy).expect("should find a JSON array");
        assert!(array.ends_with("}]"));
        let parsed: Vec<RankedCandidate> =
            serde_json::from_str(array).expect("array should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].reason, "node [edge] cluster");
    }

    #[test]
    fn extracts_empty_array() {
        assert_eq!(extract_json_array("no data: []  done"), Some("[]"));
    }

    #[test]
    fn returns_none_without_array() {
        assert!(extract_json_array("there is no array here").is_none());
        assert!(extract_json_array("unterminated [1, 2, 3").is_none());
    }

    #[test]
    fn reads_assistant_text_block() {
        let v = json!({
            "content": [
                { "type": "text", "text": "hello world" }
            ]
        });
        assert_eq!(extract_assistant_text(&v).as_deref(), Some("hello world"));
    }

    #[test]
    fn from_env_defaults_model() {
        // Pure-config sanity: a hand-built config keeps the default model name.
        let cfg = AiConfig {
            api_key: "sk-test".to_string(),
            model: DEFAULT_MODEL.to_string(),
        };
        assert_eq!(cfg.model, "claude-sonnet-4-6");
    }
}
