//! Phase 6 — WAFW00F-style HTTP response-header fingerprinting.
//!
//! This module ports a representative subset of the venerable
//! [`wafw00f`](https://github.com/EnableSecurity/wafw00f) signature set to Rust.
//! It works in two layers:
//!
//! * [`fingerprint`] is **pure**: hand it the status code, a list of
//!   `(header-name, header-value)` pairs and the raw `Set-Cookie` strings, and
//!   it returns every WAF/CDN [`Detection`] it can infer from regexes — no
//!   network, fully unit-testable.
//! * [`probe`] performs the live work: a `HEAD /` request followed by a
//!   404-bait `GET` to a deliberately odd path (some WAFs only reveal
//!   themselves on a "suspicious" request), collects the headers, runs
//!   [`fingerprint`], and *additionally* merges in
//!   [`crate::bot_protection::fingerprint`] so a single probe surfaces the full
//!   protection stack (CDN + WAF + bot-management).
//!
//! Header names are normalised to lowercase before matching; signature regexes
//! are compiled lazily and matched case-insensitively.

use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::detection::{Detection, DetectionCategory, SignalType};

/// User-Agent presented by the probe. Mimics a current desktop Chrome so that
/// servers (and the WAFs in front of them) behave the way they would for a real
/// browser rather than serving a stripped bot response.
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// A deliberately odd, *static* path used for the second (404-bait) probe.
/// WAFW00F triggers some signatures only on a request that looks abnormal; we
/// keep it fixed (no randomness — RNG crates are unavailable here) so the probe
/// is reproducible.
const BAIT_PATH: &str = "/cdncheck-probe-404?x=1";

/// The structured outcome of [`probe`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct HttpProbeResult {
    /// The effective URL that was probed (scheme + host).
    pub url: String,
    /// HTTP status code from the primary request.
    pub status: u16,
    /// Convenience copy of the `Server` header, if any.
    pub server: Option<String>,
    /// All response headers, names lowercased, values as received.
    pub headers: Vec<(String, String)>,
    /// Raw `Set-Cookie` header values collected across both requests.
    pub set_cookies: Vec<String>,
    /// Every WAF/CDN/bot-protection detection inferred from the response.
    pub detections: Vec<Detection>,
}

// ── signature table ────────────────────────────────────────────────────────

/// Which header a signature is matched against.
#[derive(Clone, Copy)]
enum Field {
    /// The `Server` response header value.
    Server,
    /// The `Via` response header value.
    Via,
    /// The `X-Powered-By` response header value.
    PoweredBy,
    /// The `X-CDN` response header value.
    XCdn,
    /// Any header *name* exists (value irrelevant) — e.g. `cf-ray`.
    HeaderName,
    /// Any header *value*, scanned across every header.
    AnyHeaderValue,
    /// A `Set-Cookie` cookie *name* (substring before `=`).
    CookieName,
}

/// One WAFW00F-derived fingerprint.
struct Fingerprint {
    provider: &'static str,
    category: DetectionCategory,
    field: Field,
    pattern: &'static str,
}

/// Convenience for the common case: match a header field.
const fn hdr(
    provider: &'static str,
    category: DetectionCategory,
    field: Field,
    pattern: &'static str,
) -> Fingerprint {
    Fingerprint {
        provider,
        category,
        field,
        pattern,
    }
}

use DetectionCategory::{Cdn, Waf};

/// The compiled signature table. Roughly 50 fingerprints spanning the major
/// commercial and open-source WAF/CDN vendors covered by WAFW00F.
static FINGERPRINTS: Lazy<Vec<(Fingerprint, Regex)>> = Lazy::new(|| {
    let raw: Vec<Fingerprint> = vec![
        // ── Cloudflare ────────────────────────────────────────────────────
        hdr("Cloudflare", Cdn, Field::Server, r"cloudflare"),
        hdr("Cloudflare", Cdn, Field::HeaderName, r"^cf-ray$"),
        hdr("Cloudflare", Cdn, Field::HeaderName, r"^cf-cache-status$"),
        hdr("Cloudflare", Cdn, Field::CookieName, r"^__cfduid$"),
        // ── AWS / Amazon ──────────────────────────────────────────────────
        hdr("AWS WAF", Waf, Field::HeaderName, r"^x-amzn-requestid$"),
        hdr("AWS CloudFront", Cdn, Field::HeaderName, r"^x-amz-cf-id$"),
        hdr("AWS CloudFront", Cdn, Field::HeaderName, r"^x-amz-cf-pop$"),
        hdr("AWS CloudFront", Cdn, Field::Via, r"cloudfront"),
        hdr("AWS CloudFront", Cdn, Field::Server, r"cloudfront"),
        hdr("AWS WAF", Waf, Field::CookieName, r"^awsalb"),
        hdr("AWS WAF", Waf, Field::CookieName, r"^aws-waf-token$"),
        // ── Akamai ────────────────────────────────────────────────────────
        hdr("Akamai", Cdn, Field::Server, r"akamaighost"),
        hdr("Akamai", Cdn, Field::HeaderName, r"^x-akamai-"),
        hdr("Akamai", Cdn, Field::HeaderName, r"^akamai-"),
        hdr("Akamai", Cdn, Field::Via, r"akamai"),
        // ── Imperva / Incapsula ───────────────────────────────────────────
        hdr("Imperva Incapsula", Waf, Field::HeaderName, r"^x-iinfo$"),
        hdr("Imperva Incapsula", Waf, Field::XCdn, r"incapsula"),
        hdr("Imperva Incapsula", Waf, Field::CookieName, r"^incap_ses"),
        hdr("Imperva Incapsula", Waf, Field::CookieName, r"^visid_incap"),
        hdr("Imperva SecureSphere", Waf, Field::AnyHeaderValue, r"securesphere"),
        // ── Sucuri ────────────────────────────────────────────────────────
        hdr("Sucuri CloudProxy", Waf, Field::Server, r"sucuri/cloudproxy"),
        hdr("Sucuri CloudProxy", Waf, Field::HeaderName, r"^x-sucuri-id$"),
        hdr("Sucuri CloudProxy", Waf, Field::HeaderName, r"^x-sucuri-cache$"),
        // ── F5 BIG-IP / ASM ───────────────────────────────────────────────
        hdr("F5 BIG-IP", Waf, Field::Server, r"big-?ip"),
        hdr("F5 BIG-IP", Waf, Field::Server, r"^big-?ip$|f5\b"),
        hdr("F5 BIG-IP ASM", Waf, Field::HeaderName, r"^x-wa-info$"),
        hdr("F5 BIG-IP", Waf, Field::HeaderName, r"^x-cnection$"),
        hdr("F5 BIG-IP", Waf, Field::CookieName, r"^ts[0-9a-f]{6,}"),
        hdr("F5 BIG-IP", Waf, Field::CookieName, r"^bigipserver"),
        // ── Fortinet FortiWeb ─────────────────────────────────────────────
        hdr("Fortinet FortiWeb", Waf, Field::Server, r"fortiweb"),
        hdr("Fortinet FortiWeb", Waf, Field::CookieName, r"^fortiwafsid$"),
        hdr("Fortinet FortiGate", Waf, Field::AnyHeaderValue, r"fortigate"),
        // ── Barracuda ─────────────────────────────────────────────────────
        hdr("Barracuda", Waf, Field::CookieName, r"^barra_counter_session$"),
        hdr("Barracuda", Waf, Field::CookieName, r"^barracuda_"),
        // ── ModSecurity / OWASP CRS / NAXSI ───────────────────────────────
        hdr("ModSecurity", Waf, Field::Server, r"mod_security|modsecurity"),
        hdr("ModSecurity", Waf, Field::AnyHeaderValue, r"mod_security|modsecurity"),
        hdr("NAXSI", Waf, Field::HeaderName, r"^x-data-origin$"),
        hdr("NAXSI", Waf, Field::AnyHeaderValue, r"naxsi"),
        // ── Wallarm ───────────────────────────────────────────────────────
        hdr("Wallarm", Waf, Field::Server, r"nginx-wallarm"),
        hdr("Wallarm", Waf, Field::AnyHeaderValue, r"wallarm"),
        // ── Citrix NetScaler ──────────────────────────────────────────────
        hdr("Citrix NetScaler", Waf, Field::CookieName, r"^ns_af"),
        hdr("Citrix NetScaler", Waf, Field::CookieName, r"^citrix_ns_id"),
        hdr("Citrix NetScaler", Waf, Field::HeaderName, r"^cneonction$"),
        hdr("Citrix NetScaler", Waf, Field::HeaderName, r"^nncoection$"),
        hdr("Citrix NetScaler", Waf, Field::Via, r"ns-cache"),
        // ── Fastly / Varnish ──────────────────────────────────────────────
        hdr("Fastly", Cdn, Field::HeaderName, r"^x-served-by$"),
        hdr("Fastly", Cdn, Field::HeaderName, r"^x-fastly-request-id$"),
        hdr("Fastly", Cdn, Field::HeaderName, r"^fastly-"),
        hdr("Fastly", Cdn, Field::Via, r"varnish"),
        hdr("Varnish", Cdn, Field::Via, r"\bvarnish\b"),
        hdr("Varnish", Cdn, Field::Server, r"varnish"),
        // ── Reblaze ───────────────────────────────────────────────────────
        hdr("Reblaze", Waf, Field::Server, r"reblaze"),
        hdr("Reblaze", Waf, Field::CookieName, r"^rbzid$"),
        hdr("Reblaze", Waf, Field::CookieName, r"^rbzsessionid$"),
        // ── Wordfence ─────────────────────────────────────────────────────
        hdr("Wordfence", Waf, Field::AnyHeaderValue, r"wordfence"),
        hdr("Wordfence", Waf, Field::CookieName, r"^wfvt_"),
        hdr("Wordfence", Waf, Field::CookieName, r"^wordfence_"),
        // ── Edgecast / Verizon ────────────────────────────────────────────
        hdr("Edgecast", Cdn, Field::Server, r"ecd|ecs\b"),
        hdr("Edgecast", Cdn, Field::AnyHeaderValue, r"edgecast"),
        // ── KeyCDN ────────────────────────────────────────────────────────
        hdr("KeyCDN", Cdn, Field::Server, r"keycdn"),
        hdr("KeyCDN", Cdn, Field::HeaderName, r"^x-edge-location$"),
        // ── Other notable CDNs / WAFs ─────────────────────────────────────
        hdr("StackPath", Cdn, Field::Server, r"stackpath"),
        hdr("Section.io", Cdn, Field::AnyHeaderValue, r"section\.io"),
        hdr("Microsoft Azure", Cdn, Field::Server, r"ecacc|azurefd|microsoft-azure"),
        hdr("Azure Front Door", Cdn, Field::HeaderName, r"^x-azure-ref$"),
        hdr("Google Cloud", Cdn, Field::Server, r"^gws$|^gfe\b|google frontend"),
        hdr("Google Cloud Armor", Waf, Field::AnyHeaderValue, r"cloud armor"),
        hdr("BunnyCDN", Cdn, Field::Server, r"bunnycdn"),
        hdr("CDN77", Cdn, Field::Server, r"cdn77"),
        hdr("Aliyun ESA / WAF", Waf, Field::Server, r"tengine"),
        hdr("DenyAll", Waf, Field::CookieName, r"^sessioncookie$"),
        hdr("DenyAll", Waf, Field::AnyHeaderValue, r"\bdenyall\b"),
        hdr("Yundun", Waf, Field::AnyHeaderValue, r"yundun"),
        hdr("Yunjiasu (Baidu)", Cdn, Field::Server, r"yunjiasu"),
        hdr("AnYu", Waf, Field::AnyHeaderValue, r"anyu"),
        hdr("Comodo cWatch", Waf, Field::Server, r"protected by comodo"),
        hdr("Qrator", Waf, Field::Server, r"qrator"),
        hdr("DDoS-Guard", Waf, Field::Server, r"ddos-guard"),
        hdr("West263 CDN", Cdn, Field::AnyHeaderValue, r"wt263cdn"),
        hdr("Airee CDN", Cdn, Field::Server, r"airee"),
        hdr("Approach", Waf, Field::AnyHeaderValue, r"approach\b"),
        // ── X-Powered-By disclosure used by some WAF stacks ───────────────
        hdr("Imperva Incapsula", Waf, Field::PoweredBy, r"incapsula"),
    ];

    raw.into_iter()
        .filter_map(|fp| {
            // Build a case-insensitive regex; skip any that fail to compile
            // (should never happen for these literals, but never panic).
            match Regex::new(&format!("(?i){}", fp.pattern)) {
                Ok(re) => Some((fp, re)),
                Err(_) => None,
            }
        })
        .collect()
});

// ── pure fingerprinting ─────────────────────────────────────────────────────

/// Extract the cookie *name* (the substring before the first `=`), trimmed and
/// lowercased, from a raw `Set-Cookie` value.
fn cookie_name(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or(raw)
        .split('=')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase()
}

/// Find the value of a specific (already-lowercased) header name.
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Pure WAF/CDN fingerprinting over already-collected response data.
///
/// `headers` must use lowercased names. `cookies` are raw `Set-Cookie` values.
/// Returns one [`Detection`] per matched provider, deduplicated by provider
/// (keeping the first/strongest match). The `status` is accepted for parity
/// with WAFW00F (which sometimes keys on status families) and to keep the
/// signature stable, though the current rule set is header/cookie driven.
pub fn fingerprint(
    status: u16,
    headers: &[(String, String)],
    cookies: &[String],
) -> Vec<Detection> {
    let _ = status; // reserved for status-family rules; keeps API stable.

    let cookie_names: Vec<String> = cookies.iter().map(|c| cookie_name(c)).collect();

    let mut detections: Vec<Detection> = Vec::new();

    for (fp, re) in FINGERPRINTS.iter() {
        let (matched, signal_type) = match fp.field {
            Field::Server => (
                header_value(headers, "server").is_some_and(|v| re.is_match(v)),
                SignalType::Header,
            ),
            Field::Via => (
                header_value(headers, "via").is_some_and(|v| re.is_match(v)),
                SignalType::Header,
            ),
            Field::PoweredBy => (
                header_value(headers, "x-powered-by").is_some_and(|v| re.is_match(v)),
                SignalType::Header,
            ),
            Field::XCdn => (
                header_value(headers, "x-cdn").is_some_and(|v| re.is_match(v)),
                SignalType::Header,
            ),
            Field::HeaderName => (
                headers.iter().any(|(k, _)| re.is_match(k)),
                SignalType::Header,
            ),
            Field::AnyHeaderValue => (
                headers.iter().any(|(_, v)| re.is_match(v)),
                SignalType::Header,
            ),
            Field::CookieName => (
                cookie_names.iter().any(|n| re.is_match(n)),
                SignalType::Cookie,
            ),
        };

        if matched && !detections.iter().any(|d| d.provider == fp.provider) {
            detections.push(Detection::single(fp.provider, fp.category, signal_type));
        }
    }

    detections
}

// ── live probe ──────────────────────────────────────────────────────────────

/// Collect a response's headers (lowercased) and `Set-Cookie` values into the
/// running result, and accumulate detections. `set_cookie` values are gathered
/// separately because they appear once per cookie.
fn ingest_response(resp: &reqwest::Response, headers_out: &mut Vec<(String, String)>, cookies_out: &mut Vec<String>) {
    for (name, value) in resp.headers().iter() {
        let key = name.as_str().to_ascii_lowercase();
        let val = value.to_str().unwrap_or("").to_string();
        if key == "set-cookie" {
            if !val.is_empty() && !cookies_out.contains(&val) {
                cookies_out.push(val.clone());
            }
        }
        let pair = (key, val);
        if !headers_out.contains(&pair) {
            headers_out.push(pair);
        }
    }
}

/// Build the candidate URLs to try for a given host. Honours an explicit scheme
/// if present, otherwise prefers `https` then falls back to `http`.
fn candidate_urls(host: &str) -> Vec<String> {
    let h = host.trim();
    if h.starts_with("http://") || h.starts_with("https://") {
        vec![h.trim_end_matches('/').to_string()]
    } else {
        let base = h.trim_end_matches('/');
        vec![format!("https://{base}"), format!("http://{base}")]
    }
}

/// Live-probe a host for WAF/CDN/bot-protection.
///
/// Performs a `HEAD /` request, then a 404-bait `GET` to [`BAIT_PATH`], on the
/// first reachable scheme (`https` preferred, `http` fallback when no scheme is
/// given). Headers and `Set-Cookie` values from *both* responses are merged,
/// fingerprinted via [`fingerprint`], and combined with
/// [`crate::bot_protection::fingerprint`]. Detections are deduplicated by
/// provider.
///
/// # Errors
/// Returns an error only if the HTTP client cannot be constructed or none of
/// the candidate URLs are reachable.
pub async fn probe(host: &str, timeout_secs: u64) -> anyhow::Result<HttpProbeResult> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut set_cookies: Vec<String> = Vec::new();
    let mut status: u16 = 0;
    let mut server: Option<String> = None;
    let mut effective_url: Option<String> = None;
    let mut last_err: Option<anyhow::Error> = None;

    'scheme: for base in candidate_urls(host) {
        // Primary: HEAD / — cheap, reveals the routing headers most WAFs add.
        match client.head(&base).send().await {
            Ok(resp) => {
                status = resp.status().as_u16();
                server = resp
                    .headers()
                    .get(reqwest::header::SERVER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                effective_url = Some(base.clone());
                ingest_response(&resp, &mut headers, &mut set_cookies);
            }
            Err(e) => {
                last_err = Some(e.into());
                continue 'scheme;
            }
        }

        // Secondary: 404-bait GET to an odd path. Some WAFs only reveal
        // themselves (or set their challenge cookies) on a suspicious request.
        let bait = format!("{base}{BAIT_PATH}");
        if let Ok(resp) = client.get(&bait).send().await {
            if server.is_none() {
                server = resp
                    .headers()
                    .get(reqwest::header::SERVER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
            }
            ingest_response(&resp, &mut headers, &mut set_cookies);
        }

        // First reachable scheme wins.
        break 'scheme;
    }

    let url = match effective_url {
        Some(u) => u,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                anyhow::anyhow!("no reachable URL for host {host:?}")
            }));
        }
    };

    // Layer 1: WAFW00F header/cookie fingerprints.
    let mut detections = fingerprint(status, &headers, &set_cookies);

    // Layer 2: bot-protection fingerprints (DataDome / Akamai BM / Kasada / …).
    for d in crate::bot_protection::fingerprint(&headers, &set_cookies) {
        if !detections.iter().any(|x| x.provider == d.provider) {
            detections.push(d);
        }
    }

    Ok(HttpProbeResult {
        url,
        status,
        server,
        headers,
        set_cookies,
        detections,
    })
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> (String, String) {
        (name.to_ascii_lowercase(), value.to_string())
    }

    #[test]
    fn cookie_name_strips_value_and_attrs() {
        assert_eq!(cookie_name("incap_ses_123=abc; path=/; HttpOnly"), "incap_ses_123");
        assert_eq!(cookie_name("__cfduid=xyz"), "__cfduid");
        assert_eq!(cookie_name("  AWSALB = v "), "awsalb");
    }

    #[test]
    fn detects_cloudflare_from_server_and_cf_ray() {
        let headers = vec![h("Server", "cloudflare"), h("CF-RAY", "abc123-IAD")];
        let dets = fingerprint(403, &headers, &[]);
        assert!(dets.iter().any(|d| d.provider == "Cloudflare"));
        // Provider is deduplicated even though two signatures matched.
        assert_eq!(
            dets.iter().filter(|d| d.provider == "Cloudflare").count(),
            1
        );
    }

    #[test]
    fn detects_incapsula_from_cookie() {
        let cookies = vec!["incap_ses_42_99=Zm9v; path=/".to_string()];
        let dets = fingerprint(200, &[], &cookies);
        let cf = dets
            .iter()
            .find(|d| d.provider == "Imperva Incapsula")
            .expect("incapsula detected");
        assert_eq!(cf.category, DetectionCategory::Waf);
        assert_eq!(cf.signals[0].signal_type, SignalType::Cookie);
    }

    #[test]
    fn detects_cloudfront_via_header() {
        let headers = vec![h("Via", "1.1 abc.cloudfront.net (CloudFront)")];
        let dets = fingerprint(200, &headers, &[]);
        assert!(dets.iter().any(|d| d.provider == "AWS CloudFront"));
    }

    #[test]
    fn no_match_yields_empty() {
        let headers = vec![h("Server", "nginx"), h("Content-Type", "text/html")];
        let dets = fingerprint(200, &headers, &[]);
        assert!(dets.is_empty());
    }

    #[test]
    fn signature_table_is_large() {
        // Guard against an accidental truncation of the ported signature set.
        assert!(FINGERPRINTS.len() >= 40, "expected 40+ fingerprints");
    }

    #[test]
    fn candidate_urls_respects_scheme() {
        assert_eq!(candidate_urls("https://example.com/"), vec!["https://example.com"]);
        assert_eq!(
            candidate_urls("example.com"),
            vec!["https://example.com", "http://example.com"]
        );
    }
}
