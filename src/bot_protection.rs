//! Phase 7 — bot-protection fingerprints.
//!
//! Pure, network-free detection of anti-bot / bot-management layers from an
//! HTTP response's headers and `Set-Cookie` values. These layers ride on top of
//! a CDN/WAF (e.g. a Cloudflare-fronted site running DataDome) so they get their
//! own [`DetectionCategory::BotProtection`] category and are meant to be
//! `Detection::merge`d into any CIDR/CNAME hit by the caller.
//!
//! Everything here is a substring / regex match against the cookie *name* (the
//! part before `=`) or a header name/value, all case-insensitively. Each matched
//! vendor yields a single [`Detection`] via [`Detection::single`]; results are
//! deduplicated by provider so a vendor that trips several cookies is reported
//! once.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::detection::{Detection, DetectionCategory, SignalType};

/// F5 Shape / Distributed Cloud "TS..." load-balancer/telemetry cookies, e.g.
/// `TS01abc123`, `TSPD_101_DID`. Matches a `ts` prefix followed by 6+ hex chars.
static F5_TS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^ts[0-9a-f]{6,}").expect("F5 TS cookie regex is valid")
});

/// Extract the lowercased cookie name (the token before the first `=`) from a
/// raw `Set-Cookie` value or a bare `name=value` pair. Leading whitespace and a
/// stray leading `;` are tolerated.
fn cookie_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches(';').trim_start();
    let name = trimmed.split('=').next().unwrap_or("").trim();
    name.to_lowercase()
}

/// True if any provided cookie's *name* equals or contains `needle`
/// (case-insensitive). `needle` must already be lowercase.
fn cookie_name_contains(names: &[String], needle: &str) -> bool {
    names.iter().any(|n| n.contains(needle))
}

/// True if any provided cookie's *name* exactly equals `needle`
/// (case-insensitive). `needle` must already be lowercase.
fn cookie_name_eq(names: &[String], needle: &str) -> bool {
    names.iter().any(|n| n == needle)
}

/// Detect bot-protection layers from response headers and `Set-Cookie` values.
///
/// `headers` is a list of `(name, value)` pairs (order/duplicates irrelevant);
/// `cookies` is a list of raw `Set-Cookie` strings or bare `name=value` pairs.
/// Returns one [`Detection`] per detected vendor, deduplicated by provider, each
/// in the [`DetectionCategory::BotProtection`] category. The function performs
/// no I/O and never panics.
pub fn fingerprint(headers: &[(String, String)], cookies: &[String]) -> Vec<Detection> {
    // Pre-lowercase everything once.
    let header_names: Vec<String> = headers.iter().map(|(k, _)| k.to_lowercase()).collect();
    let header_lines: Vec<String> = headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.to_lowercase(), v.to_lowercase()))
        .collect();
    let cookie_names: Vec<String> = cookies.iter().map(|c| cookie_name(c)).collect();

    let header_name_has =
        |needle: &str| header_names.iter().any(|h| h.contains(needle));
    let header_line_has =
        |needle: &str| header_lines.iter().any(|h| h.contains(needle));

    // (provider, matched-via-header?) — we record the strongest signal kind so a
    // header-only hit is reported as a Header signal and a cookie hit as Cookie.
    let mut detections: Vec<Detection> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    let mut push = |provider: &str, signal: SignalType| {
        if seen.iter().any(|p| p == provider) {
            return;
        }
        seen.push(provider.to_string());
        detections.push(Detection::single(
            provider,
            DetectionCategory::BotProtection,
            signal,
        ));
    };

    // ── DataDome ───────────────────────────────────────────────────────────
    if cookie_name_eq(&cookie_names, "datadome") {
        push("DataDome", SignalType::Cookie);
    } else if header_name_has("x-datadome") || header_name_has("x-datadome-cid") {
        push("DataDome", SignalType::Header);
    }

    // ── PerimeterX / HUMAN ───────────────────────────────────────────────────
    if cookie_name_eq(&cookie_names, "_px3")
        || cookie_name_eq(&cookie_names, "_pxhd")
        || cookie_name_eq(&cookie_names, "_pxvid")
        || cookie_names.iter().any(|n| n.starts_with("_px"))
    {
        push("PerimeterX", SignalType::Cookie);
    } else if header_line_has("pxcdn") || header_name_has("x-px") {
        push("PerimeterX", SignalType::Header);
    }

    // ── Kasada ────────────────────────────────────────────────────────────────
    if header_names.iter().any(|h| h.starts_with("x-kpsdk-")) {
        push("Kasada", SignalType::Header);
    } else if cookie_names.iter().any(|n| n.starts_with("kpsdk-")) {
        push("Kasada", SignalType::Cookie);
    }

    // ── Akamai Bot Manager ─────────────────────────────────────────────────────
    if cookie_name_eq(&cookie_names, "_abck")
        || cookie_name_eq(&cookie_names, "ak_bmsc")
        || cookie_name_eq(&cookie_names, "bm_sz")
        || cookie_name_eq(&cookie_names, "bm_mi")
        || cookie_name_eq(&cookie_names, "bm_sv")
    {
        push("Akamai Bot Manager", SignalType::Cookie);
    }

    // ── Cloudflare Bot Management ───────────────────────────────────────────────
    if cookie_name_eq(&cookie_names, "__cf_bm") || cookie_name_eq(&cookie_names, "__cflb") {
        push("Cloudflare Bot Management", SignalType::Cookie);
    }

    // ── F5 Shape / Distributed Cloud ────────────────────────────────────────────
    if cookie_names.iter().any(|n| F5_TS_RE.is_match(n))
        || cookie_names.iter().any(|n| n.starts_with("f5_"))
        || cookie_name_contains(&cookie_names, "f5avr")
    {
        push("F5 Shape", SignalType::Cookie);
    }

    // ── Imperva Advanced Bot Protection ─────────────────────────────────────────
    if cookie_name_eq(&cookie_names, "reese84") {
        push("Imperva", SignalType::Cookie);
    }

    // ── hCaptcha (header / script hints, header-only) ───────────────────────────
    if header_line_has("hcaptcha") {
        push("hCaptcha", SignalType::Header);
    }

    // ── reCAPTCHA (header / script hints, header-only) ──────────────────────────
    if header_line_has("recaptcha") || header_line_has("google.com/recaptcha") {
        push("reCAPTCHA", SignalType::Header);
    }

    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookies(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn headers(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(k, val)| (k.to_string(), val.to_string())).collect()
    }

    #[test]
    fn cookie_name_strips_attributes() {
        assert_eq!(cookie_name("datadome=abc; Path=/; HttpOnly"), "datadome");
        assert_eq!(cookie_name("  _abck=xyz"), "_abck");
        assert_eq!(cookie_name("__cf_bm"), "__cf_bm");
    }

    #[test]
    fn detects_datadome_cookie() {
        let dets = fingerprint(&[], &cookies(&["datadome=Abc123; Path=/"]));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "DataDome");
        assert_eq!(dets[0].category, DetectionCategory::BotProtection);
        assert_eq!(dets[0].signals[0].signal_type, SignalType::Cookie);
    }

    #[test]
    fn detects_datadome_header_only() {
        let dets = fingerprint(&headers(&[("X-DataDome", "protected")]), &[]);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "DataDome");
        assert_eq!(dets[0].signals[0].signal_type, SignalType::Header);
    }

    #[test]
    fn detects_akamai_bot_manager() {
        let dets = fingerprint(&[], &cookies(&["_abck=val", "bm_sz=val", "ak_bmsc=val"]));
        // All three are Akamai → deduped to a single detection.
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "Akamai Bot Manager");
    }

    #[test]
    fn detects_cloudflare_bot_management() {
        let dets = fingerprint(&[], &cookies(&["__cf_bm=token; Secure"]));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "Cloudflare Bot Management");
    }

    #[test]
    fn detects_kasada_header() {
        let dets = fingerprint(&headers(&[("x-kpsdk-ct", "abc")]), &[]);
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "Kasada");
        assert_eq!(dets[0].signals[0].signal_type, SignalType::Header);
    }

    #[test]
    fn detects_perimeterx() {
        let dets = fingerprint(&[], &cookies(&["_px3=value; Path=/"]));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "PerimeterX");
    }

    #[test]
    fn detects_f5_ts_cookie() {
        let dets = fingerprint(&[], &cookies(&["TS01abc123=deadbeef; Path=/"]));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "F5 Shape");
    }

    #[test]
    fn detects_imperva_reese84() {
        let dets = fingerprint(&[], &cookies(&["reese84=token"]));
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].provider, "Imperva");
    }

    #[test]
    fn dedups_and_stacks_multiple_vendors() {
        let dets = fingerprint(
            &headers(&[("x-kpsdk-ct", "x")]),
            &cookies(&["datadome=a", "_abck=b", "__cf_bm=c"]),
        );
        let mut providers: Vec<&str> = dets.iter().map(|d| d.provider.as_str()).collect();
        providers.sort_unstable();
        assert_eq!(
            providers,
            vec!["Akamai Bot Manager", "Cloudflare Bot Management", "DataDome", "Kasada"]
        );
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(fingerprint(&[], &[]).is_empty());
    }

    #[test]
    fn unrelated_cookies_yield_nothing() {
        let dets = fingerprint(
            &headers(&[("content-type", "text/html")]),
            &cookies(&["sessionid=abc", "csrftoken=xyz"]),
        );
        assert!(dets.is_empty());
    }
}
