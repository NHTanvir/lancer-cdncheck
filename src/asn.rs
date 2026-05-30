//! Phase 8 — ASN annotation.
//!
//! Enriches an IP with its autonomous-system number, holder name, announced
//! prefix and country using a public REST API. The default backend is
//! [RIPEstat](https://stat.ripe.net/) which requires no API key:
//!
//! * `GET https://stat.ripe.net/data/network-info/data.json?resource=<ip>`
//!   yields `data.asns[0]` and `data.prefix`.
//! * `GET https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>`
//!   yields `data.holder` (the AS name).
//!
//! Country is best-effort and read from the network-info / as-overview payloads
//! when present. Parsing is intentionally loose (`serde_json::Value`) so the
//! module stays robust against minor schema drift.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde_json::Value;

/// RIPEstat network-info endpoint (ASN + prefix for an IP resource).
const NETWORK_INFO_URL: &str = "https://stat.ripe.net/data/network-info/data.json";
/// RIPEstat as-overview endpoint (holder name for an `AS<n>` resource).
const AS_OVERVIEW_URL: &str = "https://stat.ripe.net/data/as-overview/data.json";

/// Per-request timeout for the ASN backend.
const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

/// User-Agent advertised to the ASN backend.
const USER_AGENT: &str = concat!("lancer-cdncheck/", env!("CARGO_PKG_VERSION"), " (+asn-lookup)");

/// Autonomous-system enrichment for a single IP address.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AsnInfo {
    /// Autonomous-system number (e.g. `13335`), if known.
    pub asn: Option<u32>,
    /// AS holder / organisation name (e.g. `CLOUDFLARENET`).
    pub name: Option<String>,
    /// Announced prefix covering the IP (e.g. `104.16.0.0/13`).
    pub prefix: Option<String>,
    /// ISO country code associated with the AS / prefix, if known.
    pub country: Option<String>,
}

impl AsnInfo {
    /// `true` when no field carries information (the default state).
    pub fn is_empty(&self) -> bool {
        self.asn.is_none()
            && self.name.is_none()
            && self.prefix.is_none()
            && self.country.is_none()
    }
}

/// Shared HTTP client (connection reuse across lookups).
static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Look up the ASN for `ip` via RIPEstat.
///
/// Returns an [`AsnInfo`]; fields stay `None` when the backend reports no data
/// for the resource. A network/transport failure or non-success HTTP status is
/// surfaced as `Err` so callers can distinguish "no data" from "lookup broke".
pub async fn lookup(ip: IpAddr) -> Result<AsnInfo> {
    let net = fetch_json(NETWORK_INFO_URL, &ip.to_string())
        .await
        .context("RIPEstat network-info request failed")?;

    let mut info = parse_network_info(&net);

    // Resolve the holder name (and a country fallback) from as-overview when we
    // have an ASN. A failure here is non-fatal: keep the ASN/prefix we have.
    if let Some(asn) = info.asn {
        if let Ok(overview) = fetch_json(AS_OVERVIEW_URL, &format!("AS{asn}")).await {
            apply_as_overview(&mut info, &overview);
        }
    }

    Ok(info)
}

/// Batch helper. Looks up each IP in order, swallowing per-IP errors into a
/// default [`AsnInfo`] so one failure never sinks the whole batch.
///
/// Results are returned paired with their input IP, preserving input order.
pub async fn lookup_many(ips: &[IpAddr]) -> Vec<(IpAddr, AsnInfo)> {
    let mut out = Vec::with_capacity(ips.len());
    for &ip in ips {
        let info = lookup(ip).await.unwrap_or_default();
        out.push((ip, info));
    }
    out
}

/// GET a RIPEstat data endpoint for `resource` and decode the JSON body.
async fn fetch_json(base: &str, resource: &str) -> Result<Value> {
    let resp = CLIENT
        .get(base)
        .query(&[("resource", resource), ("sourceapp", "lancer-cdncheck")])
        .send()
        .await
        .context("sending request")?
        .error_for_status()
        .context("non-success HTTP status")?;

    let body: Value = resp.json().await.context("decoding JSON body")?;
    Ok(body)
}

/// Extract ASN, prefix and (best-effort) country from a network-info payload.
fn parse_network_info(root: &Value) -> AsnInfo {
    let data = root.get("data").unwrap_or(&Value::Null);
    let mut info = AsnInfo::default();

    // `data.asns` is an array of numbers (or numeric strings). Take the first.
    if let Some(first) = data.get("asns").and_then(Value::as_array).and_then(|a| a.first()) {
        info.asn = value_to_u32(first);
    }

    if let Some(prefix) = data.get("prefix").and_then(Value::as_str) {
        if !prefix.is_empty() {
            info.prefix = Some(prefix.to_string());
        }
    }

    // Some payloads carry a country / actual_num_related_prefixes; pick country
    // if exposed at this layer.
    if let Some(country) = data.get("country").and_then(Value::as_str) {
        if !country.is_empty() {
            info.country = Some(country.to_string());
        }
    }

    info
}

/// Fold the holder name (and a country fallback) from an as-overview payload
/// into `info` without clobbering values already present.
fn apply_as_overview(info: &mut AsnInfo, root: &Value) {
    let data = root.get("data").unwrap_or(&Value::Null);

    if info.name.is_none() {
        if let Some(holder) = data.get("holder").and_then(Value::as_str) {
            if !holder.is_empty() {
                info.name = Some(holder.to_string());
            }
        }
    }

    if info.country.is_none() {
        // `data.block.resource` / `data.block.name` sometimes carry locale hints;
        // a direct `country` field is the cleanest source when present.
        if let Some(country) = data.get("country").and_then(Value::as_str) {
            if !country.is_empty() {
                info.country = Some(country.to_string());
            }
        }
    }
}

/// Coerce a JSON scalar (number or numeric string) into a `u32`.
fn value_to_u32(v: &Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    v.as_str().and_then(|s| s.trim().parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a representative RIPEstat network-info body without any network.
    #[test]
    fn parses_network_info_value() {
        let body = r#"{
            "status": "ok",
            "data": {
                "asns": ["13335"],
                "prefix": "104.16.0.0/13",
                "country": "US"
            }
        }"#;
        let v: Value = serde_json::from_str(body).expect("valid JSON");
        let info = parse_network_info(&v);
        assert_eq!(info.asn, Some(13335));
        assert_eq!(info.prefix.as_deref(), Some("104.16.0.0/13"));
        assert_eq!(info.country.as_deref(), Some("US"));
        assert!(info.name.is_none());
    }

    /// Numeric (non-string) ASN entries must also parse.
    #[test]
    fn parses_numeric_asn() {
        let body = r#"{ "data": { "asns": [15169], "prefix": "8.8.8.0/24" } }"#;
        let v: Value = serde_json::from_str(body).expect("valid JSON");
        let info = parse_network_info(&v);
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.prefix.as_deref(), Some("8.8.8.0/24"));
    }

    /// as-overview holder is folded in without overwriting existing fields.
    #[test]
    fn applies_as_overview_holder() {
        let mut info = AsnInfo {
            asn: Some(13335),
            prefix: Some("104.16.0.0/13".into()),
            ..Default::default()
        };
        let overview: Value = serde_json::from_str(
            r#"{ "data": { "holder": "CLOUDFLARENET, US", "country": "US" } }"#,
        )
        .expect("valid JSON");
        apply_as_overview(&mut info, &overview);
        assert_eq!(info.name.as_deref(), Some("CLOUDFLARENET, US"));
        assert_eq!(info.country.as_deref(), Some("US"));
        // Pre-existing fields are untouched.
        assert_eq!(info.asn, Some(13335));
        assert_eq!(info.prefix.as_deref(), Some("104.16.0.0/13"));
    }

    /// Missing / empty data yields an empty AsnInfo, not a panic.
    #[test]
    fn handles_missing_data() {
        let v: Value = serde_json::from_str(r#"{ "status": "ok" }"#).expect("valid JSON");
        let info = parse_network_info(&v);
        assert!(info.is_empty());
    }

    #[test]
    fn value_to_u32_handles_both_forms() {
        assert_eq!(value_to_u32(&Value::from(13335u64)), Some(13335));
        assert_eq!(value_to_u32(&Value::from(" 15169 ")), Some(15169));
        assert_eq!(value_to_u32(&Value::from("not-a-number")), None);
    }
}
