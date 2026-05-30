//! `--self-test` parity matrix.
//!
//! A fully OFFLINE self-check that exercises the detection [`Client`] against
//! deterministic vectors derived from the *embedded* dataset
//! ([`crate::data::SourceData::embedded`]). No DNS resolution and no network
//! I/O are performed: every vector is either an IP-trie lookup or a static
//! FQDN-suffix lookup, both of which are pure/synchronous.
//!
//! The matrix has two groups:
//!
//! 1. **IP CIDR vectors** — for each provider in the `cdn` / `waf` / `cloud`
//!    maps, take its first parseable IPv4 CIDR, derive a host IP that lives
//!    inside that CIDR (network address + 1, or the network address itself for
//!    a `/32`), then assert that [`Client::check`] returns a [`Detection`] whose
//!    `provider` equals that provider name. The `group` is the category name
//!    (`cdn` / `waf` / `cloud`).
//!
//! 2. **FQDN suffix vectors** — a handful of well-known CDN/host suffixes are
//!    probed via [`Client::check_suffix_one`] with a `x.<suffix>` host to assert
//!    the suffix map resolves them.
//!
//! No vector ever panics: a failure is recorded as a [`SelfTestResult`] with
//! `passed = false` and a human-readable `detail` describing expected vs got.

use std::net::{IpAddr, Ipv4Addr};

use crate::data::SourceData;
use crate::detection::DetectionCategory;
use crate::Client;

/// The outcome of a single self-test vector.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelfTestResult {
    /// Logical group: a category name (`cdn`/`waf`/`cloud`) for IP vectors, or
    /// `suffix` for the FQDN suffix vectors.
    pub group: String,
    /// The provider (or suffix) the vector targets.
    pub provider: String,
    /// The literal input fed to the client (an IP string or an FQDN).
    pub input: String,
    /// A short description of what a pass requires.
    pub expected: String,
    /// Whether the vector passed.
    pub passed: bool,
    /// Human-readable detail (what was expected vs what was observed).
    pub detail: String,
}

/// Well-known FQDN suffixes that the embedded `common` map is expected to
/// resolve. Each is probed as `x.<suffix>`.
const SUFFIX_VECTORS: &[&str] = &[
    "cloudfront.net",
    "fastly.net",
    "cloudflare.com",
    "b-cdn.net",
    "vercel.app",
    "github.io",
];

/// Run every parity vector against `client`. Pure and synchronous: performs no
/// DNS and no network I/O, and never panics.
pub fn run_self_test(client: &Client) -> Vec<SelfTestResult> {
    let data = SourceData::embedded();
    let mut results = Vec::new();

    // ── Group 1: IP CIDR vectors, one per provider per category ───────────────
    for category in [
        DetectionCategory::Cdn,
        DetectionCategory::Waf,
        DetectionCategory::Cloud,
    ] {
        let map = match category {
            DetectionCategory::Cdn => &data.cdn,
            DetectionCategory::Waf => &data.waf,
            DetectionCategory::Cloud => &data.cloud,
            // The embedded dataset has no bot-protection IP map; unreachable
            // here because we only iterate the three IP categories above.
            DetectionCategory::BotProtection => continue,
        };
        let group = category.as_str().to_string();

        // Deterministic order so the report is stable across runs.
        let mut providers: Vec<&String> = map.keys().collect();
        providers.sort();

        for provider in providers {
            let cidrs = match map.get(provider) {
                Some(c) => c,
                None => continue,
            };

            // First parseable IPv4 CIDR for this provider.
            let host = cidrs.iter().find_map(|c| host_ip_in_cidr(c));

            let host = match host {
                Some(ip) => ip,
                None => {
                    results.push(SelfTestResult {
                        group: group.clone(),
                        provider: provider.clone(),
                        input: String::new(),
                        expected: format!("a parseable IPv4 CIDR for {provider}"),
                        passed: false,
                        detail: "no parseable IPv4 CIDR found for this provider".to_string(),
                    });
                    continue;
                }
            };

            let ip = IpAddr::V4(host);
            let (passed, detail) = match client.check(ip) {
                Some(det) if det.provider == *provider => {
                    (true, format!("matched {} ({})", det.provider, det.category))
                }
                Some(det) => (
                    false,
                    format!(
                        "expected provider {provider}, got {} ({})",
                        det.provider, det.category
                    ),
                ),
                None => (
                    false,
                    format!("expected provider {provider}, got no detection"),
                ),
            };

            results.push(SelfTestResult {
                group: group.clone(),
                provider: provider.clone(),
                input: ip.to_string(),
                expected: format!("check() == {provider}"),
                passed,
                detail,
            });
        }
    }

    // ── Group 2: FQDN suffix vectors ──────────────────────────────────────────
    for suffix in SUFFIX_VECTORS {
        let host = format!("x.{suffix}");
        let (passed, detail) = match client.check_suffix_one(&host) {
            Some(det) => (
                true,
                format!("matched {} ({})", det.provider, det.category),
            ),
            None => (false, "expected a suffix match, got none".to_string()),
        };
        results.push(SelfTestResult {
            group: "suffix".to_string(),
            provider: (*suffix).to_string(),
            input: host,
            expected: format!("check_suffix_one(x.{suffix}) is Some"),
            passed,
            detail,
        });
    }

    results
}

/// Summarize a result set as `(passed, total)`.
pub fn summarize(results: &[SelfTestResult]) -> (usize, usize) {
    let passed = results.iter().filter(|r| r.passed).count();
    (passed, results.len())
}

/// Parse an IPv4 CIDR string (`a.b.c.d/prefix`) and derive a host IP that is
/// guaranteed to fall inside it: the network address + 1 for a real subnet, or
/// the network address itself for a `/32`. Returns `None` for unparseable input
/// or for IPv6 CIDRs (this matrix only covers IPv4 vectors).
fn host_ip_in_cidr(cidr: &str) -> Option<Ipv4Addr> {
    let net: ipnet::Ipv4Net = cidr.parse().ok()?;
    let network = net.network();
    if net.prefix_len() >= 32 {
        return Some(network);
    }
    let bits = u32::from(network);
    // network + 1 is always inside the subnet for prefixes < 32 (the +1 lands
    // on the first usable host and never overflows the subnet boundary).
    Some(Ipv4Addr::from(bits.wrapping_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_is_inside_its_cidr() {
        // /24 → network + 1
        let net: ipnet::Ipv4Net = "54.192.0.0/16".parse().unwrap();
        let host = host_ip_in_cidr("54.192.0.0/16").unwrap();
        assert!(net.contains(&host));
        assert_eq!(host, Ipv4Addr::new(54, 192, 0, 1));

        // /32 → the address itself
        let host32 = host_ip_in_cidr("8.8.8.8/32").unwrap();
        assert_eq!(host32, Ipv4Addr::new(8, 8, 8, 8));

        // unparseable / IPv6 → None
        assert!(host_ip_in_cidr("not-a-cidr").is_none());
        assert!(host_ip_in_cidr("2606:4700::/32").is_none());
    }

    #[test]
    fn self_test_runs_offline_and_counts_add_up() {
        // `Client::new` performs no network I/O at construction (only a
        // non-blocking IPv6 connectivity probe and trie building), so this is
        // safe to run in an offline test environment.
        let client = Client::new().expect("client builds from embedded dataset");
        let results = run_self_test(&client);
        assert!(!results.is_empty(), "expected at least one self-test vector");

        let (passed, total) = summarize(&results);
        assert_eq!(total, results.len());
        assert!(passed <= total);

        // Sanity: the fixed suffix vectors are always present.
        let suffix_count = results.iter().filter(|r| r.group == "suffix").count();
        assert_eq!(suffix_count, SUFFIX_VECTORS.len());
    }
}
