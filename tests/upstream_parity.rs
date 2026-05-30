//! Integration tests asserting parity with upstream `cdncheck` behaviour.
//!
//! These tests exercise the *public* crate surface (`lancer_cdncheck`) only and
//! must NOT require network access: every vector is derived from the embedded
//! dataset and checked through the IP/suffix tries, all of which are built at
//! construction time without any DNS or HTTP I/O.

use std::net::{IpAddr, Ipv4Addr};

use lancer_cdncheck::data::SourceData;
use lancer_cdncheck::detection::{DetectionCategory, SignalType};
use lancer_cdncheck::{self_test, Client, Detection, Signal};

/// Parse an IPv4 CIDR string (`a.b.c.d/len`) and return a host IP *inside* the
/// network: the network address + 1, or the address itself for a `/32`.
///
/// Uses std only so the integration-test crate does not need `ipnet` as a
/// dev-dependency. Returns `None` for IPv6 or malformed input.
fn inside_ipv4(cidr: &str) -> Option<Ipv4Addr> {
    // Reject IPv6 / addresses without a prefix length up front.
    if cidr.contains(':') {
        return None;
    }
    let (addr_part, len_part) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_part.trim().parse().ok()?;
    let prefix: u32 = len_part.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }

    let bits = u32::from(addr);
    // Network address (clear the host bits).
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = bits & mask;

    // /32 has a single host: use the address as-is. Otherwise network + 1,
    // which is always inside the block for prefixes <= 31.
    let host = if prefix == 32 { network } else { network + 1 };
    Some(Ipv4Addr::from(host))
}

/// Find the first parseable IPv4 CIDR for a given provider in a category map.
fn first_ipv4_cidr<'a>(
    map: &'a std::collections::HashMap<String, Vec<String>>,
    provider: &str,
) -> Option<&'a str> {
    map.get(provider)?
        .iter()
        .map(String::as_str)
        .find(|c| !c.contains(':') && c.contains('/'))
}

/// `Client::new()` must succeed (it performs no network I/O at construction).
#[test]
fn client_new_succeeds() {
    let client = Client::new();
    assert!(
        client.is_ok(),
        "Client::new() failed: {:?}",
        client.err()
    );
}

/// A known Cloudflare IP must resolve to provider `cloudflare`.
///
/// Cloudflare lives in the WAF category upstream. Rather than hard-coding an IP
/// that could rotate out of the embedded snapshot, we derive an in-range host
/// from the first IPv4 CIDR Cloudflare advertises in the WAF map.
#[test]
fn cloudflare_ip_detected() {
    let data = SourceData::embedded();
    let cidr = first_ipv4_cidr(&data.waf, "cloudflare")
        .expect("embedded dataset must contain an IPv4 cloudflare WAF CIDR");
    let ip = inside_ipv4(cidr).expect("cloudflare WAF CIDR must yield an inside IPv4");

    let client = Client::new().expect("Client::new()");
    let det = client
        .check(IpAddr::V4(ip))
        .unwrap_or_else(|| panic!("expected a detection for cloudflare IP {ip} (from {cidr})"));

    assert_eq!(
        det.provider, "cloudflare",
        "expected provider 'cloudflare' for {ip}, got '{}'",
        det.provider
    );
    assert_eq!(det.category, DetectionCategory::Waf);
}

/// A `*.cloudfront.net` FQDN must suffix-match to provider `amazon`.
#[test]
fn cloudfront_suffix_is_amazon() {
    let client = Client::new().expect("Client::new()");
    let det = client
        .check_suffix_one("abc.cloudfront.net")
        .expect("abc.cloudfront.net should match a common suffix");
    assert_eq!(
        det.provider, "amazon",
        "expected provider 'amazon' for cloudfront.net, got '{}'",
        det.provider
    );
}

/// The offline self-test matrix must run, produce results, and pass at a high
/// rate. Any failures are printed for diagnosis.
#[test]
fn self_test_matrix_high_pass_rate() {
    let client = Client::new().expect("Client::new()");
    let results = self_test::run_self_test(&client);

    assert!(
        !results.is_empty(),
        "self-test produced no results"
    );

    let (passed, total) = self_test::summarize(&results);
    assert_eq!(total, results.len(), "summarize total must equal result count");

    // Print failures so a CI log explains any dip in the pass rate.
    for r in results.iter().filter(|r| !r.passed) {
        eprintln!(
            "SELF-TEST FAIL [{}] provider={} input={} expected={} :: {}",
            r.group, r.provider, r.input, r.expected, r.detail
        );
    }

    // > 80% pass rate. Use integer math to avoid float comparisons.
    assert!(
        passed * 100 > total * 80,
        "self-test pass rate too low: {passed}/{total} ({}%)",
        if total == 0 { 0 } else { passed * 100 / total }
    );
}

/// A lone CIDR signal must score exactly 80 confidence (the plan's anchor).
#[test]
fn single_cidr_detection_confidence_is_80() {
    // Via the high-level constructor.
    let det = Detection::single("cloudflare", DetectionCategory::Waf, SignalType::Cidr);
    assert_eq!(det.confidence, 80);
    assert!(
        det.protection_stack.is_empty(),
        "a single-provider detection should not surface a protection stack"
    );

    // Via from_signals, to confirm the scoring is consistent both ways.
    let det2 = Detection::from_signals(vec![Signal::new(
        "fastly",
        DetectionCategory::Cdn,
        SignalType::Cidr,
    )])
    .expect("one signal always yields a detection");
    assert_eq!(det2.confidence, 80);

    // And through a real client lookup against the embedded dataset.
    let data = SourceData::embedded();
    let cidr = first_ipv4_cidr(&data.waf, "cloudflare")
        .expect("embedded dataset must contain an IPv4 cloudflare WAF CIDR");
    let ip = inside_ipv4(cidr).expect("inside IPv4");
    let client = Client::new().expect("Client::new()");
    if let Some(det3) = client.check(IpAddr::V4(ip)) {
        assert_eq!(
            det3.confidence, 80,
            "a CIDR-only client detection must score 80"
        );
    }
}

/// Pure-logic sanity check for the CIDR-host derivation helper (no network,
/// no client). Guards against the test harness itself producing bad vectors.
#[test]
fn inside_ipv4_derivation() {
    assert_eq!(inside_ipv4("8.45.97.0/24"), Some(Ipv4Addr::new(8, 45, 97, 1)));
    assert_eq!(
        inside_ipv4("10.0.0.0/8"),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(
        inside_ipv4("192.168.1.5/32"),
        Some(Ipv4Addr::new(192, 168, 1, 5))
    );
    // IPv6 and malformed inputs are rejected.
    assert_eq!(inside_ipv4("2a09:bac0::/64"), None);
    assert_eq!(inside_ipv4("not-a-cidr"), None);
    assert_eq!(inside_ipv4("1.2.3.4/33"), None);
}
