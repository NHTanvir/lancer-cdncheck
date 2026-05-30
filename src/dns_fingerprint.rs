//! DNS-record fingerprinting (plan "Detection methods" #4 SPF/TXT and #5 NS).
//!
//! Pure, network-free matchers that infer a hosting / cloud / CDN provider from
//! a domain's `TXT`(SPF) and `NS` records. The live DNS queries are performed by
//! [`crate::client::Client::check_dns_fingerprint`], which feeds the raw record
//! strings to [`match_spf`] / [`match_ns`] here so the matching logic stays
//! unit-testable.
//!
//! These complement the offline CIDR/CNAME signals: an SPF `include:` or an
//! authoritative-NS suffix often reveals the provider when A/AAAA and CNAME are
//! uninformative.

use crate::detection::{Detection, DetectionCategory, SignalType};

/// SPF `include:` / `redirect=` substrings → (provider, category).
const SPF_SIGNATURES: &[(&str, &str, DetectionCategory)] = &[
    ("_spf.google.com", "google", DetectionCategory::Cloud),
    ("spf.protection.outlook.com", "microsoft", DetectionCategory::Cloud),
    ("amazonses.com", "amazon", DetectionCategory::Cloud),
    ("_spf.salesforce.com", "salesforce", DetectionCategory::Cloud),
    ("sendgrid.net", "sendgrid", DetectionCategory::Cloud),
    ("mailgun.org", "mailgun", DetectionCategory::Cloud),
    ("spf.mandrillapp.com", "mandrill", DetectionCategory::Cloud),
    ("servers.mcsv.net", "mailchimp", DetectionCategory::Cloud),
    ("zoho.com", "zoho", DetectionCategory::Cloud),
    ("spf.mail.qq.com", "tencent", DetectionCategory::Cloud),
    ("aspmx.pardot.com", "salesforce", DetectionCategory::Cloud),
    ("_spf.fastly.net", "fastly", DetectionCategory::Cdn),
];

/// Authoritative-NS suffix substrings → (provider, category).
const NS_SIGNATURES: &[(&str, &str, DetectionCategory)] = &[
    ("cloudflare.com", "cloudflare", DetectionCategory::Cdn),
    ("awsdns", "amazon", DetectionCategory::Cloud),
    ("azure-dns", "azure", DetectionCategory::Cloud),
    ("googledomains.com", "google", DetectionCategory::Cloud),
    ("ns.cloud.google.com", "google", DetectionCategory::Cloud),
    ("nsone.net", "ns1", DetectionCategory::Cloud),
    ("dnsimple.com", "dnsimple", DetectionCategory::Cloud),
    ("domaincontrol.com", "godaddy", DetectionCategory::Cloud),
    ("registrar-servers.com", "namecheap", DetectionCategory::Cloud),
    ("dnspod.net", "tencent", DetectionCategory::Cloud),
    ("dnsv1.com", "tencent", DetectionCategory::Cloud),
    ("alidns.com", "alibaba", DetectionCategory::Cloud),
    ("hichina.com", "alibaba", DetectionCategory::Cloud),
    ("vercel-dns.com", "vercel", DetectionCategory::Cdn),
    ("fastly.net", "fastly", DetectionCategory::Cdn),
];

/// Infer providers from a domain's TXT records (SPF `include:`/`redirect=`).
///
/// Records that are not SPF (`v=spf1 …`) are ignored. Each matched provider
/// yields one [`Detection`] with [`SignalType::Spf`]; results are deduplicated
/// by provider.
pub fn match_spf(txt_records: &[String]) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    for record in txt_records {
        let lower = record.to_lowercase();
        if !lower.contains("v=spf1") {
            continue;
        }
        for (needle, provider, category) in SPF_SIGNATURES {
            if lower.contains(needle) && !out.iter().any(|d| d.provider == *provider) {
                out.push(Detection::single(*provider, *category, SignalType::Spf));
            }
        }
    }
    out
}

/// Infer providers from a domain's authoritative NS hostnames.
///
/// Each matched provider yields one [`Detection`] with [`SignalType::Ns`];
/// results are deduplicated by provider.
pub fn match_ns(ns_hosts: &[String]) -> Vec<Detection> {
    let mut out: Vec<Detection> = Vec::new();
    for host in ns_hosts {
        let lower = host.to_lowercase();
        for (needle, provider, category) in NS_SIGNATURES {
            if lower.contains(needle) && !out.iter().any(|d| d.provider == *provider) {
                out.push(Detection::single(*provider, *category, SignalType::Ns));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_detects_google_and_amazon() {
        let txts = vec![
            "v=spf1 include:_spf.google.com include:amazonses.com ~all".to_string(),
            "some-unrelated-verification=abc123".to_string(),
        ];
        let dets = match_spf(&txts);
        let providers: Vec<&str> = dets.iter().map(|d| d.provider.as_str()).collect();
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"amazon"));
        assert!(dets.iter().all(|d| d.signals[0].signal_type == SignalType::Spf));
    }

    #[test]
    fn spf_ignores_non_spf_txt() {
        let txts = vec!["google-site-verification=_spf.google.com".to_string()];
        // Not an SPF record (no v=spf1) → no detection even though the substring
        // appears.
        assert!(match_spf(&txts).is_empty());
    }

    #[test]
    fn ns_detects_cloudflare() {
        let ns = vec![
            "ada.ns.cloudflare.com".to_string(),
            "rex.ns.cloudflare.com".to_string(),
        ];
        let dets = match_ns(&ns);
        assert_eq!(dets.len(), 1, "two cloudflare NS dedup to one detection");
        assert_eq!(dets[0].provider, "cloudflare");
        assert_eq!(dets[0].category, DetectionCategory::Cdn);
        assert_eq!(dets[0].signals[0].signal_type, SignalType::Ns);
    }

    #[test]
    fn ns_detects_route53() {
        let ns = vec!["ns-1234.awsdns-56.org".to_string()];
        let dets = match_ns(&ns);
        assert_eq!(dets[0].provider, "amazon");
        assert_eq!(dets[0].category, DetectionCategory::Cloud);
    }

    #[test]
    fn empty_inputs_yield_nothing() {
        assert!(match_spf(&[]).is_empty());
        assert!(match_ns(&[]).is_empty());
    }
}
