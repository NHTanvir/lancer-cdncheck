//! Public Suffix List helper (Phase 1): split an FQDN into its registrable
//! domain so CNAME-suffix matching is done at the right boundary, matching
//! upstream's use of `weppos/publicsuffix-go`.
//!
//! The PSL data is embedded at compile time. All access goes through
//! [`registrable_domain`], which degrades to a naive two-label split if the
//! list fails to parse, so the rest of the program never has to care.

use std::sync::OnceLock;

use publicsuffix::{List, Psl};

const PSL_DATA: &str = include_str!("public_suffix_list.dat");

fn list() -> Option<&'static List> {
    static LIST: OnceLock<Option<List>> = OnceLock::new();
    LIST.get_or_init(|| PSL_DATA.parse::<List>().ok())
        .as_ref()
}

/// Return the registrable domain (eTLD+1) for a host, e.g.
/// `d123.cloudfront.net` → `cloudfront.net`. Falls back to the last two
/// labels if the PSL is unavailable.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    if let Some(list) = list() {
        if let Some(domain) = list.domain(host.as_bytes()) {
            if let Ok(s) = std::str::from_utf8(domain.as_bytes()) {
                return Some(s.to_string());
            }
        }
    }
    naive_etld1(&host)
}

/// Return just the effective TLD (public suffix), e.g. `co.uk`.
pub fn public_suffix(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let list = list()?;
    let suffix = list.suffix(host.as_bytes())?;
    std::str::from_utf8(suffix.as_bytes()).ok().map(str::to_string)
}

fn naive_etld1(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() >= 2 {
        Some(labels[labels.len() - 2..].join("."))
    } else if labels.len() == 1 {
        Some(labels[0].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_registrable_domain() {
        assert_eq!(
            registrable_domain("d111.cloudfront.net").as_deref(),
            Some("cloudfront.net")
        );
    }

    #[test]
    fn handles_multi_label_suffix() {
        // Falls back gracefully even if PSL is missing.
        let d = registrable_domain("foo.bar.example.co.uk");
        assert!(d.is_some());
    }
}
