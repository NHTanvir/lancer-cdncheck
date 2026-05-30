//! Core detection types shared across every module (CLI, GUI, library, probes).
//!
//! A [`Detection`] is the unit returned by every check. It carries the primary
//! provider/category (back-compat with the simple upstream `(matched, value,
//! itemType)` triple) plus the Lancer extensions: a list of [`Signal`]s that
//! contributed, a `confidence` score, and the full `protection_stack` when more
//! than one layer is detected (e.g. "Cloudflare CDN + DataDome bot-protection").

use std::fmt;

use serde::Serialize;

/// Detection category. Matches upstream cdncheck's three categories plus the
/// Lancer-added `BotProtection` layer (Phase 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionCategory {
    Cdn,
    Waf,
    Cloud,
    BotProtection,
}

/// Plan-facing alias (`Category`) for [`DetectionCategory`].
pub use DetectionCategory as Category;

impl DetectionCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionCategory::Cdn => "cdn",
            DetectionCategory::Waf => "waf",
            DetectionCategory::Cloud => "cloud",
            DetectionCategory::BotProtection => "bot-protection",
        }
    }

    /// All categories in the canonical CDN → WAF → Cloud → BotProtection order.
    pub const ALL: [DetectionCategory; 4] = [
        DetectionCategory::Cdn,
        DetectionCategory::Waf,
        DetectionCategory::Cloud,
        DetectionCategory::BotProtection,
    ];
}

impl fmt::Display for DetectionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What kind of evidence produced a signal. Drives the base confidence weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    /// IPv4/IPv6 CIDR-trie longest-prefix match.
    Cidr,
    /// ASN membership (IPinfo-expanded at generate time).
    Asn,
    /// CNAME suffix match against `common.fqdn`.
    Cname,
    /// Wappalyzer technology-name match.
    Wappalyzer,
    /// HTTP response-header fingerprint (Phase 6 — [`crate::http_probe`]).
    Header,
    /// Cookie / Set-Cookie fingerprint (Phase 7 — [`crate::bot_protection`]).
    Cookie,
    /// TLS JA3/JA4 fingerprint. Reserved in the schema; *active* JA3 probing is a
    /// documented deferred add-on (it needs raw ClientHello/JA3S capture and a
    /// curated WAF JA3 hash database, out of scope for this build).
    Tls,
    /// SPF/TXT DNS record fingerprint ([`crate::dns_fingerprint::match_spf`]).
    Spf,
    /// NS record fingerprint ([`crate::dns_fingerprint::match_ns`]).
    Ns,
}

impl SignalType {
    /// Base confidence (%) for a lone signal of this type. Combined confidence
    /// is computed in [`Detection::from_signals`] per the plan's scoring table:
    /// CIDR alone → 80, CNAME alone → 60, header/cookie alone → 50, ASN → 40,
    /// CIDR + CNAME + header → 99.
    pub fn base_confidence(&self) -> u8 {
        match self {
            SignalType::Cidr => 80,
            SignalType::Cname => 60,
            SignalType::Wappalyzer => 60,
            SignalType::Header => 50,
            SignalType::Cookie => 50,
            SignalType::Tls => 50,
            SignalType::Asn => 40,
            SignalType::Spf => 40,
            SignalType::Ns => 40,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SignalType::Cidr => "cidr",
            SignalType::Asn => "asn",
            SignalType::Cname => "cname",
            SignalType::Wappalyzer => "wappalyzer",
            SignalType::Header => "header",
            SignalType::Cookie => "cookie",
            SignalType::Tls => "tls",
            SignalType::Spf => "spf",
            SignalType::Ns => "ns",
        }
    }
}

impl fmt::Display for SignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single piece of evidence: "provider X, category Y, via signal Z".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signal {
    pub provider: String,
    pub category: DetectionCategory,
    pub signal_type: SignalType,
    pub confidence: u8,
}

impl Signal {
    pub fn new(
        provider: impl Into<String>,
        category: DetectionCategory,
        signal_type: SignalType,
    ) -> Self {
        Signal {
            provider: provider.into(),
            category,
            signal_type,
            confidence: signal_type.base_confidence(),
        }
    }
}

/// The result of a check. Back-compatible with upstream's `(value, itemType)`
/// via [`Detection::provider`] / [`Detection::category`], extended with the
/// full signal list, an aggregate confidence, and the multi-layer
/// `protection_stack`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    /// Primary provider name (from the strongest signal).
    pub provider: String,
    /// Primary category (from the strongest signal).
    pub category: DetectionCategory,
    /// Aggregate confidence 0–100.
    pub confidence: u8,
    /// Every signal that contributed to this detection.
    pub signals: Vec<Signal>,
    /// Distinct providers across all layers (CDN + WAF + bot-protection + …).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub protection_stack: Vec<String>,
}

impl Detection {
    /// Build a `Detection` from a single signal (the common CIDR/CNAME path).
    pub fn single(
        provider: impl Into<String>,
        category: DetectionCategory,
        signal_type: SignalType,
    ) -> Self {
        Detection::from_signals(vec![Signal::new(provider, category, signal_type)])
            .expect("one signal always yields a detection")
    }

    /// Combine one or more signals into a detection, computing the aggregate
    /// confidence and the protection stack. Returns `None` if `signals` is
    /// empty.
    ///
    /// Scoring: the strongest signal's base score, +10 per additional distinct
    /// signal *type*, capped at 99. This reproduces the plan's anchor points
    /// (CIDR=80, CNAME=60, header=50, ASN=40; CIDR+CNAME+header→99).
    pub fn from_signals(mut signals: Vec<Signal>) -> Option<Detection> {
        if signals.is_empty() {
            return None;
        }
        // Strongest first: higher confidence, then category priority.
        signals.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| category_rank(a.category).cmp(&category_rank(b.category)))
        });

        let primary = &signals[0];
        let provider = primary.provider.clone();
        let category = primary.category;

        // Count distinct signal types for the confidence bonus.
        let mut distinct_types: Vec<SignalType> = Vec::new();
        for s in &signals {
            if !distinct_types.contains(&s.signal_type) {
                distinct_types.push(s.signal_type);
            }
        }
        let base = primary.confidence as u16;
        let bonus = 10u16 * (distinct_types.len() as u16 - 1);
        let confidence = (base + bonus).min(99) as u8;

        // Distinct providers, primary first, preserving discovery order.
        let mut protection_stack: Vec<String> = Vec::new();
        for s in &signals {
            if !protection_stack.contains(&s.provider) {
                protection_stack.push(s.provider.clone());
            }
        }
        // Only surface a stack when there's genuinely more than one layer.
        if protection_stack.len() < 2 {
            protection_stack.clear();
        }

        Some(Detection {
            provider,
            category,
            confidence,
            signals,
            protection_stack,
        })
    }

    /// Merge another detection's signals into this one (used to layer e.g. a
    /// CDN CIDR hit with a bot-protection cookie hit), recomputing confidence
    /// and the stack.
    pub fn merge(self, other: Detection) -> Detection {
        let mut signals = self.signals;
        for s in other.signals {
            if !signals.contains(&s) {
                signals.push(s);
            }
        }
        Detection::from_signals(signals).unwrap_or(Detection {
            provider: self.provider,
            category: self.category,
            confidence: self.confidence,
            signals: Vec::new(),
            protection_stack: self.protection_stack,
        })
    }
}

/// Lower rank wins ties — CDN before WAF before Cloud before BotProtection,
/// matching upstream's `Check()` ordering.
fn category_rank(c: DetectionCategory) -> u8 {
    match c {
        DetectionCategory::Cdn => 0,
        DetectionCategory::Waf => 1,
        DetectionCategory::Cloud => 2,
        DetectionCategory::BotProtection => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_alone_is_80() {
        let d = Detection::single("cloudflare", DetectionCategory::Waf, SignalType::Cidr);
        assert_eq!(d.confidence, 80);
        assert!(d.protection_stack.is_empty());
    }

    #[test]
    fn cidr_cname_header_is_99() {
        let d = Detection::from_signals(vec![
            Signal::new("cloudflare", DetectionCategory::Cdn, SignalType::Cidr),
            Signal::new("cloudflare", DetectionCategory::Cdn, SignalType::Cname),
            Signal::new("cloudflare", DetectionCategory::Cdn, SignalType::Header),
        ])
        .unwrap();
        assert_eq!(d.confidence, 99);
    }

    #[test]
    fn multi_provider_builds_stack() {
        let d = Detection::from_signals(vec![
            Signal::new("cloudflare", DetectionCategory::Cdn, SignalType::Cidr),
            Signal::new("datadome", DetectionCategory::BotProtection, SignalType::Cookie),
        ])
        .unwrap();
        assert_eq!(d.provider, "cloudflare");
        assert_eq!(d.protection_stack, vec!["cloudflare", "datadome"]);
    }
}
