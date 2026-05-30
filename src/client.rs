//! The detection [`Client`] — the library integration point (Phase 5).
//!
//! Holds three longest-prefix-match IP tries (CDN / WAF / Cloud), the CNAME
//! suffix map, the Wappalyzer technology map, and a DNS resolver. Every other
//! Lancer crate (lancerscan, lancerdns, lancerprobe) talks to this type.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::Result;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;

use crate::data::SourceData;
use crate::detection::{Detection, DetectionCategory, Signal, SignalType};
use crate::psl;

/// A pre-fetched DNS answer set (used by callers that already resolved, like
/// naabu / dnsx — upstream's `CheckDNSResponse`).
#[derive(Debug, Clone, Default)]
pub struct DnsData {
    pub a: Vec<Ipv4Addr>,
    pub aaaa: Vec<Ipv6Addr>,
    pub cname: Vec<String>,
}

/// Wappalyzer technology-name → (provider, category) table. Mirrors upstream's
/// `CheckWappalyzer`.
const WAPPALYZER: &[(&str, &str, DetectionCategory)] = &[
    ("imperva", "incapsula", DetectionCategory::Waf),
    ("incapsula", "incapsula", DetectionCategory::Waf),
    ("cloudflare", "cloudflare", DetectionCategory::Cdn),
    ("cloudfront", "amazon", DetectionCategory::Cdn),
    ("amazon cloudfront", "amazon", DetectionCategory::Cdn),
    ("akamai", "akamai", DetectionCategory::Cdn),
    ("sucuri", "sucuri", DetectionCategory::Waf),
    ("fastly", "fastly", DetectionCategory::Cdn),
];

pub struct Client {
    cdn_trie: IpnetTrie<String>,
    waf_trie: IpnetTrie<String>,
    cloud_trie: IpnetTrie<String>,
    /// suffix → (provider, category)
    fqdn_map: HashMap<String, (String, DetectionCategory)>,
    wappalyzer_map: HashMap<String, (String, DetectionCategory)>,
    resolver: TokioAsyncResolver,
    ipv6_available: bool,
}

impl Client {
    /// Build a client with the best available dataset (disk override or
    /// embedded) and the default resolver pool (Cloudflare / Google / Quad9 /
    /// OpenDNS, plus IPv6 resolvers when IPv6 is reachable).
    pub fn new() -> Result<Self> {
        let ipv6 = check_ipv6_connectivity();
        let config = default_resolver_config(ipv6);
        Self::from_source_data(SourceData::load(), config, ResolverOpts::default(), ipv6)
    }

    /// Upstream-parity constructor: custom retry count and resolver list.
    pub fn new_with_opts(max_retries: usize, resolvers: &[String]) -> Result<Self> {
        let ipv6 = check_ipv6_connectivity();
        let config = if resolvers.is_empty() {
            default_resolver_config(ipv6)
        } else {
            build_resolver_config(resolvers)?
        };
        let mut opts = ResolverOpts::default();
        opts.attempts = max_retries;
        Self::from_source_data(SourceData::load(), config, opts, ipv6)
    }

    /// Build a client from an explicit resolver config/opts (used by the CLI).
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let ipv6 = check_ipv6_connectivity();
        Self::from_source_data(SourceData::load(), config, opts, ipv6)
    }

    /// Build a client from an explicit dataset (used by `update` and tests).
    pub fn from_source_data(
        data: SourceData,
        config: ResolverConfig,
        opts: ResolverOpts,
        ipv6_available: bool,
    ) -> Result<Self> {
        Ok(Self {
            cdn_trie: build_trie(&data.cdn),
            waf_trie: build_trie(&data.waf),
            cloud_trie: build_trie(&data.cloud),
            fqdn_map: build_fqdn_map(&data.common),
            wappalyzer_map: build_wappalyzer_map(),
            resolver: TokioAsyncResolver::tokio(config, opts),
            ipv6_available,
        })
    }

    /// Whether IPv6 was reachable at construction time.
    pub fn ipv6_available(&self) -> bool {
        self.ipv6_available
    }

    // ── single-category checks ────────────────────────────────────────────

    pub fn check_cdn(&self, ip: IpAddr) -> Option<Detection> {
        trie_lookup(&self.cdn_trie, ip)
            .map(|p| Detection::single(p, DetectionCategory::Cdn, SignalType::Cidr))
    }

    pub fn check_waf(&self, ip: IpAddr) -> Option<Detection> {
        trie_lookup(&self.waf_trie, ip)
            .map(|p| Detection::single(p, DetectionCategory::Waf, SignalType::Cidr))
    }

    pub fn check_cloud(&self, ip: IpAddr) -> Option<Detection> {
        trie_lookup(&self.cloud_trie, ip)
            .map(|p| Detection::single(p, DetectionCategory::Cloud, SignalType::Cidr))
    }

    /// Check an IP against all three tries in CDN → WAF → Cloud order, return
    /// the first match (upstream `Check`).
    pub fn check(&self, ip: IpAddr) -> Option<Detection> {
        self.check_cdn(ip)
            .or_else(|| self.check_waf(ip))
            .or_else(|| self.check_cloud(ip))
    }

    /// Alias for [`Client::check`].
    pub fn check_ip(&self, ip: IpAddr) -> Option<Detection> {
        self.check(ip)
    }

    // ── suffix / wappalyzer ─────────────────────────────────────────────────

    /// Check one or more FQDNs (e.g. a CNAME chain) against the common-suffix
    /// map (upstream `CheckSuffix`). Uses the PSL to compare at the registrable
    /// boundary, with an `ends_with` fallback.
    pub fn check_suffix(&self, fqdns: &[&str]) -> Option<Detection> {
        for raw in fqdns {
            let fqdn = raw.trim().trim_end_matches('.').to_lowercase();
            if fqdn.is_empty() {
                continue;
            }
            // Direct registrable-domain match.
            if let Some(reg) = psl::registrable_domain(&fqdn) {
                if let Some((provider, category)) = self.fqdn_map.get(&reg) {
                    return Some(Detection::single(
                        provider.clone(),
                        *category,
                        SignalType::Cname,
                    ));
                }
            }
            // Suffix (`ends_with`) match for multi-label CDN suffixes.
            for (suffix, (provider, category)) in &self.fqdn_map {
                if fqdn == *suffix || fqdn.ends_with(&format!(".{suffix}")) {
                    return Some(Detection::single(
                        provider.clone(),
                        *category,
                        SignalType::Cname,
                    ));
                }
            }
        }
        None
    }

    /// Convenience: check a single FQDN suffix.
    pub fn check_suffix_one(&self, fqdn: &str) -> Option<Detection> {
        self.check_suffix(&[fqdn])
    }

    /// Map a set of Wappalyzer technology names to a CDN/WAF provider
    /// (upstream `CheckWappalyzer`). Names are matched case-insensitively.
    pub fn check_wappalyzer<S: AsRef<str>>(&self, technologies: &[S]) -> Option<Detection> {
        for tech in technologies {
            let key = tech.as_ref().to_lowercase();
            if let Some((provider, category)) = self.wappalyzer_map.get(&key) {
                return Some(Detection::single(
                    provider.clone(),
                    *category,
                    SignalType::Wappalyzer,
                ));
            }
        }
        None
    }

    // ── DNS-backed checks ───────────────────────────────────────────────────

    /// Operate on a pre-fetched DNS answer set without doing any network I/O
    /// (upstream `CheckDNSResponse`). Checks A/AAAA in the tries, then the
    /// CNAME chain against the suffix map.
    pub fn check_dns_response(&self, dns: &DnsData) -> Option<Detection> {
        for ip in dns.a.iter().copied() {
            if let Some(det) = self.check(IpAddr::V4(ip)) {
                return Some(det);
            }
        }
        for ip in dns.aaaa.iter().copied() {
            if let Some(det) = self.check(IpAddr::V6(ip)) {
                return Some(det);
            }
        }
        let cnames: Vec<&str> = dns.cname.iter().map(String::as_str).collect();
        self.check_suffix(&cnames)
    }

    /// Resolve a domain (A/AAAA), check each IP; on no match, query CNAME and
    /// suffix-match; finally try the domain itself as a suffix (upstream
    /// `CheckDomainWithFallback`).
    pub async fn check_domain_with_fallback(&self, domain: &str) -> Result<Option<Detection>> {
        let domain = domain.trim().trim_end_matches('.');

        if let Ok(response) = self.resolver.lookup_ip(domain).await {
            for ip in response.iter() {
                if let Some(det) = self.check(ip) {
                    return Ok(Some(det));
                }
            }
        }

        if let Ok(lookup) = self.resolver.lookup(domain, RecordType::CNAME).await {
            let targets: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| match rdata {
                    RData::CNAME(cname) => {
                        Some(cname.0.to_string().trim_end_matches('.').to_string())
                    }
                    _ => None,
                })
                .collect();
            let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
            if let Some(det) = self.check_suffix(&refs) {
                return Ok(Some(det));
            }
        }

        Ok(self.check_suffix(&[domain]))
    }

    /// Back-compat alias used by earlier code.
    pub async fn check_domain(&self, domain: &str) -> Result<Option<Detection>> {
        self.check_domain_with_fallback(domain).await
    }

    /// DNS-record fingerprinting: query the domain's `TXT`(SPF) and `NS`
    /// records and match them against known provider signatures (detection
    /// methods #4/#5). Returns every provider inferred — never an error
    /// (lookup failures simply yield fewer signals).
    pub async fn check_dns_fingerprint(&self, domain: &str) -> Vec<Detection> {
        let domain = domain.trim().trim_end_matches('.');
        let mut out = Vec::new();

        // SPF via TXT records.
        if let Ok(lookup) = self.resolver.lookup(domain, RecordType::TXT).await {
            let mut txts: Vec<String> = Vec::new();
            for rdata in lookup.iter() {
                if let RData::TXT(txt) = rdata {
                    let joined: String = txt
                        .txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .collect::<Vec<_>>()
                        .join("");
                    txts.push(joined);
                }
            }
            out.extend(crate::dns_fingerprint::match_spf(&txts));
        }

        // Authoritative NS records.
        if let Ok(lookup) = self.resolver.lookup(domain, RecordType::NS).await {
            let mut hosts: Vec<String> = Vec::new();
            for rdata in lookup.iter() {
                if let RData::NS(ns) = rdata {
                    hosts.push(ns.0.to_string().trim_end_matches('.').to_string());
                }
            }
            out.extend(crate::dns_fingerprint::match_ns(&hosts));
        }

        out
    }
}

// ── trie / map construction ─────────────────────────────────────────────────

fn build_trie(map: &HashMap<String, Vec<String>>) -> IpnetTrie<String> {
    let mut trie = IpnetTrie::new();
    for (provider, cidrs) in map {
        for cidr in cidrs {
            if let Ok(net) = cidr.parse::<IpNet>() {
                trie.insert(net, provider.clone());
            } else if let Ok(ip) = cidr.parse::<IpAddr>() {
                trie.insert(IpNet::from(ip), provider.clone());
            }
        }
    }
    trie
}

fn trie_lookup(trie: &IpnetTrie<String>, ip: IpAddr) -> Option<String> {
    trie.longest_match(&IpNet::from(ip)).map(|(_, v)| v.clone())
}

fn build_fqdn_map(
    common: &HashMap<String, Vec<String>>,
) -> HashMap<String, (String, DetectionCategory)> {
    let mut map = HashMap::new();
    for (provider, fqdns) in common {
        let category = classify_common(provider);
        for fqdn in fqdns {
            map.insert(
                fqdn.trim_end_matches('.').to_lowercase(),
                (provider.clone(), category),
            );
        }
    }
    map
}

fn build_wappalyzer_map() -> HashMap<String, (String, DetectionCategory)> {
    WAPPALYZER
        .iter()
        .map(|(tech, provider, cat)| (tech.to_string(), (provider.to_string(), *cat)))
        .collect()
}

/// Common-suffix entries are mostly CDNs, but some are explicitly WAFs (the
/// name carries "WAF" or matches a known WAF brand).
fn classify_common(provider: &str) -> DetectionCategory {
    let p = provider.to_lowercase();
    const WAF_HINTS: &[&str] = &[
        "waf",
        "incapsula",
        "imperva",
        "sucuri",
        "奇安信",
        "绿盟",
        "深信服",
        "安恒",
        "网站卫士",
        "玄武盾",
    ];
    if WAF_HINTS.iter().any(|h| p.contains(h)) {
        DetectionCategory::Waf
    } else {
        DetectionCategory::Cdn
    }
}

// ── resolver helpers ─────────────────────────────────────────────────────────

/// Build a resolver config from a list of `host` or `host:port` strings.
pub fn build_resolver_config(addrs: &[String]) -> Result<ResolverConfig> {
    let mut config = ResolverConfig::new();
    for s in addrs {
        let addr: SocketAddr = if s.contains(':') && !s.starts_with('[') && s.matches(':').count() > 1
        {
            // bare IPv6 without brackets/port
            format!("[{s}]:53").parse()?
        } else if s.contains(':') {
            s.parse()?
        } else {
            format!("{s}:53").parse()?
        };
        config.add_name_server(name_server(addr));
    }
    Ok(config)
}

/// The default multi-provider resolver pool. IPv6 resolvers are only added when
/// IPv6 is reachable (matches upstream's `init()` behaviour).
pub fn default_resolver_config(ipv6_available: bool) -> ResolverConfig {
    let mut config = ResolverConfig::new();
    let v4: [Ipv4Addr; 7] = [
        Ipv4Addr::new(1, 1, 1, 1),       // Cloudflare
        Ipv4Addr::new(1, 0, 0, 1),       // Cloudflare
        Ipv4Addr::new(8, 8, 8, 8),       // Google
        Ipv4Addr::new(8, 8, 4, 4),       // Google
        Ipv4Addr::new(9, 9, 9, 9),       // Quad9
        Ipv4Addr::new(208, 67, 222, 222), // OpenDNS
        Ipv4Addr::new(208, 67, 220, 220), // OpenDNS
    ];
    for ip in v4 {
        config.add_name_server(name_server(SocketAddr::new(IpAddr::V4(ip), 53)));
    }
    if ipv6_available {
        let v6: [Ipv6Addr; 2] = [
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), // Cloudflare
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), // Google
        ];
        for ip in v6 {
            config.add_name_server(name_server(SocketAddr::new(IpAddr::V6(ip), 53)));
        }
    }
    config
}

fn name_server(socket_addr: SocketAddr) -> NameServerConfig {
    NameServerConfig {
        socket_addr,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    }
}

/// Probe IPv6 reachability with a non-blocking UDP "connect" to Google's v6
/// resolver (no packets are actually sent). Mirrors upstream's
/// `checkIPv6Connectivity()`.
pub fn check_ipv6_connectivity() -> bool {
    let Ok(sock) = UdpSocket::bind("[::]:0") else {
        return false;
    };
    let _ = sock.set_write_timeout(Some(Duration::from_secs(3)));
    let target: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    sock.connect(target).is_ok()
}
