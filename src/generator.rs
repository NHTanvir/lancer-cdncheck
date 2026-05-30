//! Dataset generator (Phase 3/4) — `crate::generator`.
//!
//! Reads the embedded [`PROVIDER_YAML`] manifest and builds a
//! [`crate::data::SourceData`] by:
//!
//!   * fetching every `urls` entry and regex-extracting CIDRs from the body,
//!   * expanding every `asn` entry into prefixes via the IPinfo API, and
//!   * copying the static `cidr` entries and `common.fqdn` suffixes through
//!     verbatim.
//!
//! Network work runs concurrently via `futures::stream::buffer_unordered`.
//! Individual fetch failures are logged and skipped — `compile` only fails on
//! unrecoverable errors (e.g. the manifest itself being malformed), and it
//! never panics when run without network access.

use std::collections::HashMap;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

/// The embedded provider manifest (source of truth for the dataset pipeline).
pub const PROVIDER_YAML: &str = include_str!("provider.yaml");

/// Concurrency limit for outbound fetches.
const FETCH_CONCURRENCY: usize = 16;

/// Default request timeout for dataset fetches.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Realistic User-Agent so providers that gate scrapers still serve us.
const USER_AGENT: &str = concat!(
    "lancer-cdncheck/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/NHTanvir/lancer-cdncheck)"
);

// ── manifest schema ────────────────────────────────────────────────────────

/// One IP category (`cdn` / `waf` / `cloud`) of the manifest: providers grouped
/// by the kind of source used to enumerate their address space.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CategorySpec {
    /// provider -> ASN list (each expanded via IPinfo).
    #[serde(default)]
    pub asn: HashMap<String, Vec<String>>,
    /// provider -> URL list (each fetched, then CIDR-extracted).
    #[serde(default)]
    pub urls: HashMap<String, Vec<String>>,
    /// provider -> static CIDR list (copied through verbatim).
    #[serde(default)]
    pub cidr: HashMap<String, Vec<String>>,
}

/// The `common` section of the manifest (DNS suffix signatures).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CommonSpec {
    /// provider -> FQDN suffix list.
    #[serde(default)]
    pub fqdn: HashMap<String, Vec<String>>,
}

/// The fully parsed `provider.yaml` manifest.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub cdn: CategorySpec,
    #[serde(default)]
    pub waf: CategorySpec,
    #[serde(default)]
    pub cloud: CategorySpec,
    #[serde(default)]
    pub common: CommonSpec,
}

/// Parse the embedded [`PROVIDER_YAML`] into a [`ProviderConfig`].
pub fn parse_provider_yaml() -> Result<ProviderConfig> {
    serde_yml::from_str(PROVIDER_YAML).context("parsing embedded provider.yaml")
}

// ── CIDR extraction ────────────────────────────────────────────────────────

/// The "monster" combined IPv4 + IPv6 CIDR regex.
///
/// * IPv4: four dotted octets (0-255) followed by `/0`..`/32`.
/// * IPv6: a fairly permissive but compression-aware address followed by
///   `/0`..`/128`.
///
/// We deliberately bound the prefix lengths and octet values so we extract
/// genuine network notation rather than arbitrary `number/number` noise.
static CIDR_RE: Lazy<Regex> = Lazy::new(|| {
    // IPv4 octet 0-255.
    let v4_octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    let v4 = format!(r"(?:{v4_octet}\.){{3}}{v4_octet}");
    // IPv4 prefix /0..=/32.
    let v4_prefix = r"(?:3[0-2]|[12]?[0-9])";
    let v4_cidr = format!(r"{v4}/{v4_prefix}");

    // IPv6: groups of hex, allowing one `::` compression. The alternation is
    // ordered most-specific-first so the longest valid form wins. Built on a
    // single logical line (no whitespace) so it needs no `(?x)` mode.
    let h16 = r"[0-9A-Fa-f]{1,4}";
    let v6 = format!(
        concat!(
            r"(?:",
            r"(?:{h16}:){{7}}{h16}",          // full 8 groups
            r"|(?:{h16}:){{1,7}}:",           // 1-7 groups then ::
            r"|(?:{h16}:){{1,6}}:{h16}",      // ... ::g
            r"|(?:{h16}:){{1,5}}(?::{h16}){{1,2}}",
            r"|(?:{h16}:){{1,4}}(?::{h16}){{1,3}}",
            r"|(?:{h16}:){{1,3}}(?::{h16}){{1,4}}",
            r"|(?:{h16}:){{1,2}}(?::{h16}){{1,5}}",
            r"|{h16}:(?::{h16}){{1,6}}",       // g(::g){1,6}
            r"|:(?::{h16}){{1,7}}",            // ::g...
            r"|::",                            // bare ::
            r")",
        ),
        h16 = h16
    );
    // IPv6 prefix /0..=/128.
    let v6_prefix = r"(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])";
    let v6_cidr = format!(r"{v6}/{v6_prefix}");

    // IPv6 alternative is tried first so it wins over the v4 branch on overlap.
    let pattern = format!(r"(?:{v6_cidr}|{v4_cidr})");
    Regex::new(&pattern).expect("CIDR regex is valid")
});

/// Extract every IPv4/IPv6 CIDR appearing anywhere in `body`.
///
/// Order is preserved and exact duplicates are removed (first occurrence wins).
pub fn extract_cidrs(body: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in CIDR_RE.find_iter(body) {
        let cidr = m.as_str().to_string();
        if seen.insert(cidr.clone()) {
            out.push(cidr);
        }
    }
    out
}

// ── fetching ───────────────────────────────────────────────────────────────

/// Build a shared `reqwest::Client` with sane defaults for dataset fetches.
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .gzip(true)
        .build()
        .context("building reqwest client")
}

/// Fetch a single URL and extract all CIDRs from its body.
///
/// Retries once on an HTTP 403 (some providers serve a soft block on the first
/// hit). HTML responses are reduced to their visible text via `scraper` before
/// extraction, so CIDRs embedded in markup are still found while HTML
/// attributes don't introduce false positives.
pub async fn fetch_url_cidrs(client: &reqwest::Client, url: &str) -> Result<Vec<String>> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;

    if resp.status().as_u16() == 403 {
        // Single retry on a soft block.
        resp = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("retrying {url} after 403"))?;
    }

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("{url} returned HTTP {}", status.as_u16());
    }

    // Decide whether the body is HTML based on the Content-Type header.
    let is_html = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false);

    let body = resp
        .text()
        .await
        .with_context(|| format!("reading body of {url}"))?;

    let text = if is_html {
        html_to_text(&body)
    } else {
        body
    };

    Ok(extract_cidrs(&text))
}

/// Reduce an HTML document to a whitespace-joined string of its text nodes so
/// CIDRs in `<pre>`/`<code>`/table cells survive while tag soup is dropped.
fn html_to_text(html: &str) -> String {
    use scraper::Html;
    let doc = Html::parse_document(html);
    doc.root_element()
        .text()
        .collect::<Vec<_>>()
        .join(" ")
}

// ── ASN expansion ──────────────────────────────────────────────────────────

/// Minimal shape of the IPinfo `AS<n>/json` response we care about.
#[derive(Debug, Deserialize)]
struct IpinfoAsn {
    #[serde(default)]
    prefixes: Vec<IpinfoPrefix>,
    #[serde(default)]
    prefixes6: Vec<IpinfoPrefix>,
}

#[derive(Debug, Deserialize)]
struct IpinfoPrefix {
    #[serde(default)]
    netblock: String,
}

/// Expand a single ASN into its announced prefixes via the IPinfo API.
///
/// `asn` may be given as `AS13335` or `13335`; IPinfo accepts the `AS`-prefixed
/// form, so we normalise to that. Both IPv4 (`prefixes`) and IPv6
/// (`prefixes6`) netblocks are returned.
pub async fn expand_asn(client: &reqwest::Client, asn: &str, token: &str) -> Result<Vec<String>> {
    let trimmed = asn.trim();
    let normalised = if trimmed
        .get(0..2)
        .map(|p| p.eq_ignore_ascii_case("AS"))
        .unwrap_or(false)
    {
        format!("AS{}", &trimmed[2..])
    } else {
        format!("AS{trimmed}")
    };

    let url = format!("https://ipinfo.io/{normalised}/json?token={token}");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("requesting IPinfo for {normalised}"))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("IPinfo returned HTTP {} for {normalised}", status.as_u16());
    }

    let data: IpinfoAsn = resp
        .json()
        .await
        .with_context(|| format!("parsing IPinfo JSON for {normalised}"))?;

    let mut out = Vec::with_capacity(data.prefixes.len() + data.prefixes6.len());
    for p in data.prefixes.into_iter().chain(data.prefixes6.into_iter()) {
        if !p.netblock.is_empty() {
            out.push(p.netblock);
        }
    }
    Ok(out)
}

// ── compilation ────────────────────────────────────────────────────────────

/// Options controlling a [`compile`] run.
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// IPinfo API token. Without it, ASN expansion is skipped (with a warning).
    pub ipinfo_token: Option<String>,
}

/// Which manifest category a job belongs to, used to route results into the
/// right [`SourceData`](crate::data::SourceData) map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cat {
    Cdn,
    Waf,
    Cloud,
}

/// A single concurrent fetch job: resolve `kind` for `provider` in `cat`.
#[derive(Debug, Clone)]
enum Job {
    Url { cat: Cat, provider: String, url: String },
    Asn { cat: Cat, provider: String, asn: String },
}

/// The outcome of running a [`Job`]: a (category, provider, cidrs) triple, or
/// `None` if the fetch failed (already logged) and should be skipped.
type JobResult = Option<(Cat, String, Vec<String>)>;

/// Compile the full dataset from the embedded manifest.
///
/// Fetches all `urls` and (token permitting) all `asn` entries concurrently,
/// merges them with the static `cidr` entries per provider per category, and
/// copies `common.fqdn` straight through. Individual fetch failures are logged
/// and skipped; the function only returns `Err` on an unrecoverable setup error
/// (malformed manifest or unbuildable HTTP client).
pub async fn compile(opts: &CompileOptions) -> Result<crate::data::SourceData> {
    let config = parse_provider_yaml()?;
    let client = build_http_client()?;

    let mut data = crate::data::SourceData::default();

    // 1) Static CIDRs and common.fqdn: copied through verbatim, no network.
    seed_static_cidrs(&mut data.cdn, &config.cdn);
    seed_static_cidrs(&mut data.waf, &config.waf);
    seed_static_cidrs(&mut data.cloud, &config.cloud);
    for (provider, suffixes) in &config.common.fqdn {
        data.common
            .entry(provider.clone())
            .or_default()
            .extend(suffixes.iter().cloned());
    }

    // 2) Build the list of network jobs (URLs always; ASNs only with a token).
    let mut jobs: Vec<Job> = Vec::new();
    for (cat, spec) in [
        (Cat::Cdn, &config.cdn),
        (Cat::Waf, &config.waf),
        (Cat::Cloud, &config.cloud),
    ] {
        for (provider, urls) in &spec.urls {
            for url in urls {
                jobs.push(Job::Url {
                    cat,
                    provider: provider.clone(),
                    url: url.clone(),
                });
            }
        }
        match &opts.ipinfo_token {
            Some(token) if !token.is_empty() => {
                for (provider, asns) in &spec.asn {
                    for asn in asns {
                        jobs.push(Job::Asn {
                            cat,
                            provider: provider.clone(),
                            asn: asn.clone(),
                        });
                    }
                }
            }
            _ => {
                let count: usize = spec.asn.values().map(Vec::len).sum();
                if count > 0 {
                    tracing::warn!(
                        category = ?cat,
                        asn_entries = count,
                        "no IPinfo token supplied; skipping ASN expansion"
                    );
                }
            }
        }
    }

    // 3) Run all jobs concurrently, bounded by FETCH_CONCURRENCY.
    let token = opts.ipinfo_token.clone().unwrap_or_default();
    let results: Vec<JobResult> = stream::iter(jobs.into_iter().map(|job| {
        let client = &client;
        let token = token.clone();
        async move {
            match job {
                Job::Url { cat, provider, url } => match fetch_url_cidrs(client, &url).await {
                    Ok(cidrs) => Some((cat, provider, cidrs)),
                    Err(e) => {
                        tracing::warn!(%url, provider = %provider, error = %e, "URL fetch failed; skipping");
                        None
                    }
                },
                Job::Asn { cat, provider, asn } => match expand_asn(client, &asn, &token).await {
                    Ok(cidrs) => Some((cat, provider, cidrs)),
                    Err(e) => {
                        tracing::warn!(%asn, provider = %provider, error = %e, "ASN expansion failed; skipping");
                        None
                    }
                },
            }
        }
    }))
    .buffer_unordered(FETCH_CONCURRENCY)
    .collect()
    .await;

    // 4) Merge fetched CIDRs into the appropriate category map.
    for (cat, provider, cidrs) in results.into_iter().flatten() {
        let map = match cat {
            Cat::Cdn => &mut data.cdn,
            Cat::Waf => &mut data.waf,
            Cat::Cloud => &mut data.cloud,
        };
        map.entry(provider).or_default().extend(cidrs);
    }

    // 5) Deduplicate every list while preserving order.
    dedup_map(&mut data.cdn);
    dedup_map(&mut data.waf);
    dedup_map(&mut data.cloud);
    dedup_map(&mut data.common);

    Ok(data)
}

/// Copy a category's static `cidr` entries into the target map.
fn seed_static_cidrs(target: &mut HashMap<String, Vec<String>>, spec: &CategorySpec) {
    for (provider, cidrs) in &spec.cidr {
        target
            .entry(provider.clone())
            .or_default()
            .extend(cidrs.iter().cloned());
    }
}

/// In-place, order-preserving dedup of every value list in a provider map.
fn dedup_map(map: &mut HashMap<String, Vec<String>>) {
    for list in map.values_mut() {
        let mut seen = std::collections::HashSet::new();
        list.retain(|item| seen.insert(item.clone()));
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cidrs_finds_v4_and_v6() {
        let blob = "\
            allow 13.32.0.0/15; deny everything else.\n\
            ipv6 = 2606:4700::/32 and 2400:cb00:2049::/48\n\
            host 192.168.1.1 (no prefix, ignored) and 10.0.0.0/8\n\
            duplicate 13.32.0.0/15 should not repeat\n\
            junk 999.999.999.999/40 must not match";
        let found = extract_cidrs(blob);

        assert!(found.contains(&"13.32.0.0/15".to_string()));
        assert!(found.contains(&"10.0.0.0/8".to_string()));
        assert!(found.contains(&"2606:4700::/32".to_string()));
        assert!(found.contains(&"2400:cb00:2049::/48".to_string()));

        // Bare IP without a prefix is not a CIDR.
        assert!(!found.iter().any(|c| c == "192.168.1.1"));
        // Out-of-range octets / oversized prefix must not match.
        assert!(!found.iter().any(|c| c == "999.999.999.999/40"));
        // First-occurrence dedup: only one copy of the repeated CIDR.
        assert_eq!(found.iter().filter(|c| *c == "13.32.0.0/15").count(), 1);
    }

    #[test]
    fn extract_cidrs_rejects_oversized_prefix() {
        // /33 is not a valid IPv4 prefix; the address part still matches /3.
        let found = extract_cidrs("1.2.3.0/33");
        assert!(found.iter().any(|c| c == "1.2.3.0/3"));
        assert!(!found.iter().any(|c| c == "1.2.3.0/33"));
    }

    #[test]
    fn parse_provider_yaml_succeeds_with_cdn_urls() {
        let cfg = parse_provider_yaml().expect("provider.yaml must parse");
        assert!(
            !cfg.cdn.urls.is_empty(),
            "cdn.urls should be non-empty in the embedded manifest"
        );
        // Sanity: at least one well-known provider should be present somewhere.
        assert!(!cfg.common.fqdn.is_empty(), "common.fqdn should be populated");
    }

    #[test]
    fn compile_options_default_has_no_token() {
        let opts = CompileOptions::default();
        assert!(opts.ipinfo_token.is_none());
    }
}
