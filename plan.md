# RESEARCH DOSSIER: cdncheck

> Part of the Lancer ecosystem. A Rust clone of ProjectDiscovery's cdncheck, the CDN/WAF/Cloud detection library + CLI. Build with Claude Code.
> Upstream: github.com/projectdiscovery/cdncheck (Go, ~750 stars). Weekly auto-bumped fingerprint dataset. Default branch: `main`.

## Feature Parity Mandate

**`lancer-cdncheck` MUST ship with 100% feature parity to the upstream `cdncheck` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `cdncheck --help` (and the long-form man page / docs) must work in `lancer-cdncheck --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-cdncheck` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-cdncheck --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does (1-paragraph)
cdncheck answers one question per input: "Is this IP/hostname behind a CDN, WAF, or cloud provider, and which one?" The answer powers two recon decisions: (1) **skip full-port scanning** of CDN/WAF hosts (you'll just hit edge servers — naabu's `-ec` flag) and (2) **prioritize WAF-bypass research** when CDN detected (need a different attack path). Detection is **offline-first** via a compiled IP-trie of provider CIDRs (refreshed weekly upstream from official provider feeds: AWS `ip-ranges.json`, Cloudflare API, Fastly public-ip-list, Google `goog.json`, Azure XML download, Oracle JSON, Akamai ASN expansion, etc.). For domain inputs, it resolves A/AAAA then matches; if no IP match, it falls back to CNAME suffix match against a curated "common FQDNs" list (`cloudfront.net`, `akamaiedge.net`, `cloudflare.com`, `fastly.net`, `impervadns.net`, plus many Chinese providers like `wsglb0.com`, `tencdns.net`, `qcloudwaf.com`).

## Internal architecture (file-level, main branch as of May 2026)

- **`cdncheck.go`** (~200 LOC) — top-level `Client` struct: three `providerScraper` instances (cdn, waf, cloud) + a `*retryabledns.Client` for domain resolution. `New()` / `NewWithOpts(maxRetries, resolvers)`. Methods: `CheckCDN(ip)`, `CheckWAF(ip)`, `CheckCloud(ip)`, `Check(ip)` (tries all three in order), `CheckDomainWithFallback(domain)` (resolve → check IP → fallback CNAME → suffix-match), `CheckDNSResponse(dnsData)` (works on a pre-fetched `retryabledns.DNSData`). IPv6 connectivity is auto-detected at `init()` time and IPv6 resolvers are added only if available.
- **`types.go`** (~60 LOC) — `InputCompiled { CDN, WAF, Cloud, Common: map[string][]string }`. `providerScraper { rangers: map[provider_name]*bart.Table[net.IP] }`. **Uses `gaissmai/bart` for binary-trie radix lookup** (much faster than naive iteration; longest-prefix match in O(log n) — actually closer to O(W) where W = address width). `Match(ip)` iterates providers and uses `ranger.Lookup(parsed)` (returns `(value, contains_bool)`).
- **`other.go`** — alternate detection paths: `CheckSuffix(fqdns...)` checks domain-suffix against a one-time-initialized `suffixToSource map[string]string` derived from `generatedData.Common`; uses `weppos/publicsuffix-go` to split into TLD/SLD properly. `CheckWappalyzer(tech_map)` matches Wappalyzer technology names → CDN providers (`imperva`, `incapsula`, `cloudflare`, `cloudfront`, `akamai`).
- **`sources_data.go`** — `var generatedData *InputCompiled` populated from `sources_data.json` (embedded JSON). Generated by `cmd/generate-index/`.
- **`sources_data.json`** (~hundreds of KB) — the compiled IP-range dataset. Auto-refreshed weekly by GitHub Actions (`Weekly fingerprints update [Sun ... UTC]`).
- **`cmd/generate-index/`** — the *dataset generator*.
  - `provider.yaml` (~726 LOC) — the **source-of-truth** declaring providers + how to fetch their CIDRs. Three top-level keys (`cdn`, `waf`, `cloud`) each with three sub-keys (`asn`, `urls`, `cidr`) + a `common` section with `fqdn` for CNAME-suffix matching. Hand-curated.
  - `main.go` — runs the generator: for each `urls` entry, HTTPs GET, regex-extract CIDRs from response body (`cidrRegex` is a monster RE matching both v4 and v6 CIDR notation); for each `asn` entry, queries IPinfo (requires `IPINFO_TOKEN`) for that ASN's prefix list; for each `cidr` entry, uses as-is. Output: `sources_data.json` (committed by Actions).
- **`generate/`** — helper for the generator.
  - `input.go` — `Categories.Compile(options)` returns `InputCompiled`. Fetches URLs, regex-extracts CIDRs (with hard-coded retry on `403 Forbidden`), queries IPinfo for ASN expansion, merges custom scrapers (from `ranges.go`).
  - `ranges.go` — `scraperTypeToScraperMap` per-provider custom scrapers (for providers whose URL serves HTML, not JSON/text — uses `PuerkitoBio/goquery` to extract).
  - `options.go`, `types.go` — `Options { IPInfoToken }`, `Categories { CDN, WAF, Cloud, Common }`.
- **`cmd/cdncheck/main.go`** — CLI entrypoint.
- **`internal/runner/`** — CLI orchestration.
  - `options.go` — `goflags` parser; ~25 flags (input, detection-type filter, match/filter per-category, output, resolvers).
  - `runner.go` — `Runner` wraps `cdncheck.Client`. `Run()` spawns 2 goroutines: `process()` reads inputs (stdin/CLI list/file) and pushes to output chan; `waitForData()` drains chan, applies match/filter, writes to OutputWriter, prints summary `Found result: 42 (CDN: 30, CLOUD: 8, WAF: 4)`. CIDR inputs are expanded via `mapcidr.IPAddressesAsStream`.
  - `output-writer.go`, `banner.go`.
- **`other_test.go`, `cdncheck_test.go`** — unit tests against known-CDN IPs.
- **`examples/simple.go`** — `cdncheck.New(); matched, value, itemType, err := client.CheckDomainWithFallback("acme.com")`.
- **Concurrency model.** Single-threaded per input (each Check is fast — trie lookup ≈ 1µs). Only async work is the optional DNS resolution. CLI runner has 2 goroutines (input + output) for streaming.
- **Total LOC.** ~1500 Go core + ~700 LOC YAML data + auto-generated JSON.
- **2024-2026 trends.**
  - **Weekly automated refresh.** Since 2023, GitHub Action runs every Sunday — re-fetches all `urls` entries, regenerates `sources_data.json`, commits, bumps minor version. This is critical: an out-of-date dataset is the #1 source of false-negatives.
  - **Migration to `gaissmai/bart` from `yl2chen/cidranger`** somewhere in 2024 — bart's binary-trie is ~2× faster on large datasets and uses less memory.
  - **Korea-focused providers added 2024.** `cdnetworks`, `kinx`, `lgtelecom`, `skbroadband`, `cafe24` — large Korean cloud/CDN players largely absent from Western tools.
  - **Chinese providers expanded.** `阿里云`, `腾讯云`, `网宿`, `加速乐`, etc. — covers China-only deployments.
  - **No major architectural changes 2024-2026.** Stable, mature project.

## Granular feature list

1. `-input 1.2.3.4,acme.com` (`-i`) — comma-separated, file (via `FileCommaSeparatedStringSliceOptions`), or stdin.
2. `-cdn` — only show entries detected as CDN.
3. `-cloud` — only show entries detected as Cloud.
4. `-waf` — only show entries detected as WAF.
5. `-match-cdn cloudflare,fastly` (`-mcdn`) — only show CDN matches of specific providers.
6. `-match-cloud aws,gcp` (`-mcloud`) — same for cloud.
7. `-match-waf cloudflare,incapsula` (`-mwaf`) — same for WAF.
8. `-filter-cdn cloudflare` (`-fcdn`) — exclude matches.
9. `-filter-cloud aws` (`-fcloud`) — exclude.
10. `-filter-waf akamai` (`-fwaf`) — exclude.
11. `-resp` — display the detected provider name in output (default just shows input).
12. `-output out.txt` (`-o`) — file output.
13. `-jsonl` (`-j`) — JSON-lines.
14. `-no-color` (`-nc`) — disable color.
15. `-silent` — output only.
16. `-verbose` (`-v`) / `-version` — display.
17. `-resolver 1.1.1.1,8.8.8.8` (`-r`) — custom DNS resolvers (overrides defaults).
18. `-exclude` (`-e`) — *invert* output: print only IPs that did NOT match anything (useful for finding origin IPs behind a CDN-protected zone).
19. `-retry 2` — DNS resolution retries.
20. `-debug` — debug output.
21. **CIDR input.** Any CIDR like `1.2.3.0/24` gets expanded via `mapcidr.IPAddressesAsStream` (streaming so /8 doesn't OOM); each IP checked individually.

**Hidden / programmatic features (library only):**
- **`CheckDomainWithFallback(domain)`** — resolves domain to A/AAAA, checks each IP, then if nothing matched, queries CNAME and runs `CheckSuffix()` against the CNAME chain.
- **`CheckDNSResponse(dnsResponse)`** — for use when caller already has `retryabledns.DNSData` (avoids duplicate DNS work; used by naabu and dnsx).
- **`CheckWappalyzer(map[string]struct{})`** — given a Wappalyzer-style technology detection result, infer CDN. Used by httpx.
- **`CheckSuffix(fqdns...)`** — exposed for callers that have CNAME data.
- **Auto IPv6 detection.** At package `init()` time, `checkIPv6Connectivity()` does a 3-sec UDP dial to `[2001:4860:4860::8888]:53`; if it succeeds, IPv6 resolvers are added to the default pool.

## Engineering hard parts

1. **The dataset is the product.** The Go code is ~1500 LOC; the value is the curated `provider.yaml` + auto-fetched `sources_data.json`. Cloning the code is easy; clone the *update pipeline* is hard. You must replicate the GitHub Actions weekly job (or use cdncheck's published `sources_data.json` directly, accepting upstream dependency).
2. **IP-range data sources change format.** AWS publishes JSON (`{"prefixes":[{"ip_prefix":"1.2.3.0/24","region":"us-east-1","service":"AMAZON"}]}`) but other providers serve HTML, TXT, or even XML-wrapped data. Each scraper is a special snowflake. `cidrRegex` is generic but loose — false positives possible.
3. **ASN-based detection requires IPinfo paid token.** Free Akamai detection without it is incomplete because Akamai doesn't publish CIDRs (they publish ASN `AS20940`, `AS16625`, etc.). Without IPinfo you miss ~30% of Akamai hosts.
4. **CNAME-suffix detection has false-positives.** `*.cloudfront.net` — if a CNAME points at `legitimate-but-deleted-distribution.cloudfront.net`, it still matches CloudFront. Doesn't mean the *current* destination is CloudFront. (Could even be a takeover candidate.) For takeover hunting this is a *feature*; for "is this Cloudflare-protected right now" it's a false-positive risk.
5. **Trie lookup vs naive iteration.** Naive: loop over all 50,000+ CIDRs per query — O(n) per lookup → 50ms × N inputs = slow at scale. Trie (`bart` in Go; `prefix-trie` or `ipnet-trie` in Rust): O(W) ≈ microseconds. Mandatory for any meaningful scale.
6. **AWS service annotation.** `ip-ranges.json` annotates each prefix with `service` (S3, EC2, AMAZON, CLOUDFRONT, ROUTE53). cdncheck flattens this to "aws" — but you might want finer-grain ("this IP is S3, not EC2 — different attack surface").
7. **IPv6 lookups are sparser.** Many providers don't publish v6 ranges, or only do so partially. False-negative rate on v6 is higher.
8. **WAF detection is heavily heuristic.** WAFs don't always have unique CIDRs (e.g., Imperva is partially CIDR + partially CNAME suffix). For cloud WAFs (AWS WAF, Cloudflare WAF, Azure FrontDoor) the WAF is in the CDN edge — IP alone can't distinguish "Cloudflare CDN no WAF" vs "Cloudflare CDN with WAF". cdncheck conservatively returns "cdn" for these; another tool (wafw00f-style HTTP probe) is needed for WAF/no-WAF.
9. **Provider name collisions.** `google` appears in both CDN (gcore via Google) and Cloud (GCP). Output must distinguish.
10. **Korean / Chinese providers.** `provider.yaml` includes Unicode keys (`百度云加速`, `腾讯云`). UTF-8 handling in the Rust port must be correct.

## Rust library mapping

| Original Go component | Recommended Rust crate | Version | Notes |
| --- | --- | --- | --- |
| `goflags` | `clap` (derive) | 4.5.x | — |
| `gologger` | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | — |
| `gaissmai/bart` (binary trie) | **`prefix-trie`** | 0.4.x | Best LPM in Rust 2026: TreeBitMap-style trie, supports both `ipnet` and `ipnetwork`. Lookup ~50ns. Memory-efficient. |
| Alternate trie | `ipnet-trie` | 0.4 | Wraps `prefix-trie`, more ergonomic for `ipnet::IpNet` storage. |
| `net.ParseIP` / `netip.ParsePrefix` | `std::net::IpAddr` + `ipnet::IpNet` | 2.10.x | std handles parse; `ipnet` adds `Ipv4Net::contains`, `hosts()`. |
| `mapcidr.IPAddressesAsStream` | `ipnet::Ipv4Net::hosts()` iter (lazy) | 2.10 | Returns iterator; for /8 use `.take(N)` to chunk. |
| `retryabledns` (resolve A/CNAME) | `hickory-resolver` | 0.24 | Default pool: Cloudflare/Google/Quad9/OpenDNS UDP + v6 resolvers when v6 reachable. |
| `weppos/publicsuffix-go` | **`publicsuffix`** (crate) | 2.2.x | PSL parsing → split into TLD/SLD/subdomain for CNAME-suffix matching. |
| `serde_json` (load embedded JSON) | `serde_json` | 1.0 | Load `sources_data.json` at startup via `serde_json::from_str(include_str!("sources_data.json"))`. |
| `serde_yaml` (load `provider.yaml`) | `serde_yml` (maintained YAML 1.2 fork) | 0.0.12 | Only used by generator binary. |
| `PuerkitoBio/goquery` (HTML scrape) | `scraper` or `tl` | 0.20 / 0.7 | Only used by generator. |
| `ipinfo/go` (ASN expansion) | `reqwest` direct call to `https://ipinfo.io/AS{n}/json?token=...` | 0.12 | Only used by generator. No need for SDK. |
| `aurora` (color) | `colored` or `nu-ansi-term` | 2.1 / 0.50 | — |
| Embedded data | `include_str!("sources_data.json")` | — | Compile-time embed; ~hundreds KB JSON. |
| Disk update cache | `directories` crate for `~/.local/share/lancercdn/` + manual download | 5.0 | For `update` subcommand. |
| HTTP fetch (generator) | `reqwest` | 0.12 | — |

## Data sources (the IP-range dataset)

| Provider | Type | URL / ASN | Notes |
| --- | --- | --- | --- |
| **CDN providers** | | | |
| Cloudflare | URL | `https://api.cloudflare.com/client/v4/ips` (v4+v6) | Listed in **WAF** category in upstream `provider.yaml` (Cloudflare is CDN+WAF). |
| CloudFront | URL | `https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips` (also in AWS `ip-ranges.json` filtered by `service:"CLOUDFRONT"`) | Listed in CDN category. |
| Fastly | URL | `https://api.fastly.com/public-ip-list` (v4+v6) | |
| Google (gcore / CDN) | URL | `https://api.gcore.com/cdn/public-ip-list`, `https://www.gstatic.com/ipranges/goog.json` | |
| Akamai | ASN | `AS20940`, `AS16625`, `AS35994`, `AS17204`, etc. via IPinfo | No CIDR list published — must expand ASNs. |
| Leaseweb | ASN | `AS60626` | |
| Qrator | ASN+CIDR | `AS197068`, `AS200449`, `AS51115` + hardcoded CIDRs (`66.110.32.128/30`, `83.234.15.112/30`, etc.) | |
| Arvancloud (Iran) | ASN+URL | `AS208006`, `AS205585`, `https://www.arvancloud.ir/fa/ips.txt` | |
| Gcore | URL | `https://api.gcore.com/cdn/public-ip-list` | |
| Cdnetworks (Korea) | CIDR | Hardcoded (~20 CIDRs) | |
| Cafe24 (Korea) | CIDR | `14.128.128.0/17` | |
| Gocache | CIDR+URL | Hardcoded + `https://gocache.com.br/ips` | |
| Kinx (Korea) | CIDR | Hardcoded | |
| Lgtelecom (Korea) | CIDR | `180.210.192.0/21`, `203.82.240.0/21` | |
| Skbroadband (Korea) | CIDR | Hardcoded | |
| 百度云加速 (Baidu CDN, China) | CIDR | Hardcoded large list | |
| 腾讯云 (Tencent CDN, China) | CIDR | Hardcoded | |
| 加速乐 (JiaSule CDN, China) | CIDR | Hardcoded | Confirmed present in upstream `provider.yaml` (2024-2026). |
| 云盾 (Yundun CDN, China) | CIDR | Hardcoded | Confirmed present in upstream `provider.yaml`. |
| **Gaps vs Lancer roadmap (not in upstream as of v1.2.37 May 2026 — Lancer ports them ourselves)** | | | |
| **Bunny.net CDN** | URL | `https://bunny.net/api/system/ips` (planned scraper) | 2026's fastest-growing low-cost CDN. ~5% global share. Critical gap. |
| **Vercel Edge Network** | ASN+CIDR | `AS17064` (Vercel) + `vercel.com` published v4 ranges | Next.js / React deployments — huge bug bounty surface. |
| **Netlify Edge** | ASN+CIDR | `AS54113` (Netlify) + CIDRs | Jamstack hosts; widely fronted. |
| **Cloudflare R2 / Workers** | (same as Cloudflare CIDRs) | distinguish via header `cf-ray` + path | R2 buckets have distinct subdomain pattern (`*.r2.cloudflarestorage.com`). |
| **Tencent EdgeOne** | URL | `https://api.edgeone.ai/iplist` | Next-gen Tencent WAF+CDN combo (2024 launch). |
| **VolcEngine CDN (ByteDance)** | CIDR | Hardcoded large list | ByteDance/TikTok infra, China-only — large gap. |
| **Huawei Cloud CDN + WAF** | URL | `https://developer.huaweicloud.com/ip-ranges` | Major China-cloud, growing internationally. |
| **JD Cloud CDN (京东云)** | CIDR | Hardcoded | Chinese e-commerce cloud. |
| **KeyCDN** | URL | `https://www.keycdn.com/network/ips` | StackPath alternative; growing. |
| **CacheFly** | URL | hardcoded + `https://www.cachefly.com/ips/` | One of the oldest CDNs, still active. |
| **BunnyCDN ASN** | ASN | `AS200325` | for ASN-fallback. |
| **Lumen / CenturyLink / Level3 CDN** | ASN | `AS3356`, `AS209` | Enterprise CDN — major gap in upstream. |
| **CDN77** | URL | `https://www.cdn77.com/network` | EU-popular CDN. |
| **Medianova** | CIDR | Hardcoded | Turkish/EU CDN. |
| **Edgio (formerly Limelight/Verizon Edgecast)** | ASN | `AS22822` | Verizon Edgecast rebrand 2024. |
| **AryakaCDN** | ASN | `AS199340` | Enterprise/SD-WAN CDN. |
| **StackPath (legacy, defunct 2024)** | (sunset) | — | Removed Q3 2024 — many records still resolve; keep historical CIDRs for takeover detection. |
| **WAF providers** | | | |
| Cloudflare | URL | `https://api.cloudflare.com/client/v4/ips` (+ IPinfo widget mirror) | Upstream uses both `api.cloudflare.com` and `ipinfo.io/widget/demo/cloudflare.com?dataset=ranges` to dual-source. |
| Akamai | ASN | Same as CDN (37 ASNs total per upstream `provider.yaml`) | |
| Sucuri | ASN | `AS30148` | |
| Incapsula (Imperva) | CNAME suffix | `impervadns.net` (in `common.fqdn`) | |
| Arvancloud | (same) | | |
| **Gaps vs Lancer roadmap — WAF additions** | | | |
| **AWS WAF** | (lives behind CloudFront/ALB) | header: `x-amzn-RequestId`, `x-amz-cf-id` + status 403 on malicious | Lancer adds via HTTP-fingerprint mode (Phase 6). |
| **Azure Front Door + Azure WAF** | URL | Azure XML download `id=56519` (filter `AzureFrontDoor.Frontend`) | Currently lumped into Azure cloud. Split out in Lancer. |
| **F5 BIG-IP / Distributed Cloud (Shape Security)** | Headers + ASN | `AS55002` (F5 Networks) + cookie `TS01...` / `F5_*` | HTTP-probe only. |
| **Fortinet FortiWeb** | Headers | `Server: FortiWeb` + ASN `AS40934` | Enterprise. |
| **Barracuda WAF** | Headers + ASN | `barra_counter_session` cookie + `AS15095` | |
| **Wallarm** | Headers | `nginx-wallarm` / `wallarm-mode` headers | Cloud + on-prem WAF. |
| **ModSecurity / OWASP CRS** | Headers | `Server: Apache/nginx` + `mod_security` blocks | Generic; HTTP probe + 403 weird-path heuristic. |
| **Reblaze** | ASN | `AS35506` | Israeli WAF/bot mitigation. |
| **PerimeterX / HUMAN** | Headers/cookie | `_px3`, `_pxhd`, `_pxvid`, `pxcdn` | Bot-protection — see §Bot-protection extension Phase 7. |
| **DataDome** | Headers/cookie | `datadome` cookie, `x-datadome-*`, header `X-DataDome-*` | Bot-protection. |
| **Kasada** | Headers/cookie | `x-kasada-*`, `kpsdk-*` | Bot-protection. |
| **Akamai Bot Manager** | Headers | `_abck`, `ak_bmsc`, `bm_sz` cookies | Layered on Akamai CDN. |
| **Wordfence / Sucuri-Lite** | Headers | `Server: Sucuri/Cloudproxy` (already partial) | Common SMB WAF; CIDR partial. |
| **NSFOCUS WAF (绿盟云)** | FQDN suffix | already partial in `common.fqdn` | Confirmed in upstream `common.fqdn` (绿盟云 WAF). |
| **奇安信网站卫士 (QiAnXin WAF)** | FQDN suffix | already in `common.fqdn` | Confirmed in upstream. |
| **华为云 WAF (Huawei WAF)** | FQDN suffix | already in `common.fqdn` | Confirmed in upstream. |
| **深信服云盾 (Sangfor WAF)** | FQDN suffix | already in `common.fqdn` | Confirmed in upstream. |
| **安恒玄武盾 (DBAPPSecurity XuanWu)** | FQDN suffix | already in `common.fqdn` | Confirmed in upstream. |
| **Cloud providers** | | | |
| AWS | URL | `https://ip-ranges.amazonaws.com/ip-ranges.json` | Filter by `service:"AMAZON"` for general (excludes S3/CloudFront which have their own). |
| GCP / Google Cloud | URL | `https://www.gstatic.com/ipranges/cloud.json` | |
| Azure | URL | `https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519` (XML download — awkward; usually scraped manually) and `https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7` (O365 endpoints) | |
| Oracle | URL | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` | |
| Zscaler | URL | `https://api.config.zscaler.com/zscaler.net/cenr/json` | |
| Office365 | URL | `https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7` | Confirmed in upstream `provider.yaml`. |
| **Gaps vs Lancer roadmap — Cloud additions** | | | |
| **DigitalOcean** | URL | `https://www.digitalocean.com/geo/google.csv` | Huge gap — DO hosts millions of VPS. CSV format. |
| **Linode / Akamai Connected Cloud** | URL | `https://geoip.linode.com/` (CSV) | Acquired by Akamai 2022, now overlaps. |
| **Vultr** | URL | `https://geofeed.constant.com/?text` | Popular VPS cloud. |
| **Hetzner** | URL | `https://docs.hetzner.com/cloud/general/locations/ip-ranges/` | Major EU VPS. |
| **OVHcloud** | ASN | `AS16276` | French/EU mega-cloud. |
| **Tencent Cloud (general)** | URL | `https://en.intl.cloud.tencent.com/document/product/213/17156` | Distinct from Tencent CDN. |
| **Alibaba Cloud** | URL | `https://ipinfo.io/AS45102/json` (Alibaba US) + `AS37963` (China) | Largest non-Western cloud. |
| **Huawei Cloud (general)** | URL | published v4/v6 | Major China-cloud growth 2024-2026. |
| **IBM Cloud / SoftLayer** | ASN | `AS36351` (SoftLayer) + URL | Enterprise. |
| **DigitalRealty / Equinix Metal** | ASN | `AS393495`, `AS22822` | Bare-metal cloud. |
| **Fly.io** | ASN | `AS47853` | Edge-app cloud (rising 2024-2026). |
| **Render** | ASN | (varies) | PaaS popular 2024+. |
| **Railway** | ASN | (varies) | PaaS popular 2024+. |
| **Heroku (Salesforce)** | URL | `https://api.heroku.com/ip-ranges` | Common takeover target via `*.herokuapp.com` / `*.herokudns.com`. |
| **Backblaze B2** | URL | `https://www.backblaze.com/network` | S3-alternative; `*.backblazeb2.com`. |
| **Wasabi Cloud Storage** | URL | published v4 ranges | S3-alternative. |
| **Tencent COS (Object Storage)** | URL | (region-list endpoints) | Tencent S3 equivalent. |
| Gabia (Korea) | CIDR | Hardcoded | |
| Hostway (Korea) | CIDR | Hardcoded | |
| KT Cloud (Korea) | CIDR | Hardcoded | |
| Naver Cloud (Korea) | CIDR | Hardcoded (large list) | |
| NHN Cloud (Korea) | CIDR | Hardcoded (large list) | |
| Arvancloud | (same) | | |
| **Common FQDNs (CNAME-suffix detection)** | | | |
| amazon | `cloudfront.net`, `amazonaws.com` | |
| akamai | `edgekey.net`, `akamaiedge.net`, `akamaitechnologies.com`, `akamaihd.net`, `edgesuite.net` | |
| cloudflare | `cloudflare.com` | |
| fastly | `fastly.net` | |
| edgecast | `edgecastcdn.net`, `edgesuite.net` | |
| incapsula | `impervadns.net` | |
| qrator | `qrator.net` | |
| arvancloud | (various) | |
| 阿里云 CDN (Alibaba) | `kunlunpi.com`, `alikunlun.com`, `kunlunea.com`, `kunlunca.com`, `yundunwaf3-5.com`, `cdngslb.com`, `alicloudwaf.com` | |
| 腾讯云 CDN | `cdn.dnsv1.com`, `qcloudcjgj.com`, `qcloudwzgj.com`, `qcloudzygj.com`, `qcloudwaf.com`, `cdntip.com`, `dnsv1.com`, `tencdns.net`, `tdnsv5.com` | |
| 网宿 CDN (ChinaCache) | `wsdvs.com`, `lxdns.com`, `wswebcdn.com`, `wsglb0.com`, etc. (large list) | |
| 加速乐 (JiaSule) | `cname.365cyd.cn`, `cdn.jiashule.com`, `vip.jiasule.org` | |
| 又拍云 (Upyun) | `aicdn.com` | |
| 白山云 (Baishan) | `bsgslb.cn`, `qingcdn.com`, `trpcdn.net`, `bsclink.cn` | |
| 云盾 (Yundun) | `yunduncdn.com` | |
| 360 云加速 / 360 云 CDN | `qh-cdn.com`, `qihucdn.com`, `qh-cdn.cn`, `360wzb.com` | Confirmed in upstream `common.fqdn` (two variants). |
| 七牛云 (Qiniu) | `qbox.me`, `qiniudns.com`, `qnssl.com`, `clouddn.com` | Confirmed in upstream. |
| 京东云 CDN (JD Cloud) | `jdcdn.com`, `jcloudcs.com`, `jcloud-cdn.com` | Confirmed in upstream. |
| 帝联 CDN (DiLian) | `chinanetcenter.com`, `customcdn.cn`, `customcdn.com` | Confirmed in upstream. |
| 广东网堤 CDN | `wangsu.com` derivatives | Confirmed in upstream. |
| 美橙 CDN (Meichuang) | `cdnmytags.cn` | Confirmed in upstream. |
| 网神 CDN (NetThinker) | various | Confirmed in upstream. |
| 蓝盾云 CDN (LanDun) | various | Confirmed in upstream. |
| 腾正安全加速 (TengZheng) | various | Confirmed in upstream. |
| **Lancer-additions (not yet upstream, planned for Phase 2)** | | |
| Bunny.net | `b-cdn.net`, `bunnycdn.net`, `bunny.net` | 5%+ global share, missing in upstream. |
| Vercel | `vercel.app`, `vercel-dns.com`, `cname.vercel-dns.com` | Next.js standard host. |
| Netlify | `netlify.app`, `netlify.com`, `nlf.fans` | Jamstack standard. |
| Render | `onrender.com`, `render.com` | |
| Fly.io | `fly.dev`, `fly.io` | |
| Railway | `railway.app`, `up.railway.app` | |
| Heroku | `herokuapp.com`, `herokudns.com`, `herokussl.com` | High takeover-detection value. |
| Backblaze B2 | `backblazeb2.com`, `s3.us-west-002.backblazeb2.com` | |
| Wasabi | `wasabisys.com`, `s3.wasabisys.com` | |
| Tencent EdgeOne | `edgeone.app`, `edgeonepre.com` | |
| Huawei Cloud | `myhwcdn.cn`, `myhwcloud.com`, `dayu.com` | |
| GitHub Pages | `github.io`, `githubpages.com` | Critical for subdomain takeover. |
| GitLab Pages | `gitlab.io` | |
| Vercel Edge | `now.sh` (legacy alias) | |
| Pantheon | `pantheonsite.io` | |
| WP Engine | `wpengine.com`, `wpenginepowered.com` | |
| Shopify | `myshopify.com` | |
| Squarespace | `squarespace.com` | |
| (Several more Chinese CDN providers) | | |

## Detection methods (extended for Lancer)

Upstream cdncheck uses four detection signals: (1) IPv4/IPv6 CIDR-trie match, (2) ASN match (via IPinfo expansion at generate-time), (3) CNAME suffix match against `common.fqdn`, (4) Wappalyzer technology name match. Lancer adds five more — *required* to close 2024-2026 coverage gaps:

1. **HTTP response-header fingerprint (Phase 6).** WAFW00F-style probe — `HEAD /` + a 404-bait weird path. Required for: AWS WAF (CIDR-invisible), Cloudflare WAF vs Cloudflare CDN distinction, F5 BIG-IP, Fortinet FortiWeb, Barracuda, ModSecurity, Imperva (HTTP layer), Wallarm.
2. **Cookie / Set-Cookie fingerprint.** Required for bot-protection layer: `datadome`, `_pxhd`/`_px3` (PerimeterX/HUMAN), `kpsdk-*` (Kasada), `_abck`/`bm_sz` (Akamai Bot Manager), `__cf_bm` (Cloudflare BM), `__cflb`, `TS01...`/`F5_*` (F5).
3. **TLS JA3/JA4 fingerprint.** Modern WAFs/bot-protection inspect TLS ClientHello. Reverse: hitting endpoint with `ja3` library, compare against known WAF JA3 hashes (DataDome, Kasada, Akamai BM all have distinctive TLS termination fingerprints). Phase 7 add-on.
4. **TXT/SPF DNS record fingerprint.** Many cloud providers expose themselves via SPF (`v=spf1 include:_spf.salesforce.com`, `include:spf.sendgrid.net`, `include:_spf.google.com`). Useful when CNAME/A unhelpful.
5. **NS record fingerprint.** `*.cloudflare.com`, `*.awsdns-*.org`, `*.azure-dns.com`, `*.googledomains.com`, `*.nsone.net` (NS1), `*.dnsimple.com`. Identifies authoritative DNS provider — often correlates with hosting choice and gives takeover hints.

**Confidence scoring (new in Lancer).** Each detection emits `(provider, category, signal_type, confidence_pct)`. Signals combine: CIDR + CNAME + header → 99%; CIDR alone → 80%; CNAME alone → 60%; header alone → 50%; ASN alone → 40%. Per-record `Detection.signals: Vec<Signal>` so caller can inspect.

**Multi-provider stack inference.** Real targets often layer e.g. "Cloudflare CDN + DataDome bot + Imperva WAF behind". Lancer emits *all* layers detected, not just first match (upstream returns first hit and stops). Output schema includes `protection_stack: Vec<Provider>`.

## 2024-2026 state

- **The dataset gets weekly refresh** via GitHub Actions auto-commit. No manual user action needed.
- **CDN landscape in 2026.** Cloudflare dominates ~30%, CloudFront ~20%, Fastly+Akamai ~15% each, the rest fragmented. Bot-protection-as-a-service (DataDome, Kasada, PerimeterX) emerging — *not yet* well-covered by cdncheck's CIDR approach because they front via Cloudflare/CloudFront infrastructure.
- **Alternative: BlackLanternSecurity's CloudCheck** (Rust). Pivots from CIDR-hardcoding to *Internet Registry IDs* — claims to detect brand-new ASNs as they're spun up. Different model: queries `ASNDB` REST API at runtime instead of compile-time embedding. Trade-off: faster fingerprint updates but requires network at every lookup. Bug-bounty hunters split between cdncheck (offline, fast) and CloudCheck (fresh).
- **IPinfo IP Privacy Detection.** Commercial product detects VPNs/proxies/Tor at lookup time. Some recon workflows blend it with cdncheck output ("CDN = Cloudflare, Privacy = TorExit" → high suspicion).
- **No big competitor stole subfinder-style mindshare.** cdncheck is the standard library for this category in 2026, embedded directly in naabu, dnsx, httpx.
- **Performance benchmarks.** cdncheck lookup is ~1µs per IP with bart trie. Domain check adds DNS RTT (~30ms). At 1M IPs/sec single-threaded (trivial to parallelize).
- **Community sentiment.** "If you're not using cdncheck somewhere in your pipeline, you're scanning Cloudflare edge servers for nothing."

### Deep-research update — 2026-05-30

Direct read of upstream `cdncheck` (v1.2.37, latest release dated 2026-05-24, 91 total releases) + `cmd/generate-index/provider.yaml`. Findings:

- **Upstream is still narrow on Western "modern" CDNs.** The README's marketed coverage matrix lists only `cloudfront / fastly / google / leaseweb / akamai` (CDN), `aws / google / oracle` (cloud), `cloudflare / incapsula / sucuri / akamai` (WAF). **Bunny.net, Vercel, Netlify, KeyCDN, CacheFly, CDN77, Edgio (Verizon Edgecast rebrand), Lumen/Level3, Render, Fly.io, Railway, Heroku, DigitalOcean, Linode, Vultr, Hetzner, OVHcloud, IBM Cloud, Fly.io, Backblaze B2, Wasabi are all absent** from upstream's coverage. Lancer ports these in Phase 2 / Phase 6 via new `provider.yaml` rows + new FQDN suffixes (see additions above).
- **Bunny.net is the single biggest 2024-2026 miss.** Now ~5% global CDN share, cheapest serious option (~$0.005/GB), and growing fast on cost-sensitive web hosting. Any modern recon pipeline misses 1-in-20 hosts without it.
- **Edgio (formerly Verizon Edgecast / Limelight) merged 2023, rebranded 2024.** Upstream `common.fqdn` still lists only legacy `edgecastcdn.net`/`edgesuite.net`. Lancer adds `edg.io`, `edgesuite.com`, `lldns.net`.
- **Bot-protection-as-a-service is genuinely uncovered.** DataDome, Kasada, HUMAN (PerimeterX rebrand 2022), Akamai Bot Manager, Reblaze, Shape Security (now F5 Distributed Cloud) all front via existing CDN CIDRs — CIDR-only detection misses them 100%. Lancer Phase 6 (HTTP probe) + Phase 7 (cookie/header fingerprint) close this. References: DataDome trust-score model uses 35+ signals/session; identification via the `datadome` cookie or `x-datadome-*` headers is reliable per Antibot Detector (Scrapfly 2026 ranking).
- **Modern China/Asia gap is partially covered already.** Upstream `common.fqdn` does include 360 云加速, 七牛云, 京东云 CDN, 帝联, 广东网堤, 美橙, 网神, 蓝盾云, 腾正安全加速, 绿盟云 WAF, 奇安信网站卫士, 华为云 WAF/CDN, 深信服云盾, 安恒玄武盾 — re-confirmed against upstream YAML; existing plan undersold this. **But Tencent EdgeOne (2024 launch) and VolcEngine CDN (ByteDance) are missing.**
- **No new top-level CLI flags 2024-2026.** v1.2.x has been pure dataset bumps + minor lib changes — the public CLI surface (and the ~25 flags enumerated in the Granular feature list above) remains stable. Parity contract is achievable.
- **Cloudflare dual-source via IPinfo widget.** Upstream now fetches Cloudflare CIDRs from BOTH `api.cloudflare.com/client/v4/ips` AND `ipinfo.io/widget/demo/cloudflare.com?dataset=ranges` (newly added 2024-2025). Lancer's `update` subcommand must mirror this for resilience.
- **`cdncheck --self-test` parity matrix.** Add the additional providers above as test vectors (one known IP per provider) so CI fails if Lancer regresses against any modern Western CDN that upstream still doesn't ship.

References reviewed: upstream README & `provider.yaml` (main branch, 2026-05); v1.2.37 release notes; DeepWiki cdncheck index; commercial bot-protection landscape reviews (DataDome / Kasada / HUMAN, Scrapfly 2026 ranking); CDN market share reports (Bunny.net 2026 positioning).

## Real-world pipeline patterns

```bash
# Single-shot: is this IP CDN?
echo 104.21.1.1 | cdncheck -resp -silent
# → 104.21.1.1 [cdn] [cloudflare]

# Domain check
echo acme.com | cdncheck -resp -silent

# Find origin IPs (NOT behind CDN) for a sub list
cat subs.txt | dnsx -a -resp-only -silent \
  | cdncheck -exclude -silent
# → only IPs that didn't match any CDN/WAF/Cloud → likely origin IPs

# Skip CDN hosts before port-scanning (canonical)
cat hosts.txt | dnsx -a -resp-only -silent | cdncheck -exclude -silent \
  | naabu -top-ports 1000 -silent

# Per-category filtering
cat ips.txt | cdncheck -match-cloud aws -resp
# → only AWS-cloud IPs (good for AWS-bug research)

# WAF-fronted target list
cat hosts.txt | cdncheck -match-waf cloudflare,incapsula -resp

# CIDR enumeration
echo 13.32.0.0/16 | cdncheck -resp -silent  # AWS CloudFront /16

# Library use (Go)
client := cdncheck.New()
matched, value, itemType, err := client.CheckDomainWithFallback("acme.com")
```

**Failure modes:**

- **Out-of-date dataset.** If you embedded `sources_data.json` 6 months ago and a CDN added a new /16, you'll false-negative on that range. Set up a weekly refresh job or auto-pull at startup.
- **Cloudflare Workers behind a custom domain.** A user-purchased domain on Cloudflare resolves to Cloudflare IPs — cdncheck correctly says CDN. But the *origin* (the Worker) is *also* Cloudflare. There is no "origin IP" to find — it's serverless. cdncheck can't tell you that.
- **Bot-protection-as-a-service (DataDome / Kasada).** These services don't always have their own CIDRs; they front via Cloudflare/CloudFront. cdncheck will return "CDN: cloudflare" but miss the bot-protection layer. Need a separate fingerprint (response headers).
- **IPv6 false-negatives.** Less complete v6 data → more "not matched" for v6 IPs.

## Bug bounty value + AI augmentation ideas

**Why a hunter cares in 2026.**

cdncheck answers two binary decisions that cascade through your entire recon:

1. **Should I full-port scan this?** No, if CDN/WAF: only scan 80/443. Saves 99% of scan time.
2. **Should I try WAF bypass first?** Yes, if WAF detected: the direct host is shielded — your input never reaches the origin app. Common bypass techniques: subdomain takeover of `direct.acme.com` (often points at non-CDN), historical IPs from `securitytrails`/`shodan`, SSRF-based egress, DNS history.

**Bug classes the output enables:**

- **WAF bypass** (the bypass research only makes sense once you've identified there's a WAF to bypass).
- **Origin IP discovery** (`-exclude` mode finds the unprotected origin behind a CDN-fronted zone).
- **Subdomain takeover** (CNAME suffix matches against `*.s3.amazonaws.com` → check if bucket exists; against `*.github.io` → check if repo exists; against `*.herokudns.com` → check if app exists).
- **Cloud-misconfig hunting** prioritization (host on AWS → look for IMDS SSRF, S3 misconfigs; on Azure → Azure Storage public containers, etc.).

**AI augmentation opportunities (Lancer differentiator):**

1. **Origin-IP candidate ranker.** For a CDN-protected target, feed the historical IPs (from passive DNS — SecurityTrails, ShadowServer, Shodan) to Claude with context "Which of these is the most likely current origin IP behind Cloudflare?" Output ranked candidates (older + less Cloudflare-tied → higher rank).
2. **Takeover candidate triage.** When CheckSuffix matches `*.s3.amazonaws.com` or `*.azurewebsites.net`, immediately probe the destination and AI decides "takeable?" with confidence + step-by-step instructions.
3. **Auto-refresh dataset.** Daily cron pulls from each upstream URL, AI diffs against last week, surfaces interesting changes ("Cloudflare added 5 new /16s today; new ASN appeared in AWS").
4. **Bot-protection inference.** Combine cdncheck output with HTTP response header fingerprints (DataDome cookies, Kasada `kasada` header, PerimeterX `_pxhd` cookies) → AI infers the full protection stack: "CDN: Cloudflare + Bot-Protection: DataDome".
5. **Bypass recipe generator.** Given "WAF: Cloudflare, host: api.acme.com", AI suggests bypass techniques to try first (cache-buster header, HTTP Pipelining, Host-header smuggling, etc.).
6. **Asset categorization for asset-management.** "Of these 10k subdomains, 3000 are Cloudflare-protected (low-priority for direct scan), 2000 on AWS (likely backend APIs), 500 on Azure (likely SaaS integrations), 4500 unprotected (highest-priority scan)."

## Implementation phases (10-week plan)

### Phase 0 — Skeleton + offline dataset + trie lookup (Week 1)
- `cargo new lancercdn`. `clap` derive (detection / matcher / filter / output / config groups).
- `include_str!("sources_data.json")` (embed cdncheck's latest snapshot, ~hundreds KB).
- Parse via `serde_json` into `InputCompiled { cdn, waf, cloud, common: HashMap<String, Vec<String>> }`.
- Build three `ipnet_trie::IpnetTrie<String>` (one per category) at startup. Insert each CIDR with provider-name as value.
- `lancercdn 1.2.3.4` → `Check(ip)` → walk three tries, return first match.
- Deliverable: `lancercdn 104.21.1.1` → `104.21.1.1 [waf] [cloudflare]`.

### Phase 1 — Domain inputs + DNS resolve + CNAME fallback (Week 2)
- Add `hickory-resolver` with default 8-resolver pool.
- `CheckDomainWithFallback(domain)`: resolve A/AAAA → check each IP → if no match, query CNAME → suffix-match against `common.fqdn` map.
- `publicsuffix` crate to split FQDN into TLD/SLD properly.
- Deliverable: `lancercdn acme.com` resolves + checks.

### Phase 2 — CIDR inputs + STDIN streaming + CLI completeness (Week 3)
- CIDR input: detect via `ipnet::IpNet::from_str`, expand lazily (streaming so /8 doesn't OOM).
- STDIN reader (`tokio::io::BufReader::new(stdin()).lines()`).
- `-i input,input2` (`FileCommaSeparatedStringSliceOptions` equivalent — comma-separated, file path, or stdin).
- All output flags: `-resp`, `-jsonl`, `-output`, `-silent`, `-no-color`, summary print.
- Match/filter for each category (`-match-cdn`, `-filter-cdn`, etc.).
- `-exclude` mode (invert output).
- Deliverable: feature parity with upstream cdncheck CLI.

### Phase 3 — Auto-refresh dataset (`update` subcommand) (Week 4-5)
- `lancercdn update` subcommand: re-fetch every URL in `provider.yaml`, regex-extract CIDRs.
- Compile-time `provider.yaml` embedded; runtime fetches generate `sources_data.json` into `~/.local/share/lancercdn/sources_data.json`.
- On startup, prefer disk-version if present and newer than embedded.
- SHA256 integrity check.
- Daily cron suggestion in README.
- Custom scrapers for HTML providers (Azure XML download is the pain point) — use `scraper` crate.
- Deliverable: `lancercdn update` refreshes dataset; next lookup uses new data.

### Phase 4 — ASN expansion (IPinfo integration) (Week 6)
- `lancercdn update --ipinfo-token TOKEN` enables ASN expansion (Akamai, Sucuri, etc.).
- `reqwest` GET `https://ipinfo.io/AS{n}/json?token=...`, parse `prefixes[].netblock`.
- Mark provider-name with `asn:` prefix to distinguish from URL-derived ranges.
- Deliverable: without token, Akamai detection is partial; with token, comprehensive.

### Phase 5 — Library API (the Lancer integration point) (Week 7)
- `lib.rs`: `Client { cdn_trie, waf_trie, cloud_trie, fqdn_map, resolver }`.
- Methods: `check(ip) -> Detection`, `check_domain_with_fallback(domain) -> Detection`, `check_dns_response(data) -> Detection`, `check_suffix(fqdns) -> Detection`.
- `Detection { provider: Option<String>, category: Category, confidence: Confidence }`.
- Re-export for Lancer §37 Bulk Probe, LancerScan (naabu clone), LancerDNS (dnsx clone), LancerProbe (httpx clone).
- Deliverable: `use lancercdn::Client;` works from sibling crates.

### Phase 6 — HTTP-fingerprint WAF detection (the addition cdncheck doesn't have) (Week 8)
- New flag `--http-probe`: for each input host, send `HEAD /`, capture response headers (`Server`, `X-Powered-By`, `Set-Cookie`, `CF-Ray`, `X-Akamai-*`, etc.).
- Port WAFW00F's regex fingerprints (300+ patterns covering AWS WAF, Cloudflare WAF, Imperva, F5 BIG-IP, Barracuda, FortiWeb, ModSecurity, Sucuri, Akamai, Wallarm, etc.).
- Optional second probe with weird path (`/<random>?<random>=<random>`) to trigger 403-on-WAF.
- Output: in addition to CIDR-based category, emit `waf-fingerprint: cloudflare-waf` or `waf-fingerprint: imperva`.
- Deliverable: detects bot-protection (DataDome via headers) where CIDR alone fails.

### Phase 7 — Bot-protection detection extension (Week 8-9)
- Port DataDome, Kasada, PerimeterX, Akamai Bot Manager, Shape, hCaptcha header/cookie fingerprints.
- Compose with CDN detection: "Cloudflare CDN + DataDome BotProtection".
- Deliverable: full protection-stack inference.

### Phase 8 — Output enrichment + ASN annotation (Week 9)
- `--asn` flag: annotate output with AS number + AS name (via BGPView or RIPEstat REST).
- Json output: `{ip, cdn, cdn_name, waf, waf_name, cloud, cloud_name, asn, asn_name, http_fingerprint}`.
- Deliverable: rich JSON for downstream consumers.

### Phase 9 — AI ranking + polish (Week 10)
- `--ai-rank`: for a list of "candidate origin IPs behind CDN-protected host", AI ranks most-likely-current.
- `--ai-bypass`: given detected WAF + target URL, AI suggests bypass techniques.
- Cross-platform binary release.
- Healthcheck command (`-hc`).
- Deliverable: AI-augmented CDN detection / bypass recipes.

## CLAUDE.md to seed in the clone repo
```
This project = a cdncheck clone in Rust ("lancercdn").
- Dataset is the product: embed sources_data.json (cdncheck's compiled CIDR set) via include_str!.
- Lookup uses prefix-trie (or ipnet-trie); MUST be O(W) longest-prefix-match — never iterate.
- Three categories: CDN, WAF, Cloud — separate tries; Check(ip) tries CDN → WAF → Cloud, returns first match.
- For domain inputs: hickory-resolver to get A/AAAA → check IPs; on no match, query CNAME and run suffix-match against common.fqdn map (uses publicsuffix crate for proper TLD split).
- Auto-refresh dataset: `lancercdn update` re-fetches every URL in embedded provider.yaml, parses with regex, writes ~/.local/share/lancercdn/sources_data.json. SHA256 integrity check.
- ASN expansion (Akamai, Sucuri) needs IPinfo token (--ipinfo-token).
- HTTP fingerprint mode (--http-probe) sends ONE benign HEAD / and ONE 404-baiting weird path; ports WAFW00F's regex fingerprints for WAF detection.
- Library API in lib.rs — sibling Lancer crates (lancerscan, lancerdns, lancerprobe) import the Client.
- Output formats: txt (default), JSON, JSON-lines; -resp annotates with provider name; -exclude inverts (origin-IP candidates).
- NEVER block: trie lookup is microseconds; domain check has DNS RTT but at most ~100ms.
```

---

## GUI (Lancer-standard pattern)

`lancer-cdncheck` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-cdncheck-cli` companion binary), but the **plain `lancer-cdncheck` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-cdncheck/`, `%APPDATA%\lancer-cdncheck\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-cdncheck-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-cdncheck.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-cdncheck.exe` (double-click opens the GUI window).
- Linux: `build/lancer-cdncheck` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-cdncheck` (bundled into `lancer-cdncheck.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-cdncheck/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-cdncheck.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-cdncheck-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-cdncheck
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-cdncheck.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-cdncheck-windows-x86_64\bin\lancer-cdncheck.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-cdncheck`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
