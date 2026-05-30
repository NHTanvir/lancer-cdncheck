# lancer-cdncheck

A Rust clone of [ProjectDiscovery's `cdncheck`](https://github.com/projectdiscovery/cdncheck) — CDN / WAF / Cloud detection — with full CLI feature parity plus a native GUI and modern detection extensions. Part of the **Lancer** bug-bounty toolkit.

> Answers one question per input: *"Is this IP/hostname behind a CDN, WAF, or cloud provider — and which one?"* — so you can skip port-scanning edge servers and prioritize WAF-bypass research.

## Features

- **Offline-first detection** via a compiled longest-prefix-match IP trie (`ipnet-trie`) over an embedded provider CIDR dataset (`sources_data.json`).
- **Three categories** — CDN, WAF, Cloud — checked in order, returning the first match.
- **Domain inputs** — resolves A/AAAA (via `hickory-resolver`), then falls back to CNAME-suffix matching against a curated common-FQDN list (PSL-aware via `publicsuffix`).
- **CIDR inputs** — `1.2.3.0/24` is expanded lazily (streaming, so a `/8` won't OOM).
- **Full upstream CLI parity** — every flag: `-i`, `-cdn/-cloud/-waf`, `-match-*`, `-filter-*`, `-resp`, `-o`, `-jsonl`, `-no-color`, `-silent`, `-verbose`, `-resolver`, `-exclude`, `-retry`, `-debug`.
- **Library API** (`lancer_cdncheck::Client`) — `check`, `check_domain_with_fallback`, `check_dns_response`, `check_suffix`, `check_wappalyzer` — re-used by sibling Lancer crates.
- **Lancer extensions:**
  - `--http-probe` — WAFW00F-style HTTP response-header fingerprinting (Phase 6).
  - bot-protection detection — DataDome, Kasada, PerimeterX/HUMAN, Akamai Bot Manager, … (Phase 7).
  - `--dns-probe` — SPF/TXT and authoritative-NS record provider fingerprints.
  - `--asn` — ASN + AS-name enrichment via RIPEstat (Phase 8).
  - `--ai-rank` / `--ai-bypass` — AI origin-IP ranking and WAF-bypass recipes (Phase 9, needs `ANTHROPIC_API_KEY`).
  - confidence scoring + multi-layer `protection_stack` output.
- **`update` subcommand** — re-fetch the dataset from the embedded `provider.yaml` sources (regex CIDR extraction + IPinfo ASN expansion) into the per-OS data dir with a SHA256 integrity sidecar.
- **`--self-test`** — runs the parity matrix against the embedded dataset.
- **Native GUI** — three-pane `egui`/`eframe` desktop app (the default when launched with no input on an interactive terminal), with a local HTTP server for Lancer cross-tool integration.

## Usage

```bash
# Single IP
echo 104.16.0.1 | lancer-cdncheck -resp -silent
# → 104.16.0.1 [waf] [cloudflare]

# Domain
lancer-cdncheck -i acme.com -resp

# Find origin IPs (not behind any CDN/WAF/Cloud)
cat ips.txt | lancer-cdncheck -exclude -silent

# Per-category match
cat ips.txt | lancer-cdncheck -match-cloud aws -resp

# CIDR expansion
echo 13.32.0.0/16 | lancer-cdncheck -resp -silent

# JSON lines with HTTP fingerprint + ASN enrichment
lancer-cdncheck -i acme.com -jsonl --http-probe --asn

# Refresh the dataset (optionally with an IPinfo token for ASN expansion)
lancer-cdncheck update --ipinfo-token "$IPINFO_TOKEN"

# Parity self-test
lancer-cdncheck --self-test
```

For CI / headless / scripting, the GUI never opens for piped input; you can also use the `lancer-cdncheck-cli` companion binary or pass `--cli`.

## Build

### Windows
Double-click `build.bat` or run from cmd:
```
build.bat
```
Output: `build\lancer-cdncheck.exe`

For a packaged dist build:
```
build-windows.bat
```
Output: `dist\lancer-cdncheck-windows-x86_64\bin\lancer-cdncheck.exe`

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-cdncheck`

### Headless (CLI-only, no GUI deps)
```bash
cargo build --release --no-default-features
```

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## License

MIT
