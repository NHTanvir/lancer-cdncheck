# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-cdncheck` — a Rust clone of ProjectDiscovery's [`cdncheck`](https://github.com/projectdiscovery/cdncheck) (CDN / WAF / Cloud detection) with full upstream CLI parity, a native GUI, and modern detection extensions (HTTP-probe WAF fingerprinting, bot-protection, ASN enrichment, AI ranking). Part of the **Lancer** bug-bounty toolkit.

## Architecture

**The dataset is the product.** `src/sources_data.json` (the compiled provider CIDR set) is embedded at compile time via `include_str!` and loaded into three longest-prefix-match IP tries (CDN / WAF / Cloud) using `ipnet-trie`. Lookups are O(W) — never iterate the CIDR list.

**Library crate** (`src/lib.rs`, crate name `lancer_cdncheck`) — the integration point sibling Lancer crates import:

- `detection.rs` — `Detection`, `Signal`, `SignalType`, `DetectionCategory`; confidence scoring + multi-layer `protection_stack`.
- `client.rs` — `Client`: the three tries + CNAME suffix map + Wappalyzer map + resolver. Methods: `check`, `check_cdn/waf/cloud`, `check_domain_with_fallback`, `check_dns_response`, `check_suffix`, `check_wappalyzer`, `check_dns_fingerprint`. IPv6 reachability is auto-detected at construction.
- `data.rs` — `SourceData` loading: embedded snapshot, or a disk override written by `update` (with a SHA256 sidecar).
- `psl.rs` — Public Suffix List (embedded `public_suffix_list.dat`) for proper TLD/SLD splitting.
- `http_probe.rs` (Phase 6) — WAFW00F-style HTTP header/cookie fingerprints.
- `bot_protection.rs` (Phase 7) — DataDome / Kasada / PerimeterX / Akamai Bot Manager / F5 / ….
- `dns_fingerprint.rs` — SPF/TXT + authoritative-NS record signatures.
- `asn.rs` (Phase 8) — ASN annotation via RIPEstat (no key required).
- `ai.rs` (Phase 9) — Anthropic Messages API: origin-IP ranking + WAF-bypass recipes (`ANTHROPIC_API_KEY`).
- `generator.rs` + `provider.yaml` — dataset pipeline: fetch URLs, regex-extract CIDRs, IPinfo ASN expansion, HTML scrape.
- `update.rs` — `update` subcommand backend.
- `self_test.rs` — `--self-test` parity matrix (offline).
- `cli.rs` — the full CLI surface + runner, shared by both binaries.

**Binaries**: `src/main.rs` → `lancer-cdncheck` (opens the GUI by default; runs the CLI on piped input, any scan flag, a subcommand, or `--cli`). `src/bin/lancer-cdncheck-cli.rs` → `lancer-cdncheck-cli` (always CLI). `src/gui.rs` is the eframe/egui GUI, gated behind the default `gui` feature, with a local HTTP control server for Lancer cross-tool integration.

## Conventions

- Detection order is **CDN → WAF → Cloud, first match wins** (upstream parity).
- **Never block** the hot path: trie lookups are microseconds; only DNS / HTTP probes are async.
- Confidence anchors: CIDR=80, CNAME=60, header/cookie=50, ASN=40; +10 per extra distinct signal type, capped at 99.
- Library code propagates errors with `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- The GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI-only binary.
- Pinned crate versions matter (egui/eframe 0.28, reqwest 0.12, hickory 0.24, ipnet-trie 0.3, publicsuffix 2). Check `Cargo.toml` before bumping.

## Build / test / run

```
build.bat                                    # Windows → build\lancer-cdncheck.exe (GUI)
./build-linux.sh                             # Linux/macOS → build/lancer-cdncheck
cargo build --release --no-default-features  # headless CLI-only
cargo test                                   # unit tests + tests/upstream_parity.rs
cargo run --example simple
```

## Repo notes

- `plan.md` is a **local-only blueprint** and must **not** be committed or pushed. It is gitignored; if it ever shows up as tracked, run `git rm --cached plan.md`.
- `src/sources_data.json` and `src/public_suffix_list.dat` are embedded data assets — keep them committed.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
