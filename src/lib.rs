//! `lancer-cdncheck` — a Rust clone of ProjectDiscovery's `cdncheck` with full
//! CLI feature parity plus Lancer extensions (HTTP-probe WAF fingerprinting,
//! bot-protection detection, ASN enrichment, AI ranking) and a native GUI.
//!
//! The library entry point is [`Client`]; see [`client`] for the detection API
//! that sibling Lancer crates (lancerscan / lancerdns / lancerprobe) import.

// ── core ─────────────────────────────────────────────────────────────────────
pub mod client;
pub mod data;
pub mod detection;
pub mod psl;

// ── detection extensions ──────────────────────────────────────────────────────
pub mod asn; // Phase 8 — ASN annotation
pub mod bot_protection; // Phase 7 — DataDome / Kasada / PerimeterX / Akamai BM
pub mod dns_fingerprint; // Detection methods #4/#5 — SPF/TXT + NS record signatures
pub mod http_probe; // Phase 6 — WAFW00F-style header fingerprints

// ── dataset pipeline ──────────────────────────────────────────────────────────
pub mod generator; // Phase 3/4 — provider.yaml → sources_data.json (scrape + IPinfo)
pub mod update; // Phase 3 — `update` subcommand

// ── augmentation + orchestration ──────────────────────────────────────────────
pub mod ai; // Phase 9 — AI origin-ranking / bypass-recipe
pub mod cli; // CLI runner (shared by the main and companion binaries)
pub mod self_test; // `--self-test` parity matrix

// ── re-exports ─────────────────────────────────────────────────────────────────
pub use client::{Client, DnsData};
pub use detection::{Category, Detection, DetectionCategory, Signal, SignalType};

/// Crate version, surfaced by `--version` and the GUI About dialog.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
