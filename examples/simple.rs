//! Minimal usage example for `lancer-cdncheck`, mirroring upstream's
//! `examples/simple.go`. Builds a [`Client`], checks a known CDN IP and a
//! domain (via DNS fallback), and prints any [`Detection`] found.
//!
//! Run with: `cargo run --example simple`

use std::net::IpAddr;

use lancer_cdncheck::{Client, Detection};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build the client from the embedded provider dataset.
    let client = Client::new()?;

    // 1) Synchronous IP check against the CIDR/ASN tries (Cloudflare range).
    let ip: IpAddr = "104.16.0.1".parse()?;
    match client.check(ip) {
        Some(d) => report(&format!("IP {ip}"), &d),
        None => println!("IP {ip}: no CDN/WAF/Cloud match"),
    }

    // 2) Async domain check: resolves DNS, then falls back to CNAME/suffix logic.
    let domain = "acme.com";
    match client.check_domain_with_fallback(domain).await? {
        Some(d) => report(&format!("domain {domain}"), &d),
        None => println!("domain {domain}: no CDN/WAF/Cloud match"),
    }

    Ok(())
}

/// Pretty-print a detection: full debug plus the headline fields.
fn report(subject: &str, d: &Detection) {
    println!("{subject} => {d:#?}");
    println!(
        "  provider={} category={} confidence={}",
        d.provider,
        d.category.as_str(),
        d.confidence
    );
}
