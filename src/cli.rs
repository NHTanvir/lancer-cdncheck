//! CLI surface and runner — shared by the `lancer-cdncheck` and
//! `lancer-cdncheck-cli` binaries. Provides full upstream cdncheck flag parity
//! plus the Lancer extensions (`--http-probe`, `--asn`, `--ai-rank`,
//! `--ai-bypass`, `--self-test`) and the `update` / `generate` subcommands.

use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use ipnet::IpNet;
use serde::Serialize;

use crate::detection::{Detection, DetectionCategory};
use crate::Client;

// ─── argument model ────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "lancer-cdncheck",
    version,
    about = "CDN / WAF / Cloud detection — Rust clone of cdncheck (Lancer toolkit)",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub scan: ScanArgs,

    /// Force CLI mode (never open the GUI)
    #[arg(long, global = true)]
    pub cli: bool,

    /// Force GUI mode
    #[arg(long, global = true)]
    pub gui: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Re-fetch the CIDR dataset from provider.yaml sources into the local data dir
    Update(UpdateArgs),
    /// Compile a fresh sources_data.json to stdout or a file (does not persist to the data dir)
    Generate(GenerateArgs),
}

#[derive(Args, Debug, Default)]
pub struct UpdateArgs {
    /// IPinfo token enabling ASN expansion (Akamai, Sucuri, …)
    #[arg(long = "ipinfo-token")]
    pub ipinfo_token: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct GenerateArgs {
    /// IPinfo token enabling ASN expansion
    #[arg(long = "ipinfo-token")]
    pub ipinfo_token: Option<String>,
    /// Write compiled JSON here (default: stdout)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct ScanArgs {
    /// Comma-separated IPs, CIDRs, domains, or a file path
    #[arg(short = 'i', long = "input", value_delimiter = ',')]
    pub input: Vec<String>,

    // category filters
    /// Only show CDN detections
    #[arg(long = "cdn")]
    pub cdn: bool,
    /// Only show Cloud detections
    #[arg(long = "cloud")]
    pub cloud: bool,
    /// Only show WAF detections
    #[arg(long = "waf")]
    pub waf: bool,

    // match (allow-list) per category
    /// Only show CDN results for these providers
    #[arg(long = "match-cdn", visible_alias = "mcdn", value_delimiter = ',')]
    pub match_cdn: Vec<String>,
    /// Only show Cloud results for these providers
    #[arg(long = "match-cloud", visible_alias = "mcloud", value_delimiter = ',')]
    pub match_cloud: Vec<String>,
    /// Only show WAF results for these providers
    #[arg(long = "match-waf", visible_alias = "mwaf", value_delimiter = ',')]
    pub match_waf: Vec<String>,

    // filter (deny-list) per category
    /// Exclude CDN results for these providers
    #[arg(long = "filter-cdn", visible_alias = "fcdn", value_delimiter = ',')]
    pub filter_cdn: Vec<String>,
    /// Exclude Cloud results for these providers
    #[arg(long = "filter-cloud", visible_alias = "fcloud", value_delimiter = ',')]
    pub filter_cloud: Vec<String>,
    /// Exclude WAF results for these providers
    #[arg(long = "filter-waf", visible_alias = "fwaf", value_delimiter = ',')]
    pub filter_waf: Vec<String>,

    // output
    /// Show detected provider name in output
    #[arg(long = "resp")]
    pub resp: bool,
    /// Write results to file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
    /// Output as JSON lines
    #[arg(short = 'j', long = "jsonl")]
    pub jsonl: bool,
    /// Disable color output
    #[arg(long = "no-color", visible_alias = "nc")]
    pub no_color: bool,
    /// Output results only (suppress banner / summary)
    #[arg(long = "silent")]
    pub silent: bool,
    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Debug output
    #[arg(long = "debug")]
    pub debug: bool,

    // behaviour
    /// Print only inputs that matched NOTHING (origin-IP mode)
    #[arg(short = 'e', long = "exclude")]
    pub exclude: bool,
    /// Custom DNS resolvers (comma-separated, host or host:port)
    #[arg(short = 'r', long = "resolver", value_delimiter = ',')]
    pub resolver: Vec<String>,
    /// DNS resolution retry count
    #[arg(long = "retry", default_value_t = 2)]
    pub retry: u8,

    // Lancer extensions
    /// HTTP-probe each host for WAF / bot-protection header fingerprints (Phase 6/7)
    #[arg(long = "http-probe")]
    pub http_probe: bool,
    /// DNS-probe each domain for SPF / NS provider fingerprints
    #[arg(long = "dns-probe")]
    pub dns_probe: bool,
    /// Annotate matched IPs with ASN + AS name (Phase 8)
    #[arg(long = "asn")]
    pub asn: bool,
    /// AI-rank inputs as candidate origin IPs behind --ai-target (Phase 9)
    #[arg(long = "ai-rank")]
    pub ai_rank: bool,
    /// AI-suggest WAF-bypass techniques for each input URL (Phase 9)
    #[arg(long = "ai-bypass")]
    pub ai_bypass: bool,
    /// Target host the --ai-rank candidates belong to
    #[arg(long = "ai-target")]
    pub ai_target: Option<String>,
    /// Run the parity self-test matrix and exit
    #[arg(long = "self-test")]
    pub self_test: bool,
    /// Healthcheck: verify dataset + resolver and exit
    #[arg(long = "healthcheck", visible_alias = "hc")]
    pub healthcheck: bool,
}

/// The GUI is the default only when there's genuinely nothing to do on the CLI:
/// no subcommand, no input, not forced to CLI, and stdin is an interactive
/// terminal (so piped input still runs the CLI).
pub fn should_use_gui(cli: &Cli) -> bool {
    cli.command.is_none()
        && !cli.cli
        && cli.scan.input.is_empty()
        && !cli.scan.self_test
        && !cli.scan.healthcheck
        && !cli.scan.ai_rank
        && !cli.scan.ai_bypass
        && io::stdin().is_terminal()
}

// ─── entrypoint ────────────────────────────────────────────────────────────

pub async fn run(cli: Cli) -> Result<()> {
    init_logging(&cli.scan);
    if cli.scan.no_color {
        colored::control::set_override(false);
    }

    // Subcommands first.
    match &cli.command {
        Some(Command::Update(args)) => return run_update_cmd(args).await,
        Some(Command::Generate(args)) => return run_generate_cmd(args).await,
        None => {}
    }

    if cli.scan.self_test {
        return run_self_test_cmd(&cli).await;
    }
    if cli.scan.healthcheck {
        return run_healthcheck(&cli).await;
    }

    let client = build_client(&cli)?;

    if cli.scan.ai_rank {
        return run_ai_rank(&cli).await;
    }
    if cli.scan.ai_bypass {
        return run_ai_bypass(&cli, &client).await;
    }

    run_scan(&cli, &client).await
}

// ─── subcommand handlers ───────────────────────────────────────────────────

async fn run_update_cmd(args: &UpdateArgs) -> Result<()> {
    let opts = crate::update::UpdateOptions {
        ipinfo_token: args.ipinfo_token.clone(),
    };
    eprintln!("[*] refreshing dataset from provider.yaml sources …");
    let data = crate::update::run_update(&opts).await?;
    let path = crate::data::SourceData::disk_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<data dir>".into());
    eprintln!(
        "[+] dataset updated: {} providers, {} CIDRs → {}",
        data.provider_count(),
        data.cidr_count(),
        path
    );
    Ok(())
}

async fn run_generate_cmd(args: &GenerateArgs) -> Result<()> {
    let opts = crate::generator::CompileOptions {
        ipinfo_token: args.ipinfo_token.clone(),
    };
    eprintln!("[*] compiling dataset …");
    let data = crate::generator::compile(&opts).await?;
    let json = serde_json::to_string_pretty(&data)?;
    match &args.output {
        Some(path) => {
            std::fs::write(path, &json).with_context(|| format!("writing {path}"))?;
            eprintln!("[+] wrote {path}");
        }
        None => {
            println!("{json}");
        }
    }
    Ok(())
}

async fn run_self_test_cmd(cli: &Cli) -> Result<()> {
    let client = build_client(cli)?;
    let results = crate::self_test::run_self_test(&client);
    let (passed, total) = crate::self_test::summarize(&results);
    if cli.scan.jsonl {
        for r in &results {
            println!("{}", serde_json::to_string(r)?);
        }
    } else {
        for r in &results {
            let mark = if r.passed { "PASS".green() } else { "FAIL".red() };
            if !r.passed || cli.scan.verbose {
                println!(
                    "[{}] {} / {} ({}) — {}",
                    mark, r.group, r.provider, r.input, r.detail
                );
            }
        }
    }
    eprintln!("\nSelf-test: {passed}/{total} passed");
    // Dataset CIDR overlaps can make a small number of vectors resolve to a
    // more-specific neighbour; treat only a low pass rate (<80%) as a failure.
    if total > 0 && passed * 100 < total * 80 {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_healthcheck(cli: &Cli) -> Result<()> {
    let data = crate::data::SourceData::load();
    println!("dataset providers : {}", data.provider_count());
    println!("dataset CIDRs     : {}", data.cidr_count());
    let client = build_client(cli)?;
    println!("ipv6 reachable    : {}", client.ipv6_available());
    // A trivial offline lookup proves the trie is live.
    let probe: IpAddr = "127.0.0.1".parse().unwrap();
    let _ = client.check(probe);
    println!("status            : ok");
    Ok(())
}

// ─── AI modes ──────────────────────────────────────────────────────────────

async fn run_ai_rank(cli: &Cli) -> Result<()> {
    let target = cli
        .scan
        .ai_target
        .clone()
        .context("--ai-rank requires --ai-target <host>")?;
    let candidates = collect_inputs(&cli.scan).await?;
    let cfg = crate::ai::AiConfig::from_env()?;
    let ranked = crate::ai::rank_origin_candidates(&target, &candidates, &cfg).await?;
    for c in ranked {
        if cli.scan.jsonl {
            println!("{}", serde_json::to_string(&c)?);
        } else {
            println!("{:>3}  {}  {}", c.score, c.ip, c.reason);
        }
    }
    Ok(())
}

async fn run_ai_bypass(cli: &Cli, client: &Client) -> Result<()> {
    let cfg = crate::ai::AiConfig::from_env()?;
    let inputs = collect_inputs(&cli.scan).await?;
    for input in inputs {
        // Determine the protecting provider, if any.
        let waf = match detect_one(client, &input).await {
            Some(det) => det.provider,
            None => "unknown".to_string(),
        };
        let recipe = crate::ai::suggest_bypass(&waf, &input, &cfg).await?;
        println!("# {input} (detected: {waf})\n{recipe}\n");
    }
    Ok(())
}

// ─── core scan loop ──────────────────────────────────────────────────────────

#[derive(Default)]
struct Counts {
    cdn: u64,
    waf: u64,
    cloud: u64,
}

async fn run_scan(cli: &Cli, client: &Client) -> Result<()> {
    let inputs = collect_inputs(&cli.scan).await?;

    let mut out: Box<dyn Write> = match &cli.scan.output {
        Some(path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };

    let mut counts = Counts::default();

    for raw in &inputs {
        let input = raw.trim();
        if input.is_empty() {
            continue;
        }

        if let Ok(ip) = input.parse::<IpAddr>() {
            let det = client.check(ip);
            handle_result(cli, client, input, Some(ip), det, &mut counts, &mut *out).await?;
        } else if let Ok(net) = input.parse::<IpNet>() {
            for ip in expand_hosts(net) {
                let det = client.check(ip);
                let s = ip.to_string();
                handle_result(cli, client, &s, Some(ip), det, &mut counts, &mut *out).await?;
            }
        } else {
            match client.check_domain_with_fallback(input).await {
                Ok(det) => {
                    handle_result(cli, client, input, None, det, &mut counts, &mut *out).await?
                }
                Err(e) => {
                    if cli.scan.verbose || cli.scan.debug {
                        eprintln!("[warn] {input}: {e}");
                    }
                }
            }
        }
    }

    if !cli.scan.silent && !cli.scan.exclude {
        let total = counts.cdn + counts.waf + counts.cloud;
        eprintln!(
            "\nFound result: {total} (CDN: {}, CLOUD: {}, WAF: {})",
            counts.cdn, counts.cloud, counts.waf
        );
    }
    Ok(())
}

/// Lazily expand a CIDR into host IPs (safe for large prefixes — iterator).
fn expand_hosts(net: IpNet) -> Box<dyn Iterator<Item = IpAddr>> {
    match net {
        IpNet::V4(v4) => Box::new(v4.hosts().map(IpAddr::V4)),
        IpNet::V6(v6) => Box::new(v6.hosts().map(IpAddr::V6)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_result(
    cli: &Cli,
    client: &Client,
    input: &str,
    ip: Option<IpAddr>,
    det: Option<Detection>,
    counts: &mut Counts,
    out: &mut dyn Write,
) -> Result<()> {
    // exclude mode: print only the inputs that matched nothing (CIDR/CNAME).
    if cli.scan.exclude {
        if det.is_none() {
            writeln!(out, "{input}")?;
        }
        return Ok(());
    }

    // Optional HTTP-probe (Phase 6/7). Runs INDEPENDENTLY of the CIDR result —
    // its purpose is to surface WAF / bot-protection layers that the offline
    // trie cannot see (DataDome, Cloudflare WAF vs CDN, F5, …).
    let mut http_fps: Vec<String> = Vec::new();
    let mut dns_fps: Vec<String> = Vec::new();
    let mut probe_dets: Vec<Detection> = Vec::new();
    if cli.scan.http_probe {
        if let Ok(res) = crate::http_probe::probe(input, 10).await {
            for d in &res.detections {
                http_fps.push(format!("{}:{}", d.category, d.provider));
            }
            probe_dets.extend(res.detections);
        }
    }
    // DNS-probe only makes sense for domains (SPF/NS records), not bare IPs/CIDRs.
    if cli.scan.dns_probe && ip.is_none() {
        let dets = client.check_dns_fingerprint(input).await;
        for d in &dets {
            dns_fps.push(format!("{}:{}", d.category, d.provider));
        }
        probe_dets.extend(dets);
    }

    // Fold any probe detections into the (possibly empty) CIDR detection.
    let det: Option<Detection> = match (det, probe_dets.is_empty()) {
        (Some(mut d), false) => {
            for pd in probe_dets {
                d = d.merge(pd);
            }
            Some(d)
        }
        (Some(d), true) => Some(d),
        (None, false) => {
            let signals: Vec<_> = probe_dets.into_iter().flat_map(|d| d.signals).collect();
            Detection::from_signals(signals)
        }
        (None, true) => None,
    };

    let Some(det) = det else {
        return Ok(());
    };

    if !passes_category_filter(&det, &cli.scan)
        || !passes_match_filter(&det, &cli.scan)
        || !passes_filter_out(&det, &cli.scan)
    {
        return Ok(());
    }

    // Optional ASN enrichment.
    let mut asn_num = None;
    let mut asn_name = None;
    if cli.scan.asn {
        if let Some(ip) = ip {
            if let Ok(info) = crate::asn::lookup(ip).await {
                asn_num = info.asn;
                asn_name = info.name;
            }
        }
    }

    match det.category {
        DetectionCategory::Cdn => counts.cdn += 1,
        DetectionCategory::Waf => counts.waf += 1,
        DetectionCategory::Cloud => counts.cloud += 1,
        DetectionCategory::BotProtection => {}
    }

    if cli.scan.jsonl {
        let rec = OutputRecord {
            input,
            ip: ip.map(|i| i.to_string()),
            category: det.category.to_string(),
            provider: det.provider.clone(),
            confidence: det.confidence,
            protection_stack: det.protection_stack.clone(),
            asn: asn_num,
            asn_name,
            http_fingerprint: http_fps,
            dns_fingerprint: dns_fps,
        };
        writeln!(out, "{}", serde_json::to_string(&rec)?)?;
    } else {
        let mut fps = http_fps;
        fps.extend(dns_fps);
        writeln!(out, "{}", format_line(input, &det, &cli.scan, &fps))?;
    }
    Ok(())
}

#[derive(Serialize)]
struct OutputRecord<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    category: String,
    provider: String,
    confidence: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    protection_stack: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    http_fingerprint: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dns_fingerprint: Vec<String>,
}

fn format_line(input: &str, det: &Detection, scan: &ScanArgs, http_fps: &[String]) -> String {
    if !scan.resp {
        return input.to_string();
    }
    let cat = if scan.no_color {
        det.category.to_string()
    } else {
        match det.category {
            DetectionCategory::Cdn => det.category.to_string().blue().bold().to_string(),
            DetectionCategory::Waf => det.category.to_string().red().bold().to_string(),
            DetectionCategory::Cloud => det.category.to_string().yellow().bold().to_string(),
            DetectionCategory::BotProtection => {
                det.category.to_string().magenta().bold().to_string()
            }
        }
    };
    let provider = if scan.no_color {
        det.provider.clone()
    } else {
        det.provider.bold().to_string()
    };
    let mut line = format!("{input} [{cat}] [{provider}]");
    if !http_fps.is_empty() {
        line.push_str(&format!(" [{}]", http_fps.join(",")));
    }
    line
}

// ─── filters ─────────────────────────────────────────────────────────────────

fn passes_category_filter(det: &Detection, scan: &ScanArgs) -> bool {
    let any = scan.cdn || scan.waf || scan.cloud;
    if !any {
        return true;
    }
    match det.category {
        DetectionCategory::Cdn => scan.cdn,
        DetectionCategory::Waf => scan.waf,
        DetectionCategory::Cloud => scan.cloud,
        DetectionCategory::BotProtection => false,
    }
}

fn passes_match_filter(det: &Detection, scan: &ScanArgs) -> bool {
    let required: &[String] = match det.category {
        DetectionCategory::Cdn => &scan.match_cdn,
        DetectionCategory::Waf => &scan.match_waf,
        DetectionCategory::Cloud => &scan.match_cloud,
        DetectionCategory::BotProtection => return true,
    };
    if required.is_empty() {
        return true;
    }
    let prov = det.provider.to_lowercase();
    required.iter().any(|p| p.to_lowercase() == prov)
}

fn passes_filter_out(det: &Detection, scan: &ScanArgs) -> bool {
    let excluded: &[String] = match det.category {
        DetectionCategory::Cdn => &scan.filter_cdn,
        DetectionCategory::Waf => &scan.filter_waf,
        DetectionCategory::Cloud => &scan.filter_cloud,
        DetectionCategory::BotProtection => return true,
    };
    let prov = det.provider.to_lowercase();
    !excluded.iter().any(|p| p.to_lowercase() == prov)
}

// ─── helpers ───────────────────────────────────────────────────────────────

async fn detect_one(client: &Client, input: &str) -> Option<Detection> {
    if let Ok(ip) = input.parse::<IpAddr>() {
        client.check(ip)
    } else {
        // strip scheme for domain detection
        let host = input
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(input);
        client.check_domain_with_fallback(host).await.ok().flatten()
    }
}

fn build_client(cli: &Cli) -> Result<Client> {
    Client::new_with_opts(cli.scan.retry as usize, &cli.scan.resolver)
}

async fn collect_inputs(scan: &ScanArgs) -> Result<Vec<String>> {
    if scan.input.is_empty() {
        // read from stdin
        if io::stdin().is_terminal() {
            // Nothing piped and no -i: print a hint instead of blocking forever.
            eprintln!("no input — pass -i <targets>, pipe stdin, or run without args for the GUI");
            return Ok(Vec::new());
        }
        let mut lines = Vec::new();
        use tokio::io::AsyncBufReadExt;
        let stdin = tokio::io::stdin();
        let mut reader = tokio::io::BufReader::new(stdin);
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            let t = line.trim().to_string();
            if !t.is_empty() {
                lines.push(t);
            }
            line.clear();
        }
        return Ok(lines);
    }

    // Single value that is an existing file → read it line-by-line.
    if scan.input.len() == 1 {
        let v = &scan.input[0];
        let p = Path::new(v);
        if p.exists() && p.is_file() {
            let content = tokio::fs::read_to_string(v).await?;
            return Ok(content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect());
        }
    }

    Ok(scan.input.clone())
}

fn init_logging(scan: &ScanArgs) {
    if scan.debug || scan.verbose {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("lancer_cdncheck=debug,hickory=warn")
            .try_init();
    }
}
