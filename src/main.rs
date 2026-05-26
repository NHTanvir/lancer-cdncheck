//! lancer-cdncheck
//! Rust clone of cdncheck. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-cdncheck", version, about = "Rust clone of cdncheck")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-cdncheck - scaffold ready. Implement per plan.md.");
    Ok(())
}
