//! Companion binary: always runs the CLI surface (for CI / headless /
//! scripting), never the GUI. Equivalent to `lancer-cdncheck --cli`.

use clap::Parser;
use lancer_cdncheck::cli::{self, Cli};

fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    cli.cli = true;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cli::run(cli))
}
