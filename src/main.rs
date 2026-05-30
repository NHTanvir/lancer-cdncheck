//! `lancer-cdncheck` binary entrypoint.
//!
//! Plain invocation on an interactive terminal opens the native GUI (when built
//! with the default `gui` feature). With piped input, a subcommand, any scan
//! flag, or `--cli`, it runs the CLI surface. `--no-default-features` produces a
//! headless CLI-only binary.

#[cfg(feature = "gui")]
mod gui;

use clap::Parser;
use lancer_cdncheck::cli::{self, Cli};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    #[cfg(feature = "gui")]
    {
        if cli.gui || cli::should_use_gui(&cli) {
            return gui::run();
        }
    }

    #[cfg(not(feature = "gui"))]
    {
        if cli.gui {
            anyhow::bail!(
                "this binary was built without GUI support (--no-default-features); use --cli"
            );
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(cli::run(cli))
}
