//! The `update` subcommand backend (`Phase 3`).
//!
//! Re-fetches the provider dataset via [`crate::generator::compile`], persists
//! it to the per-OS data directory with a SHA256 sidecar via
//! [`crate::data::SourceData::save_to_disk`], and returns the freshly compiled
//! dataset so callers can report on it.

use anyhow::Result;

use crate::data::SourceData;
use crate::generator::CompileOptions;

/// Options controlling a dataset refresh.
#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    /// Optional IPinfo API token used to expand ASN entries into prefixes.
    /// When `None`, ASN-derived ranges are skipped by the generator.
    pub ipinfo_token: Option<String>,
}

/// Re-fetch the dataset, persist it to disk, and return the compiled result.
///
/// Builds a [`CompileOptions`] from `opts`, runs the generator, writes the
/// dataset (plus its SHA256 sidecar) to disk, and logs a short progress
/// summary via `tracing`.
pub async fn run_update(opts: &UpdateOptions) -> Result<SourceData> {
    tracing::info!(
        has_token = opts.ipinfo_token.is_some(),
        "starting dataset update"
    );

    let compile_opts = CompileOptions {
        ipinfo_token: opts.ipinfo_token.clone(),
    };

    let data = crate::generator::compile(&compile_opts).await?;

    let path = data.save_to_disk()?;

    tracing::info!(
        path = %path.display(),
        providers = data.provider_count(),
        cidrs = data.cidr_count(),
        "dataset update complete"
    );

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_have_no_token() {
        let opts = UpdateOptions::default();
        assert!(opts.ipinfo_token.is_none());
    }
}
