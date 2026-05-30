//! Dataset loading: the embedded `sources_data.json` snapshot plus the
//! runtime disk override written by `lancer-cdncheck update`
//! (`Phase 3`). Includes SHA256 integrity verification.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The compiled CIDR / FQDN dataset. Mirrors upstream's `InputCompiled`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SourceData {
    #[serde(default)]
    pub cdn: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub waf: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub cloud: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub common: HashMap<String, Vec<String>>,
}

/// Compile-time embedded snapshot (cdncheck's latest committed dataset).
pub const EMBEDDED_SOURCES: &str = include_str!("sources_data.json");

impl SourceData {
    /// Parse the compile-time embedded dataset.
    pub fn embedded() -> SourceData {
        serde_json::from_str(EMBEDDED_SOURCES).expect("embedded sources_data.json is valid JSON")
    }

    /// Parse a dataset from a JSON string.
    pub fn from_json(s: &str) -> Result<SourceData> {
        serde_json::from_str(s).context("parsing sources_data.json")
    }

    /// Load the best available dataset: prefer a valid on-disk override (from
    /// `update`) over the embedded snapshot.
    pub fn load() -> SourceData {
        if let Some(path) = Self::disk_path() {
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        // Verify integrity if a sidecar .sha256 exists.
                        if Self::verify_sidecar(&path, &content).unwrap_or(true) {
                            if let Ok(data) = Self::from_json(&content) {
                                return data;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
        Self::embedded()
    }

    /// Per-OS data path: `~/.local/share/lancercdn/sources_data.json` (Linux),
    /// `%APPDATA%\lancercdn\data\sources_data.json` (Windows), etc.
    pub fn disk_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "lancercdn")
            .map(|d| d.data_dir().join("sources_data.json"))
    }

    /// Write this dataset to the disk-override path with a SHA256 sidecar.
    pub fn save_to_disk(&self) -> Result<PathBuf> {
        let path = Self::disk_path().context("could not determine data directory")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating data dir {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
        let sum = sha256_hex(json.as_bytes());
        std::fs::write(path.with_extension("json.sha256"), &sum)?;
        Ok(path)
    }

    fn verify_sidecar(path: &std::path::Path, content: &str) -> Option<bool> {
        let sidecar = path.with_extension("json.sha256");
        let expected = std::fs::read_to_string(&sidecar).ok()?;
        let expected = expected.split_whitespace().next()?.to_lowercase();
        Some(sha256_hex(content.as_bytes()) == expected)
    }

    /// Total number of providers across the three IP categories.
    pub fn provider_count(&self) -> usize {
        self.cdn.len() + self.waf.len() + self.cloud.len()
    }

    /// Total number of CIDR entries across the three IP categories.
    pub fn cidr_count(&self) -> usize {
        let sum = |m: &HashMap<String, Vec<String>>| m.values().map(Vec::len).sum::<usize>();
        sum(&self.cdn) + sum(&self.waf) + sum(&self.cloud)
    }
}

/// Lowercase hex SHA256 of the given bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
