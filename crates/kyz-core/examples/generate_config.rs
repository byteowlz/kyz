//! Generate config.toml and config.schema.json to examples/ directory.
//!
//! Run with: cargo run -p kyz-core --example generate_config

use std::path::PathBuf;

use kyz_core::{write_generated_files, APP_NAME};

/// Repository URL for schema $id.
const REPO_URL: &str = "https://github.com/byteowlz/kyz";

fn main() -> anyhow::Result<()> {
    // Find workspace root (where examples/ lives)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let crate_root = PathBuf::from(&manifest_dir);
    let workspace_root = crate_root
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("could not find workspace root");

    let examples_dir = workspace_root.join("examples");

    println!("Generating config files to {}...", examples_dir.display());
    write_generated_files(&examples_dir, APP_NAME, REPO_URL)?;
    println!("Done! Generated:");
    println!("  - {}/config.schema.json", examples_dir.display());
    println!("  - {}/config.toml", examples_dir.display());

    Ok(())
}
