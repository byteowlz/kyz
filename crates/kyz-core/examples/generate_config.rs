//! Generate config.toml and config.schema.json to examples/ directory.
//!
//! Run with: cargo run -p kyz-core --example `generate_config`

use std::path::PathBuf;

use kyz_core::{APP_NAME, write_generated_files};

/// Repository URL for schema $id.
const REPO_URL: &str = "https://github.com/byteowlz/kyz";

fn main() -> anyhow::Result<()> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let crate_root = PathBuf::from(&manifest_dir);
    let workspace_root = crate_root
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| anyhow::anyhow!("could not find workspace root"))?;

    let examples_dir = workspace_root.join("examples");

    println!("Generating config files to {}...", examples_dir.display());
    write_generated_files(&examples_dir, APP_NAME, REPO_URL)?;
    println!("Done! Generated:");
    println!("  - {}/config.schema.json", examples_dir.display());
    println!("  - {}/config.toml", examples_dir.display());

    Ok(())
}
