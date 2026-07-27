// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{Context, Result};
use log::{error, info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TARBALLS_DIR: &str = "/opt/kata-artifacts/tarballs";
const TAR_PREFIX: &str = "opt/kata";
const TARBALL_ABS_PREFIX: &str = "/opt/kata";
const KATA_DEST: &str = "/host/opt/kata";
const SHIM_SOURCE: &str = "/host/opt/kata/bin/containerd-shim-kata-v2";
const SHIM_DEST: &str = "/host/usr/bin/containerd-shim-kata-v2";
const CONFIG_SOURCE: &str = "/host/opt/kata/share/defaults/kata-containers/configuration.toml";
const CONFIG_DEST_DIR: &str = "/host/etc/kata-containers";
const CONFIG_DEST: &str = "/host/etc/kata-containers/configuration.toml";

fn extract_tarball(tarball_path: &Path, dest_dir: &str) -> Result<()> {
    let file = fs::File::open(tarball_path)
        .with_context(|| format!("Failed to open tarball: {}", tarball_path.display()))?;
    // stream-decompress with pure-Rust zstd decoder; no C dependency required
    let decoder = ruzstd::streaming_decoder::StreamingDecoder::new(file)
        .map_err(|e| anyhow::anyhow!("Failed to create zstd decoder for {}: {}", tarball_path.display(), e))?;
    let mut archive = tar::Archive::new(decoder);
    let dest_path = Path::new(dest_dir);
    let dot_slash_prefix = Path::new("./opt/kata");

    for entry_result in archive.entries()? {
        let mut entry = entry_result.context("Failed to read tar entry")?;
        let raw_path = entry
            .path()
            .context("Failed to get tar entry path")?
            .into_owned();

        // strip "opt/kata" or "./opt/kata" prefix; skip unrelated entries
        let stripped = if let Ok(p) = raw_path.strip_prefix(TAR_PREFIX) {
            p.to_path_buf()
        } else if let Ok(p) = raw_path.strip_prefix(dot_slash_prefix) {
            p.to_path_buf()
        } else {
            log::debug!(
                "Skipping entry without expected prefix: {}",
                raw_path.display()
            );
            continue;
        };

        // root "opt/kata/" entry itself — just ensure dest exists
        if stripped.as_os_str().is_empty() {
            fs::create_dir_all(dest_path)?;
            continue;
        }

        // reject path traversal attempts
        for component in stripped.components() {
            if component == Component::ParentDir {
                anyhow::bail!(
                    "Tarball {} contains path traversal in entry: {}",
                    tarball_path.display(),
                    raw_path.display()
                );
            }
        }

        let dest_entry = dest_path.join(&stripped);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&dest_entry)
                .with_context(|| format!("Failed to create directory: {}", dest_entry.display()))?;
        } else if entry_type.is_symlink() {
            let link_target = entry
                .header()
                .link_name()?
                .ok_or_else(|| anyhow::anyhow!("Symlink has no link name: {}", raw_path.display()))?
                .into_owned();

            // Validate symlink target to avoid host path escapes.
            if link_target
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                anyhow::bail!(
                    "Tarball {} contains symlink with '..' in target: {} -> {}",
                    tarball_path.display(),
                    raw_path.display(),
                    link_target.display()
                );
            }

            // Rewrite absolute symlinks that point into /opt/kata so they resolve on the host.
            let final_target: PathBuf = if link_target.is_absolute() {
                let rel = link_target.strip_prefix(TARBALL_ABS_PREFIX).map_err(|_| {
                    anyhow::anyhow!(
                        "Tarball {} contains symlink with absolute target outside {}: {} -> {}",
                        tarball_path.display(),
                        TARBALL_ABS_PREFIX,
                        raw_path.display(),
                        link_target.display()
                    )
                })?;
                dest_path.join(rel)
            } else {
                link_target
            };

            if let Some(parent) = dest_entry.parent() {
                fs::create_dir_all(parent)?;
            }
            match fs::remove_file(&dest_entry) {
                Ok(()) | Err(_) => {}
            }
            unix_fs::symlink(&final_target, &dest_entry).with_context(|| {
                format!(
                    "Failed to create symlink {} -> {}",
                    dest_entry.display(),
                    final_target.display()
                )
            })?;
        } else {
            if let Some(parent) = dest_entry.parent() {
                fs::create_dir_all(parent)?;
            }
            match fs::remove_file(&dest_entry) {
                Ok(()) | Err(_) => {}
            }
            entry
                .unpack(&dest_entry)
                .with_context(|| format!("Failed to unpack entry to: {}", dest_entry.display()))?;
        }
    }
    Ok(())
}

fn copy_artifacts() -> Result<()> {
    info!("Extracting Kata artifacts from {} into {}", TARBALLS_DIR, KATA_DEST);

    let tarballs_path = Path::new(TARBALLS_DIR);
    if !tarballs_path.exists() {
        return Err(anyhow::anyhow!("Tarballs directory {} does not exist", TARBALLS_DIR));
    }

    // collect all kata-static-*.tar.zst component tarballs
    let mut tarballs: Vec<PathBuf> = fs::read_dir(tarballs_path)
        .with_context(|| format!("Failed to read tarballs directory: {}", TARBALLS_DIR))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("kata-static-") && n.ends_with(".tar.zst"))
                .unwrap_or(false)
        })
        .collect();

    if tarballs.is_empty() {
        return Err(anyhow::anyhow!(
            "No kata-static-*.tar.zst files found in {}",
            TARBALLS_DIR
        ));
    }

    tarballs.sort();

    fs::create_dir_all(KATA_DEST)
        .with_context(|| format!("Failed to create destination directory: {}", KATA_DEST))?;

    for tarball in &tarballs {
        info!("Extracting {}", tarball.display());
        extract_tarball(tarball, KATA_DEST)
            .with_context(|| format!("Failed to extract {}", tarball.display()))?;
    }

    info!("Successfully extracted {} tarball(s) into {}", tarballs.len(), KATA_DEST);
    Ok(())
}

fn install_shim_binary() -> Result<()> {
    if !Path::new(SHIM_SOURCE).exists() {
        return Err(anyhow::anyhow!(
            "Required Kata shim binary not found at {}; cannot install {}",
            SHIM_SOURCE, SHIM_DEST
        ));
    }
    // Remove existing file/symlink if present
    if Path::new(SHIM_DEST).exists() || Path::new(SHIM_DEST).is_symlink() {
        fs::remove_file(SHIM_DEST)
            .with_context(|| format!("Failed to remove existing {}", SHIM_DEST))?;
    }
    // Copy the binary
    fs::copy(SHIM_SOURCE, SHIM_DEST)
        .with_context(|| format!("Failed to copy {} to {}", SHIM_SOURCE, SHIM_DEST))?;
    // Preserve executable permissions
    if let Ok(metadata) = fs::metadata(SHIM_SOURCE) {
        fs::set_permissions(SHIM_DEST, metadata.permissions()).ok();
    }
    info!("Installed shim: {} -> {}", SHIM_SOURCE, SHIM_DEST);
    Ok(())
}

fn install_config() -> Result<()> {
    if !Path::new(CONFIG_SOURCE).exists() {
        warn!("Config file not found at {}, skipping", CONFIG_SOURCE);
        return Ok(());
    }
    // Create destination directory if it doesn't exist
    if !Path::new(CONFIG_DEST_DIR).exists() {
        fs::create_dir_all(CONFIG_DEST_DIR)
            .with_context(|| format!("Failed to create directory {}", CONFIG_DEST_DIR))?;
    }
    // Remove existing config file if present
    if Path::new(CONFIG_DEST).exists() {
        fs::remove_file(CONFIG_DEST)
            .with_context(|| format!("Failed to remove existing {}", CONFIG_DEST))?;
    }
    // Copy the config file
    fs::copy(CONFIG_SOURCE, CONFIG_DEST)
        .with_context(|| format!("Failed to copy {} to {}", CONFIG_SOURCE, CONFIG_DEST))?;
    info!("Installed config: {} -> {}", CONFIG_SOURCE, CONFIG_DEST);
    Ok(())
}

fn cleanup_artifacts() -> Result<()> {
    if Path::new(KATA_DEST).exists() {
        fs::remove_dir_all(KATA_DEST)
            .with_context(|| format!("Failed to remove {}", KATA_DEST))?;
        info!("Removed {}", KATA_DEST);
    }
    // Remove shim binary
    if Path::new(SHIM_DEST).exists() || Path::new(SHIM_DEST).is_symlink() {
        fs::remove_file(SHIM_DEST)
            .with_context(|| format!("Failed to remove {}", SHIM_DEST))?;
    }
    // Remove config file
    if Path::new(CONFIG_DEST).exists() {
        fs::remove_file(CONFIG_DEST)
            .with_context(|| format!("Failed to remove {}", CONFIG_DEST))?;
    }
    // Remove config directory if empty
    if Path::new(CONFIG_DEST_DIR).exists() {
        if let Ok(mut entries) = fs::read_dir(CONFIG_DEST_DIR) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(CONFIG_DEST_DIR);
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // Initialize logger
    let debug_enabled = std::env::var("DEBUG")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    env_logger::Builder::from_default_env()
        .filter_level(if debug_enabled { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .init();

    info!("Trusted Workload Docker Deploy starting...");

    // Set up signal handler for graceful shutdown
    let term = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, Arc::clone(&term))?;
    flag::register(SIGINT, Arc::clone(&term))?;

    // Install artifacts
    match copy_artifacts() {
        Ok(_) => info!("Artifacts installed"),
        Err(e) => {
            error!("Failed to install artifacts: {}", e);
            if let Err(ce) = cleanup_artifacts() {
                error!("Cleanup after failed install also failed: {}", ce);
            }
            std::process::exit(1);
        }
    }

    // Copy shim binary to /usr/bin
    match install_shim_binary() {
        Ok(_) => info!("Shim installed"),
        Err(e) => { error!("Failed to install shim: {}", e); std::process::exit(1); }
    }

    // Copy configuration file to /etc/kata-containers
    if let Err(e) = install_config() {
        warn!("Failed to install config: {}", e); // non-fatal
    }

    info!("Installation complete. Waiting for termination signal...");

    // Wait for termination signal
    while !term.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Cleanup on termination
    info!("Received termination signal. Running cleanup...");
    match cleanup_artifacts() {
        Ok(_) => info!("Cleanup complete"),
        Err(e) => { error!("Cleanup failed: {}", e); std::process::exit(1); }
    }
    info!("Shutdown complete");
    Ok(())
}
