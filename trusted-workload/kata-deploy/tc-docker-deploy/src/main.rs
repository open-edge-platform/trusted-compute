// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{Context, Result};
use log::{error, info, warn};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

const ARTIFACTS_SOURCE: &str = "/opt/kata-artifacts/opt/kata";
const KATA_DEST: &str = "/host/opt/kata";
const SHIM_SOURCE: &str = "/host/opt/kata/bin/containerd-shim-kata-v2";
const SHIM_DEST: &str = "/host/usr/bin/containerd-shim-kata-v2";
const CONFIG_SOURCE: &str = "/host/opt/kata/share/defaults/kata-containers/configuration.toml";
const CONFIG_DEST_DIR: &str = "/host/etc/kata-containers";
const CONFIG_DEST: &str = "/host/etc/kata-containers/configuration.toml";

/// Copy all artifacts from source to destination
fn copy_artifacts() -> Result<()> {
    info!("Copying Kata artifacts from {} to {}", ARTIFACTS_SOURCE, KATA_DEST);
    
    if !Path::new(ARTIFACTS_SOURCE).exists() {
        return Err(anyhow::anyhow!("Artifacts source directory {} does not exist", ARTIFACTS_SOURCE));
    }

    // Create destination directory
    fs::create_dir_all(KATA_DEST)
        .with_context(|| format!("Failed to create directory {}", KATA_DEST))?;

    // Copy all files and directories
    for entry in WalkDir::new(ARTIFACTS_SOURCE)
        .follow_links(false)
        .into_iter()
    {
        let entry = entry.with_context(|| {
            format!(
                "Failed to traverse artifacts source directory {}",
                ARTIFACTS_SOURCE
            )
        })?;
        let src_path = entry.path();
        let relative_path = src_path.strip_prefix(ARTIFACTS_SOURCE)
            .context("Failed to get relative path")?;
        
        if relative_path.as_os_str().is_empty() {
            continue; // Skip root directory
        }

        let dest_path = PathBuf::from(KATA_DEST).join(relative_path);

        if entry.file_type().is_dir() {
            fs::create_dir_all(&dest_path)
                .with_context(|| format!("Failed to create directory {:?}", dest_path))?;
        } else if entry.file_type().is_symlink() {
            let link_target = fs::read_link(src_path)
                .with_context(|| format!("Failed to read symlink {:?}", src_path))?;
            
            // Remove existing symlink if present
            if dest_path.exists() || dest_path.is_symlink() {
                fs::remove_file(&dest_path).ok();
            }
            
            unix_fs::symlink(&link_target, &dest_path)
                .with_context(|| format!("Failed to create symlink {:?} -> {:?}", dest_path, link_target))?;
        } else {
            fs::copy(src_path, &dest_path)
                .with_context(|| format!("Failed to copy {:?} to {:?}", src_path, dest_path))?;
            
            // Preserve permissions
            if let Ok(metadata) = fs::metadata(src_path) {
                let permissions = metadata.permissions();
                fs::set_permissions(&dest_path, permissions).ok();
            }
        }
    }

    info!("Successfully copied all Kata artifacts");
    Ok(())
}

/// Copy the shim binary to /usr/bin
fn install_shim_binary() -> Result<()> {
    if !Path::new(SHIM_SOURCE).exists() {
        warn!("Shim binary not found at {}, skipping copy", SHIM_SOURCE);
        return Ok(());
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
        let permissions = metadata.permissions();
        fs::set_permissions(SHIM_DEST, permissions).ok();
    }
    
    info!("Successfully copied shim binary: {} -> {}", SHIM_SOURCE, SHIM_DEST);
    Ok(())
}

/// Copy configuration.toml to /etc/kata-containers
fn install_config() -> Result<()> {
    if !Path::new(CONFIG_SOURCE).exists() {
        warn!("Config file not found at {}, skipping copy", CONFIG_SOURCE);
        return Ok(());
    }

    // Create destination directory if it doesn't exist
    if !Path::new(CONFIG_DEST_DIR).exists() {
        fs::create_dir_all(CONFIG_DEST_DIR)
            .with_context(|| format!("Failed to create directory {}", CONFIG_DEST_DIR))?;
        info!("Created directory {}", CONFIG_DEST_DIR);
    }

    // Remove existing config file if present
    if Path::new(CONFIG_DEST).exists() {
        fs::remove_file(CONFIG_DEST)
            .with_context(|| format!("Failed to remove existing {}", CONFIG_DEST))?;
    }

    // Copy the config file
    fs::copy(CONFIG_SOURCE, CONFIG_DEST)
        .with_context(|| format!("Failed to copy {} to {}", CONFIG_SOURCE, CONFIG_DEST))?;
    
    info!("Successfully copied config file: {} -> {}", CONFIG_SOURCE, CONFIG_DEST);
    Ok(())
}

/// Remove all Kata artifacts
fn cleanup_artifacts() -> Result<()> {
    info!("Removing Kata artifacts from {}", KATA_DEST);
    
    if Path::new(KATA_DEST).exists() {
        fs::remove_dir_all(KATA_DEST)
            .with_context(|| format!("Failed to remove directory {}", KATA_DEST))?;
        info!("Successfully removed {}", KATA_DEST);
    } else {
        info!("Directory {} does not exist, nothing to clean", KATA_DEST);
    }

    // Remove shim binary
    if Path::new(SHIM_DEST).exists() || Path::new(SHIM_DEST).is_symlink() {
        fs::remove_file(SHIM_DEST)
            .with_context(|| format!("Failed to remove shim binary {}", SHIM_DEST))?;
        info!("Successfully removed shim binary {}", SHIM_DEST);
    }

    // Remove config file
    if Path::new(CONFIG_DEST).exists() {
        fs::remove_file(CONFIG_DEST)
            .with_context(|| format!("Failed to remove config file {}", CONFIG_DEST))?;
        info!("Successfully removed config file {}", CONFIG_DEST);
    }

    // Remove config directory if empty
    if Path::new(CONFIG_DEST_DIR).exists() {
        if let Ok(mut entries) = fs::read_dir(CONFIG_DEST_DIR) {
            if entries.next().is_none() {
                // Directory is empty, remove it
                fs::remove_dir(CONFIG_DEST_DIR)
                    .with_context(|| format!("Failed to remove directory {}", CONFIG_DEST_DIR))?;
                info!("Successfully removed empty directory {}", CONFIG_DEST_DIR);
            } else {
                info!("Directory {} is not empty, skipping removal", CONFIG_DEST_DIR);
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

    let log_level = if debug_enabled {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    info!("Trusted Workload Docker Deploy starting...");

    // Set up signal handler for graceful shutdown
    let term = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, Arc::clone(&term))?;
    flag::register(SIGINT, Arc::clone(&term))?;

    // Install artifacts
    info!("Starting Kata Containers installation...");
    
    match copy_artifacts() {
        Ok(_) => info!("Artifact installation completed successfully"),
        Err(e) => {
            error!("Failed to copy artifacts: {}", e);
            std::process::exit(1);
        }
    }

    // Copy shim binary to /usr/bin
    if let Err(e) = install_shim_binary() {
        warn!("Failed to copy shim binary: {}", e);
        // Don't fail the installation if binary copy fails
    }

    // Copy configuration file to /etc/kata-containers
    if let Err(e) = install_config() {
        warn!("Failed to copy config file: {}", e);
        // Don't fail the installation if config copy fails
    }

    info!("Installation complete. Container will stay running until terminated.");
    info!("Run 'docker compose down' to trigger automatic cleanup.");
    
    // Wait for termination signal
    while !term.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    info!("Received termination signal. Running cleanup...");
    
    // Cleanup on termination
    match cleanup_artifacts() {
        Ok(_) => {
            info!("Cleanup completed successfully");
        }
        Err(e) => {
            error!("Cleanup failed: {}", e);
            std::process::exit(1);
        }
    }

    info!("Shutdown complete");
    Ok(())
}
