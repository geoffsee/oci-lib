// SPDX-License-Identifier: Apache-2.0

//! Build-script helpers that embed a Linux guest into `OUT_DIR`.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::vm::attest;
use crate::vm::check;
use crate::vm::config::EmbedConfig;

pub fn embed_guest(config: &EmbedConfig, manifest: &Path, out_dir: &Path) -> Result<(), String> {
    println!("cargo:rerun-if-env-changed={}", config.kernel_env);
    println!("cargo:rerun-if-env-changed={}", config.initrd_env);
    println!("cargo:rerun-if-env-changed={}", config.cache_env);
    println!("cargo:rerun-if-changed=guest/out/vmlinuz");
    println!("cargo:rerun-if-changed=guest/out/initramfs");
    println!("cargo:rerun-if-changed=guest/out/attestation.json");

    let kernel_dest = out_dir.join(config.out_kernel_name);
    let initrd_dest = out_dir.join(config.out_initrd_name);
    let package = env::var("CARGO_PKG_NAME").map_err(|e| e.to_string())?;
    let version = env::var("CARGO_PKG_VERSION").map_err(|e| e.to_string())?;
    let (kernel, initrd, attestation) =
        guest_sources(config, manifest, out_dir, &package, &version)?;
    println!("cargo:rerun-if-changed={}", kernel.display());
    println!("cargo:rerun-if-changed={}", initrd.display());
    let kernel_bytes =
        std::fs::read(&kernel).map_err(|err| format!("reading {}: {err}", kernel.display()))?;
    let mut initrd_bytes =
        std::fs::read(&initrd).map_err(|err| format!("reading {}: {err}", initrd.display()))?;
    if kernel_bytes.is_empty() || initrd_bytes.is_empty() {
        return Err("refusing to embed an empty guest kernel or initramfs".into());
    }
    // `cargo xtask guest` gzips the cpio archive. zstd compresses the raw archive
    // better than it compresses gzip output, and the kernel boots a plain cpio.
    if initrd_bytes.starts_with(&[0x1f, 0x8b]) {
        let mut raw = Vec::new();
        flate2::read::MultiGzDecoder::new(&initrd_bytes[..])
            .read_to_end(&mut raw)
            .map_err(|err| format!("gunzipping {}: {err}", initrd.display()))?;
        initrd_bytes = raw;
    }
    write_zstd(&kernel_bytes, &kernel_dest)?;
    write_zstd(&initrd_bytes, &initrd_dest)?;
    let attestation_dest = out_dir.join(config.out_attestation_name);
    std::fs::write(&attestation_dest, attestation)
        .map_err(|err| format!("writing {}: {err}", attestation_dest.display()))?;
    Ok(())
}

fn write_zstd(bytes: &[u8], dest: &Path) -> Result<(), String> {
    let compressed = zstd::encode_all(bytes, 19)
        .map_err(|err| format!("compressing {}: {err}", dest.display()))?;
    std::fs::write(dest, compressed).map_err(|err| format!("writing {}: {err}", dest.display()))
}

fn guest_sources(
    config: &EmbedConfig,
    manifest: &Path,
    out_dir: &Path,
    package: &str,
    version: &str,
) -> Result<(PathBuf, PathBuf, String), String> {
    match (env::var(config.kernel_env), env::var(config.initrd_env)) {
        (Ok(kernel), Ok(initrd)) => {
            let pair = (PathBuf::from(kernel), PathBuf::from(initrd));
            if pair.0.is_file() && pair.1.is_file() {
                let attestation =
                    require_local_attestation(config, &pair.0, &pair.1, package, version)?;
                return Ok((pair.0, pair.1, attestation));
            }
            return Err(format!(
                "{} ({}) or {} ({}) is missing",
                config.kernel_env,
                pair.0.display(),
                config.initrd_env,
                pair.1.display()
            ));
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            return Err(format!(
                "set both {} and {}",
                config.kernel_env, config.initrd_env
            ));
        }
        (Err(_), Err(_)) => {}
    }
    let dir = manifest.join("guest/out");
    let pair = (dir.join("vmlinuz"), dir.join("initramfs"));
    if pair.0.is_file() && pair.1.is_file() {
        let attestation = require_local_attestation(config, &pair.0, &pair.1, package, version)?;
        return Ok((pair.0, pair.1, attestation));
    }
    cached_guest(config, out_dir)
}

/// Files land in the cache only after their checksum matches, so a cached
/// file is a verified one and its presence skips the download.
fn cached_guest(
    config: &EmbedConfig,
    out_dir: &Path,
) -> Result<(PathBuf, PathBuf, String), String> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let (kernel_name, kernel_sha) = match arch.as_str() {
        "aarch64" => (
            "kernel-arm64",
            "a122ce7a69a77408eeef9423afd9f6915828ba74a767e3e1eace635f913e02c4",
        ),
        "x86_64" => (
            "kernel-x86_64",
            "04f18c7f3a9bc6a26c601b472a7b95fd5e69f3cbbdc06622f731d7529aecf165",
        ),
        other => return Err(format!("no Linux guest kernel for target arch {other}")),
    };
    let package = env::var("CARGO_PKG_NAME").map_err(|e| e.to_string())?;
    let version = env::var("CARGO_PKG_VERSION").map_err(|e| e.to_string())?;
    let repository = env::var("CARGO_PKG_REPOSITORY").map_err(|e| e.to_string())?;

    let root = match env::var_os(config.cache_env) {
        Some(dir) => PathBuf::from(dir),
        None => match env::var("HOME") {
            Ok(home) if !home.is_empty() => {
                PathBuf::from(home).join(format!("Library/Caches/{package}/downloads"))
            }
            _ => out_dir.join("guest-cache"),
        },
    };
    let dir = root.join(format!("v{version}-{arch}"));
    std::fs::create_dir_all(&dir).map_err(|err| format!("creating {}: {err}", dir.display()))?;
    let kernel = dir.join("vmlinuz");
    let initrd = dir.join("initramfs");

    if !kernel.is_file() {
        let url =
            format!("https://github.com/arcboxlabs/kernel/releases/download/v0.0.25/{kernel_name}");
        download(&url, &kernel, kernel_sha)?;
    }
    let release = format!(
        "{}/releases/download/v{version}",
        repository.trim_end_matches('/')
    );
    if !initrd.is_file() {
        let asset = format!("{package}-v{version}-{arch}-initramfs");
        let sha = release_asset_sha(&release, &dir, &asset)?;
        download(&format!("{release}/{asset}"), &initrd, &sha)?;
    }
    let attestation = if check::version_requires_guest_attestation(&version) {
        let path = dir.join("attestation.json");
        if !path.is_file() {
            let asset = format!("{package}-v{version}-{arch}-guest-attestation.json");
            let sha = release_asset_sha(&release, &dir, &asset)?;
            download(&format!("{release}/{asset}"), &path, &sha)?;
        }
        println!("cargo:rerun-if-changed={}", path.display());
        let json = std::fs::read_to_string(&path)
            .map_err(|err| format!("reading {}: {err}", path.display()))?;
        accept_attestation(config, &json, &kernel, &initrd, &package, &version).map_err(|err| {
            format!(
                "{err}; refusing to embed a guest whose attestation does not match the downloaded files"
            )
        })?;
        json
    } else {
        return Err(format!(
            "release guest v{version} has no compatibility attestation; refusing to embed it"
        ));
    };
    Ok((kernel, initrd, attestation))
}

/// `attestation.json` sits next to the initramfs. A missing file or a hash
/// that does not match the blobs on disk means the guest was not built by
/// the current xtask.
fn require_local_attestation(
    config: &EmbedConfig,
    kernel: &Path,
    initrd: &Path,
    package: &str,
    version: &str,
) -> Result<String, String> {
    let attestation = match initrd.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("attestation.json"),
        _ => PathBuf::from("attestation.json"),
    };
    if !attestation.is_file() {
        return Err(format!(
            "missing {}; rerun `cargo xtask guest`",
            attestation.display()
        ));
    }
    println!("cargo:rerun-if-changed={}", attestation.display());
    let json = std::fs::read_to_string(&attestation)
        .map_err(|err| format!("reading {}: {err}", attestation.display()))?;
    accept_attestation(config, &json, kernel, initrd, package, version)
        .map_err(|err| format!("{err}; rerun `cargo xtask guest`"))?;
    Ok(json)
}

fn accept_attestation(
    config: &EmbedConfig,
    json: &str,
    kernel: &Path,
    initrd: &Path,
    package: &str,
    version: &str,
) -> Result<(), String> {
    let attestation = attest::parse(json)?;
    check::hashes_match(&attestation, &sha256(kernel)?, &sha256(initrd)?)?;
    check::compatibility_match(&attestation, package, version, config.protocol_version)
}

fn release_asset_sha(release: &str, dir: &Path, asset: &str) -> Result<String, String> {
    let sums = dir.join("SHA256SUMS");
    curl(&format!("{release}/SHA256SUMS"), &sums)?;
    let text = std::fs::read_to_string(&sums)
        .map_err(|err| format!("reading {}: {err}", sums.display()))?;
    let _ = std::fs::remove_file(&sums);
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?, fields.next()?))
        })
        .find(|(_, name)| name.trim_start_matches("./") == asset)
        .map(|(sha, _)| sha.to_string())
        .ok_or_else(|| format!("{release}/SHA256SUMS does not list {asset}"))
}

fn download(url: &str, dest: &Path, sha: &str) -> Result<(), String> {
    let partial = dest.with_extension("partial");
    curl(url, &partial)?;
    let got = sha256(&partial)?;
    if got != sha {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("checksum mismatch for {url}: got {got} want {sha}"));
    }
    std::fs::rename(&partial, dest).map_err(|err| {
        format!(
            "renaming {} to {}: {err}",
            partial.display(),
            dest.display()
        )
    })
}

fn curl(url: &str, dest: &Path) -> Result<(), String> {
    println!("cargo:warning=downloading {url}");
    let output = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(dest)
        .arg(url)
        .output()
        .map_err(|err| format!("starting curl for {url}: {err}"))?;
    if !output.status.success() {
        let _ = std::fs::remove_file(dest);
        return Err(format!(
            "downloading {url} failed:\n{}\nBuild guest/out with `cargo xtask guest` on Linux, or set guest kernel/initrd env vars.",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .or_else(|_| Command::new("sha256sum").arg(path).output())
        .map_err(|err| format!("hashing {}: {err}", path.display()))?;
    if !output.status.success() {
        return Err(format!("hashing {} failed", path.display()));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| format!("no hash printed for {}", path.display()))
}
