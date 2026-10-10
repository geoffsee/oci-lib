// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if let Err(err) = run() {
        eprintln!("build.rs: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // Declare the custom cfg before any crate is compiled. Linux builds leave it unset.
    println!("cargo::rustc-check-cfg=cfg(rob_stub)");
    println!("cargo::rustc-check-cfg=cfg(rob_vm)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=shim");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-env-changed=ROB_GO_TAGS");
    println!("cargo:rerun-if-env-changed=ROB_ALLOW_CROSS");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CGO_ENABLED");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?);
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();
    if pointer_width != "64" {
        return Err(format!(
            "the Buildah ABI is LP64; target pointer width is {pointer_width}"
        ));
    }

    emit_abi(&manifest, &out_dir)?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        // The macOS guest is opt-in. Without the `vm` feature macOS links the stub.
        // `vm` is a default feature. Its build dependencies exist only on a macOS host.
        #[cfg(all(feature = "vm", target_os = "macos"))]
        if target_os == "macos" {
            guest::embed_guest(&manifest, &out_dir)?;
            println!("cargo:rustc-cfg=rob_vm");
        }
        #[cfg(all(feature = "vm", not(target_os = "macos")))]
        if target_os == "macos" {
            println!(
                "cargo:warning=the macOS guest can only be embedded on a macOS host; linking the stub"
            );
        }
        compile_stub();
        return Ok(());
    }

    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    if host != target && env::var_os("ROB_ALLOW_CROSS").is_none() {
        return Err(format!(
            "refusing to cross-compile the Buildah c-archive from {host} to {target}. \
             cgo needs a Linux C toolchain. Set CC and ROB_ALLOW_CROSS=1 to attempt it. \
             Non-Linux hosts link a stub; build on Linux for the real engine."
        ));
    }

    link_go_archive(&manifest, &out_dir, &host, &target)?;
    Ok(())
}

fn compile_stub() {
    let mut build = cc::Build::new();
    build.file("native/stub.c").include("shim/include");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && env::var_os("CARGO_FEATURE_VM").is_none()
    {
        build.define(
            "ROB_STUB_DETAIL",
            "\"This build has the `vm` feature off. macOS runs the engine in a Linux VM; rebuild with default features or `--features vm`.\"",
        );
    }
    build.compile("robshim");
    println!("cargo:rustc-cfg=rob_stub");
}

#[cfg(all(feature = "vm", target_os = "macos"))]
mod guest {
    use super::*;
    use std::io::Read;

    // Same parser diagnose uses. Compiled here so a mismatch fails the build
    // before any guest bytes are embedded.
    // `#[path]` inside this inline module is relative to `guest/`, not build.rs.
    #[path = "../src/guest_attest.rs"]
    mod attest;
    #[path = "../src/guest_check.rs"]
    mod check;
    #[path = "../src/protocol_version.rs"]
    mod protocol_version;

    /// Copy the Linux guest into OUT_DIR so macos.rs can `include_bytes!` it.
    /// The macOS binary only boots these embedded bytes, so a build without a
    /// guest image fails. Sources, in order: `ROB_GUEST_KERNEL` and
    /// `ROB_GUEST_INITRD` plus a sibling `attestation.json`, guest/out (which
    /// must include `attestation.json`), then the download cache. A cache miss
    /// downloads this version's images from the GitHub release and verifies
    /// them. Versions after 0.1.7 also require the release attestation asset.
    pub(super) fn embed_guest(manifest: &Path, out_dir: &Path) -> Result<(), String> {
        println!("cargo:rerun-if-env-changed=ROB_GUEST_KERNEL");
        println!("cargo:rerun-if-env-changed=ROB_GUEST_INITRD");
        println!("cargo:rerun-if-env-changed=ROB_GUEST_CACHE");
        println!("cargo:rerun-if-changed=guest/out/vmlinuz");
        println!("cargo:rerun-if-changed=guest/out/initramfs");
        println!("cargo:rerun-if-changed=guest/out/attestation.json");

        let kernel_dest = out_dir.join("rob-guest-vmlinuz.zst");
        let initrd_dest = out_dir.join("rob-guest-initramfs.zst");
        let package = env::var("CARGO_PKG_NAME").map_err(|e| e.to_string())?;
        let version = env::var("CARGO_PKG_VERSION").map_err(|e| e.to_string())?;
        let (kernel, initrd, attestation) = guest_sources(manifest, out_dir, &package, &version)?;
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
        let attestation_dest = out_dir.join("rob-guest-attestation.json");
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
        manifest: &Path,
        out_dir: &Path,
        package: &str,
        version: &str,
    ) -> Result<(PathBuf, PathBuf, String), String> {
        match (env::var("ROB_GUEST_KERNEL"), env::var("ROB_GUEST_INITRD")) {
            (Ok(kernel), Ok(initrd)) => {
                let pair = (PathBuf::from(kernel), PathBuf::from(initrd));
                if pair.0.is_file() && pair.1.is_file() {
                    let attestation =
                        require_local_attestation(&pair.0, &pair.1, package, version)?;
                    return Ok((pair.0, pair.1, attestation));
                }
                return Err(format!(
                    "ROB_GUEST_KERNEL ({}) or ROB_GUEST_INITRD ({}) is missing",
                    pair.0.display(),
                    pair.1.display()
                ));
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                return Err("set both ROB_GUEST_KERNEL and ROB_GUEST_INITRD".into());
            }
            (Err(_), Err(_)) => {}
        }
        let dir = manifest.join("guest/out");
        let pair = (dir.join("vmlinuz"), dir.join("initramfs"));
        if pair.0.is_file() && pair.1.is_file() {
            let attestation = require_local_attestation(&pair.0, &pair.1, package, version)?;
            return Ok((pair.0, pair.1, attestation));
        }
        cached_guest(out_dir)
    }

    /// Files land in the cache only after their checksum matches, so a cached
    /// file is a verified one and its presence skips the download.
    fn cached_guest(out_dir: &Path) -> Result<(PathBuf, PathBuf, String), String> {
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

        let root = match env::var_os("ROB_GUEST_CACHE") {
            Some(dir) => PathBuf::from(dir),
            None => match env::var("HOME") {
                Ok(home) if !home.is_empty() => {
                    PathBuf::from(home).join(format!("Library/Caches/{package}/downloads"))
                }
                _ => out_dir.join("guest-cache"),
            },
        };
        let dir = root.join(format!("v{version}-{arch}"));
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("creating {}: {err}", dir.display()))?;
        let kernel = dir.join("vmlinuz");
        let initrd = dir.join("initramfs");

        if !kernel.is_file() {
            let url = format!(
                "https://github.com/arcboxlabs/kernel/releases/download/v0.0.25/{kernel_name}"
            );
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
            accept_attestation(&json, &kernel, &initrd, &package, &version).map_err(|err| {
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
        accept_attestation(&json, kernel, initrd, package, version)
            .map_err(|err| format!("{err}; rerun `cargo xtask guest`"))?;
        Ok(json)
    }

    fn accept_attestation(
        json: &str,
        kernel: &Path,
        initrd: &Path,
        package: &str,
        version: &str,
    ) -> Result<(), String> {
        let attestation = attest::parse(json)?;
        check::hashes_match(&attestation, &sha256(kernel)?, &sha256(initrd)?)?;
        check::compatibility_match(
            &attestation,
            package,
            version,
            protocol_version::PROTOCOL_VERSION,
        )
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
                "downloading {url} failed:\n{}\nBuild guest/out with `cargo xtask guest` on Linux, or set ROB_GUEST_KERNEL and ROB_GUEST_INITRD.",
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
}

fn emit_abi(manifest: &Path, out_dir: &Path) -> Result<(), String> {
    let compiler = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let bin = out_dir.join("abi_size");
    let output = Command::new(&compiler)
        .arg("-I")
        .arg(manifest.join("shim/include"))
        .arg("-o")
        .arg(&bin)
        .arg(manifest.join("native/abi_size.c"))
        .output()
        .map_err(|err| format!("compiling abi_size.c with {compiler}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "abi_size.c failed to compile:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let printed = Command::new(&bin)
        .output()
        .map_err(|err| format!("running abi_size: {err}"))?;
    if !printed.status.success() {
        return Err(format!(
            "abi_size failed:\n{}",
            String::from_utf8_lossy(&printed.stderr)
        ));
    }
    std::fs::write(out_dir.join("abi_gen.rs"), &printed.stdout).map_err(|err| err.to_string())?;
    Ok(())
}

fn link_go_archive(
    manifest: &Path,
    out_dir: &Path,
    host: &str,
    target: &str,
) -> Result<(), String> {
    let go = require_go()?;
    let mut tags = vec![
        "exclude_graphdriver_btrfs".to_string(),
        "exclude_graphdriver_devicemapper".to_string(),
        "containers_image_openpgp".to_string(),
    ];
    let skip_optional = env::var_os("ROB_DISABLE_OPTIONAL_LIBS").is_some();
    let seccomp = if skip_optional {
        false
    } else if pkg_config_exists("libseccomp") {
        true
    } else {
        println!(
            "cargo:warning=libseccomp not found; building without the seccomp tag. RUN steps that install a seccomp profile will fail."
        );
        false
    };
    if seccomp {
        tags.push("seccomp".to_string());
    }
    if !skip_optional && pkg_config_exists("libapparmor") {
        tags.push("apparmor".to_string());
    }
    if let Ok(extra) = env::var("ROB_GO_TAGS") {
        tags.extend(
            extra
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }

    let archive = out_dir.join("librobshim.a");
    let mut cmd = Command::new(&go);
    cmd.current_dir(manifest.join("shim"))
        .env("CGO_ENABLED", "1")
        .env("GO111MODULE", "on")
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-trimpath")
        .arg("-mod=readonly")
        .arg("-buildvcs=false")
        .arg("-tags")
        .arg(tags.join(","))
        .arg("-o")
        .arg(&archive)
        .arg(".");
    if host != target {
        cmd.env("GOOS", "linux");
        cmd.env("GOARCH", goarch(target)?);
        if let Ok(cc) = env::var("CC") {
            cmd.env("CC", cc);
        }
    }
    let output = cmd
        .output()
        .map_err(|err| format!("starting `{go} build`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "go build -buildmode=c-archive failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Emit this link line before the c-archive so _containers_unshare resolves
    // from librobshim.a. rob_unshare_keep is referenced from Rust so the
    // constructor object is not dropped.
    cc::Build::new()
        .file("native/unshare_early.c")
        .compile("rob_unshare_early");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=robshim");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=resolv");
    if seccomp {
        link_pkg_config("libseccomp")?;
    }
    if !skip_optional && pkg_config_exists("libapparmor") {
        link_pkg_config("libapparmor")?;
    }
    Ok(())
}

fn require_go() -> Result<String, String> {
    let go = env::var("GO").unwrap_or_else(|_| "go".to_string());
    let output = Command::new(&go).arg("version").output().map_err(|err| {
        format!("`{go}` not found ({err}). Linux builds of this crate need Go >= 1.26.")
    })?;
    if !output.status.success() {
        return Err(format!("`{go} version` failed"));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let token = text
        .split_whitespace()
        .find(|word| word.starts_with("go1.") || word.starts_with("go2."))
        .ok_or_else(|| format!("cannot parse Go version from `{text}`"))?;
    let numeric = token.trim_start_matches("go");
    let mut parts = numeric.split('.');
    let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    if major < 1 || (major == 1 && minor < 26) {
        return Err(format!(
            "{token} is too old. Buildah v1.45.1 requires Go >= 1.26."
        ));
    }
    Ok(go)
}

fn goarch(target: &str) -> Result<&'static str, String> {
    let arch = target.split('-').next().unwrap_or("");
    match arch {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        "arm" => Ok("arm"),
        "riscv64" => Ok("riscv64"),
        "s390x" => Ok("s390x"),
        "powerpc64le" => Ok("ppc64le"),
        other => Err(format!("no GOARCH mapping for target arch {other}")),
    }
}

fn pkg_config_exists(package: &str) -> bool {
    Command::new("pkg-config")
        .args(["--exists", package])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn link_pkg_config(package: &str) -> Result<(), String> {
    let output = Command::new("pkg-config")
        .args(["--libs", package])
        .output()
        .map_err(|err| format!("pkg-config --libs {package}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "pkg-config --libs {package} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for token in text.split_whitespace() {
        if let Some(dir) = token.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={dir}");
        } else if let Some(lib) = token.strip_prefix("-l") {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
    Ok(())
}
