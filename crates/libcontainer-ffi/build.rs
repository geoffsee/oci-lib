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
    println!("cargo::rustc-check-cfg=cfg(ror_stub)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=shim");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-env-changed=ROR_GO_TAGS");
    println!("cargo:rerun-if-env-changed=ROR_ALLOW_CROSS");
    println!("cargo:rerun-if-env-changed=ROR_DISABLE_OPTIONAL_LIBS");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CGO_ENABLED");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|e| e.to_string())?);
    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|e| e.to_string())?);
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();
    if pointer_width != "64" {
        return Err(format!(
            "the libcontainer ABI is LP64; target pointer width is {pointer_width}"
        ));
    }

    emit_abi(&manifest, &out_dir)?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        if target_os == "macos" {
            embed_guest(&manifest, &out_dir)?;
        }
        compile_stub();
        return Ok(());
    }

    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    if host != target && env::var_os("ROR_ALLOW_CROSS").is_none() {
        return Err(format!(
            "refusing to cross-compile the libcontainer c-archive from {host} to {target}. \
             Set CC and ROR_ALLOW_CROSS=1 to attempt it. Non-Linux hosts link a stub."
        ));
    }

    link_go_archive(&manifest, &out_dir, &host, &target)?;
    Ok(())
}

fn compile_stub() {
    cc::Build::new()
        .file("native/stub.c")
        .include("shim/include")
        .compile("rorshim");
    println!("cargo:rustc-cfg=ror_stub");
}

fn embed_guest(manifest: &Path, out_dir: &Path) -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=ROR_GUEST_KERNEL");
    println!("cargo:rerun-if-env-changed=ROR_GUEST_INITRD");
    println!("cargo:rerun-if-env-changed=ROR_REQUIRE_EMBEDDED_GUEST");
    println!("cargo:rerun-if-changed=../../guest/out/vmlinuz");
    println!("cargo:rerun-if-changed=../../guest/out/initramfs");

    let kernel_dest = out_dir.join("ror-guest-vmlinuz");
    let initrd_dest = out_dir.join("ror-guest-initramfs");
    match guest_sources(manifest)? {
        Some((kernel, initrd)) => {
            println!("cargo:rerun-if-changed={}", kernel.display());
            println!("cargo:rerun-if-changed={}", initrd.display());
            std::fs::copy(&kernel, &kernel_dest)
                .map_err(|err| format!("copying {}: {err}", kernel.display()))?;
            std::fs::copy(&initrd, &initrd_dest)
                .map_err(|err| format!("copying {}: {err}", initrd.display()))?;
            if std::fs::metadata(&kernel_dest)
                .map(|m| m.len())
                .unwrap_or(0)
                == 0
                || std::fs::metadata(&initrd_dest)
                    .map(|m| m.len())
                    .unwrap_or(0)
                    == 0
            {
                return Err("refusing to embed an empty guest kernel or initramfs".into());
            }
        }
        None => {
            std::fs::write(&kernel_dest, []).map_err(|err| err.to_string())?;
            std::fs::write(&initrd_dest, []).map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

fn guest_sources(manifest: &Path) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let kernel_env = env::var("ROR_GUEST_KERNEL");
    let initrd_env = env::var("ROR_GUEST_INITRD");
    let (pair, from_env) = match (kernel_env, initrd_env) {
        (Ok(kernel), Ok(initrd)) => ((PathBuf::from(kernel), PathBuf::from(initrd)), true),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            return Err("set both ROR_GUEST_KERNEL and ROR_GUEST_INITRD".into());
        }
        (Err(_), Err(_)) => {
            let dir = manifest.join("../../guest/out");
            ((dir.join("vmlinuz"), dir.join("initramfs")), false)
        }
    };
    if pair.0.is_file() && pair.1.is_file() {
        return Ok(Some(pair));
    }
    if env::var_os("ROR_REQUIRE_EMBEDDED_GUEST").is_some() {
        return Err(format!(
            "refusing to build without a Linux guest image. Looked for {} and {}.",
            pair.0.display(),
            pair.1.display()
        ));
    }
    if from_env {
        return Err(format!(
            "ROR_GUEST_KERNEL ({}) or ROR_GUEST_INITRD ({}) is missing",
            pair.0.display(),
            pair.1.display()
        ));
    }
    println!(
        "cargo:warning=Linux guest images not found; the macOS binary will look for guest/out at runtime"
    );
    Ok(None)
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
    let mut tags = Vec::new();
    let skip_optional = env::var_os("ROR_DISABLE_OPTIONAL_LIBS").is_some();
    let seccomp = if skip_optional {
        false
    } else if pkg_config_exists("libseccomp") {
        true
    } else {
        println!("cargo:warning=libseccomp not found; building without the seccomp tag");
        false
    };
    if seccomp {
        tags.push("seccomp".to_string());
    }
    if let Ok(extra) = env::var("ROR_GO_TAGS") {
        tags.extend(
            extra
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }

    let archive = out_dir.join("librorshim.a");
    let mut cmd = Command::new(&go);
    cmd.current_dir(manifest.join("shim"))
        .env("CGO_ENABLED", "1")
        .env("GO111MODULE", "on")
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-trimpath")
        .arg("-mod=readonly")
        .arg("-buildvcs=false");
    if !tags.is_empty() {
        cmd.arg("-tags").arg(tags.join(","));
    }
    cmd.arg("-o").arg(&archive).arg(".");
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

    cc::Build::new()
        .file("native/nsexec_early.c")
        .compile("ror_nsexec_early");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=rorshim");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=resolv");
    if seccomp {
        link_pkg_config("libseccomp")?;
    }
    Ok(())
}

fn require_go() -> Result<String, String> {
    let go = env::var("GO").unwrap_or_else(|_| "go".to_string());
    let output = Command::new(&go)
        .arg("version")
        .output()
        .map_err(|err| format!("`{go}` not found ({err}). Linux builds need Go >= 1.26."))?;
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
            "{token} is too old. runc v1.5.2 requires Go >= 1.26."
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
