// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn bin() -> PathBuf {
    // Cargo 1.99 sets CARGO_BIN_EXE_<name> only while it runs the harness.
    // `env!` fails under `cargo clippy` and under `cargo test --no-run`.
    // The release jobs compile with `--no-run` and exec the harness themselves,
    // so fall back to the package binary next to `target/.../deps`.
    let path = std::env::var_os("CARGO_BIN_EXE_oci-builder")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let exe = std::env::current_exe().expect("test executable");
            exe.parent()
                .and_then(|dir| dir.parent())
                .map(|dir| dir.join(format!("oci-builder{}", std::env::consts::EXE_SUFFIX)))
                .expect("oci-builder beside the test harness")
        });
    #[cfg(target_os = "macos")]
    {
        use std::sync::Once;
        static SIGN: Once = Once::new();
        let to_sign = path.clone();
        SIGN.call_once(|| {
            let entitlements =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/entitlements.plist");
            let status = Command::new("codesign")
                .arg("--force")
                .arg("--sign")
                .arg("-")
                .arg("--entitlements")
                .arg(&entitlements)
                .arg(&to_sign)
                .status()
                .expect("codesign");
            assert!(
                status.success(),
                "codesign failed for {}",
                to_sign.display()
            );
        });
    }
    path
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rob-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn combined(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn stub_message(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("linux only") || lower.contains("unsupported")
}

#[test]
fn diagnose_reports_readiness_or_the_stub() {
    let output = Command::new(bin()).arg("diagnose").output().unwrap();
    let text = combined(&output);
    if stub_message(&text) {
        assert!(!output.status.success(), "{text}");
        return;
    }
    if output.status.success() {
        assert!(text.contains("status: ready"), "{text}");
    } else {
        assert!(
            text.contains("status: blocked") || text.contains("[fail]"),
            "{text}"
        );
    }
}

#[test]
fn build_scratch_image_and_optional_push() {
    let probe = Command::new(bin()).arg("diagnose").output().unwrap();
    let probe_text = combined(&probe);
    if stub_message(&probe_text) || !probe.status.success() {
        if std::env::var_os("ROB_REQUIRE_BUILD").is_some() {
            panic!("this runner must be able to build, diagnose said:\n{probe_text}");
        }
        eprintln!("skipping image build:\n{probe_text}");
        return;
    }

    let dir = TempDir::new("build");
    let context = dir.path().join("context");
    std::fs::create_dir_all(&context).unwrap();
    std::fs::write(
        context.join("Dockerfile"),
        "FROM scratch\nCOPY hello.txt /hello.txt\n",
    )
    .unwrap();
    std::fs::write(context.join("hello.txt"), "hello\n").unwrap();
    let policy = dir.path().join("policy.json");
    std::fs::write(
        &policy,
        r#"{"default":[{"type":"insecureAcceptAnything"}]}"#,
    )
    .unwrap();
    let registries = dir.path().join("registries.conf");
    std::fs::write(
        &registries,
        "unqualified-search-registries = [\"docker.io\"]\n",
    )
    .unwrap();
    let graph = dir.path().join("graph");
    let run = dir.path().join("run");
    std::fs::create_dir_all(&graph).unwrap();
    std::fs::create_dir_all(&run).unwrap();

    let common = [
        "--root",
        graph.to_str().unwrap(),
        "--runroot",
        run.to_str().unwrap(),
        "--storage-driver",
        "vfs",
        "--signature-policy",
        policy.to_str().unwrap(),
        "--registries-conf",
        registries.to_str().unwrap(),
        "--log-level",
        "info",
    ];

    let output = Command::new(bin())
        .args(common)
        .args([
            "build",
            "-f",
            context.join("Dockerfile").to_str().unwrap(),
            "-t",
            "localhost/rob-test:latest",
            "--context",
            context.to_str().unwrap(),
            "--pull",
            "never",
            "--isolation",
            "chroot",
            "--format",
            "oci",
        ])
        .output()
        .unwrap();
    let text = combined(&output);
    assert!(
        output.status.success(),
        "build failed ({}):\n{text}",
        output.status
    );
    assert!(
        output_has_prefix(&output.stdout, "image_id="),
        "stdout missing image_id:\n{text}"
    );
    assert!(
        stdout_digest_is_sha256(&output.stdout),
        "stdout missing digest=sha256:\n{text}"
    );

    let Ok(registry) = std::env::var("ROB_TEST_REGISTRY") else {
        return;
    };
    if registry.is_empty() {
        return;
    }
    let dest = format!("{registry}/rob-test:latest");
    let mut pushed = None;
    for _ in 0..5 {
        let attempt = Command::new(bin())
            .args(common)
            .args(["push", "localhost/rob-test:latest", &dest, "--insecure"])
            .output()
            .unwrap();
        if attempt.status.success() && stdout_digest_is_sha256(&attempt.stdout) {
            pushed = Some(attempt);
            break;
        }
        pushed = Some(attempt);
        std::thread::sleep(Duration::from_secs(1));
    }
    let pushed = pushed.expect("push attempt");
    let push_text = combined(&pushed);
    assert!(
        pushed.status.success(),
        "push to {dest} failed:\n{push_text}"
    );
    assert!(
        stdout_digest_is_sha256(&pushed.stdout),
        "push stdout missing digest:\n{push_text}"
    );
}

#[test]
fn example_contexts_match_their_documented_results() {
    let probe = Command::new(bin()).arg("diagnose").output().unwrap();
    let probe_text = combined(&probe);
    if stub_message(&probe_text) || !probe.status.success() {
        if std::env::var_os("ROB_REQUIRE_BUILD").is_some() {
            panic!("this runner must be able to build, diagnose said:\n{probe_text}");
        }
        eprintln!("skipping example builds:\n{probe_text}");
        return;
    }

    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    assert!(
        examples.join("scratch-copy/Dockerfile").is_file(),
        "missing {}",
        examples.display()
    );

    let dir = TempDir::new("examples");
    let policy = dir.path().join("policy.json");
    std::fs::write(
        &policy,
        r#"{"default":[{"type":"insecureAcceptAnything"}]}"#,
    )
    .unwrap();
    let registries = dir.path().join("registries.conf");
    std::fs::write(
        &registries,
        "unqualified-search-registries = [\"docker.io\"]\n",
    )
    .unwrap();
    let graph = dir.path().join("graph");
    let run = dir.path().join("run");
    std::fs::create_dir_all(&graph).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    let common = [
        "--root",
        graph.to_str().unwrap(),
        "--runroot",
        run.to_str().unwrap(),
        "--storage-driver",
        "vfs",
        "--signature-policy",
        policy.to_str().unwrap(),
        "--registries-conf",
        registries.to_str().unwrap(),
        "--log-level",
        "info",
    ];

    let ok = [
        (
            "scratch-copy",
            Some("Dockerfile"),
            &[][..],
            "localhost/ex-scratch:latest",
        ),
        (
            "build-args",
            Some("Dockerfile"),
            &["--build-arg", "GREETING=world"][..],
            "localhost/ex-args:latest",
        ),
        (
            "multi-stage",
            Some("Dockerfile"),
            &[][..],
            "localhost/ex-final:latest",
        ),
        (
            "multi-stage",
            Some("Dockerfile"),
            &["--target", "docs"][..],
            "localhost/ex-docs:latest",
        ),
        (
            "multi-stage",
            Some("Dockerfile"),
            &["--target", "final"][..],
            "localhost/ex-final-explicit:latest",
        ),
        (
            "containerfile",
            None,
            &[][..],
            "localhost/ex-containerfile:latest",
        ),
        (
            "dockerignore",
            Some("Dockerfile"),
            &[][..],
            "localhost/ex-ignore:latest",
        ),
    ];
    for (name, file, extra, tag) in ok {
        let output = run_build(&common, &examples.join(name), file, extra, tag);
        assert_build_ok(&output, name);
    }

    for name in ["missing-copy", "unknown-instruction"] {
        let output = run_build(
            &common,
            &examples.join(name),
            Some("Dockerfile"),
            &[],
            "localhost/ex-should-fail:latest",
        );
        assert_build_failed(&output, name);
    }

    let missing_target = run_build(
        &common,
        &examples.join("multi-stage"),
        Some("Dockerfile"),
        &["--target", "missing"],
        "localhost/ex-missing-target:latest",
    );
    assert_build_failed(&missing_target, "multi-stage --target missing");
}

fn run_build(
    common: &[&str],
    context: &Path,
    dockerfile: Option<&str>,
    extra: &[&str],
    tag: &str,
) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.args(common).arg("build");
    if let Some(file) = dockerfile {
        cmd.arg("-f").arg(context.join(file));
    }
    cmd.args(["-t", tag, "--context"])
        .arg(context)
        .args([
            "--pull",
            "never",
            "--isolation",
            "chroot",
            "--format",
            "oci",
        ])
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn macos_scratch_copy_example_when_guest_image_is_present() {
    if !cfg!(rob_vm) {
        eprintln!("skipping macOS guest build on this host");
        return;
    }
    let guest_out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../guest/out");
    let kernel = guest_out.join("vmlinuz");
    let initrd = guest_out.join("initramfs");
    if !kernel.is_file() || !initrd.is_file() {
        eprintln!(
            "skipping scratch-copy guest build; {} is missing",
            guest_out.display()
        );
        return;
    }

    let dir = TempDir::new("macos-scratch");
    let policy = dir.path().join("policy.json");
    std::fs::write(
        &policy,
        r#"{"default":[{"type":"insecureAcceptAnything"}]}"#,
    )
    .unwrap();
    let graph = dir.path().join("graph");
    let run = dir.path().join("run");
    let context = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/scratch-copy");
    let output = Command::new(bin())
        .args([
            "--root",
            graph.to_str().unwrap(),
            "--runroot",
            run.to_str().unwrap(),
            "--storage-driver",
            "vfs",
            "--signature-policy",
            policy.to_str().unwrap(),
            "build",
            "--context",
            context.to_str().unwrap(),
            "-t",
            "localhost/scratch-copy:latest",
            "--pull",
            "never",
            "--isolation",
            "chroot",
        ])
        .output()
        .unwrap();
    assert_build_ok(&output, "scratch-copy");
}

fn assert_build_ok(output: &std::process::Output, name: &str) {
    let text = combined(output);
    assert!(
        output.status.success(),
        "{name} failed ({}):\n{text}",
        output.status
    );
    assert!(
        output_has_prefix(&output.stdout, "image_id="),
        "{name} missing image_id:\n{text}"
    );
    assert!(
        stdout_digest_is_sha256(&output.stdout),
        "{name} missing digest:\n{text}"
    );
}

fn assert_build_failed(output: &std::process::Output, name: &str) {
    let text = combined(output);
    assert_eq!(
        output.status.code(),
        Some(5),
        "{name} expected exit 5:\n{text}"
    );
}

fn output_has_prefix(stdout: &[u8], prefix: &str) -> bool {
    String::from_utf8_lossy(stdout)
        .lines()
        .any(|line| line.starts_with(prefix) && line.len() > prefix.len())
}

fn stdout_digest_is_sha256(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout).lines().any(|line| {
        line.strip_prefix("digest=")
            .is_some_and(|rest| rest.starts_with("sha256:"))
    })
}
