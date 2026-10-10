// SPDX-License-Identifier: Apache-2.0

//! Ignore-file selection and dockerignore matching.
//!
//! Selection follows Buildah v1.45.1 `parse.ContainerIgnoreFile`. Buildah's
//! `BuildOptions.Excludes` replaces the ignore file when it is non-empty, so
//! the file's patterns and [`crate::BuildRequest::excludes`] are combined
//! here and passed as that list.

// The matcher and the staging copy run on macOS and in tests. Linux releases
// pass the same patterns to Buildah and do not stage a tree.
#![cfg_attr(not(any(rob_vm, test)), allow(dead_code))]

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, ErrorCode, Result};

/// Patterns from the selected ignore file, then `extra`.
///
/// Empty means neither a file nor extra patterns contributed anything.
/// `extra` uses the same syntax and does not disable the file.
pub(crate) fn collect_excludes(
    context: &Path,
    dockerfile: &Path,
    extra: &[String],
) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    if let Some(path) = select_ignore_file(context, dockerfile) {
        let text = fs::read_to_string(&path).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("ignore file {}: {err}", path.display()),
                "",
            )
        })?;
        patterns.extend(parse_ignore(&text));
    }
    for item in extra {
        patterns.extend(parse_ignore(item));
    }
    Ok(patterns)
}

/// Whether `rel` (slash-separated, relative to the context) is excluded.
///
/// Last match wins. A pattern without a slash, such as `.env*`, matches only
/// that path and does not match `nested/.env.synthetic`.
#[cfg(test)]
fn is_excluded(rel: &str, patterns: &[String]) -> Result<bool> {
    Ok(Matcher::compile(patterns)?.excludes(rel))
}

/// Copy `context` to `dest`, leaving excluded paths out.
///
/// The Dockerfile is always copied, even when a pattern names it. Ignore
/// files are left out: the guest does not need them once the patterns were
/// collected. `dest` must not be inside `context`.
pub(crate) fn stage_context(
    context: &Path,
    dockerfile: &Path,
    patterns: &[String],
    dest: &Path,
) -> Result<()> {
    let context = context.canonicalize().map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("context {}: {err}", context.display()),
            "",
        )
    })?;
    if !dest.is_dir() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("stage destination is not a directory: {}", dest.display()),
            "",
        ));
    }
    let dest = dest.canonicalize().map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("stage destination {}: {err}", dest.display()),
            "",
        )
    })?;
    if dest.starts_with(&context) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "stage destination is inside the build context",
            "",
        ));
    }
    let dockerfile_rel = rel_text(&rel_of(&context, dockerfile)?)?;
    let matcher = Matcher::compile(patterns)?;
    copy_tree(&context, &context, &dest, &dockerfile_rel, &matcher)?;
    let staged = dest.join(&dockerfile_rel);
    if !staged.is_file() {
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
        fs::copy(dockerfile, &staged).map_err(io_err)?;
    }
    Ok(())
}

/// Buildah checks `<Dockerfile>.containerignore` and then
/// `<Dockerfile>.dockerignore`, so the latter wins when both exist.
/// Otherwise the context-root `.containerignore` is used when present, else
/// the context-root `.dockerignore`. The two root files are not merged.
fn select_ignore_file(context: &Path, dockerfile: &Path) -> Option<PathBuf> {
    let mut chosen = None;
    let beside_container = sidecar(dockerfile, ".containerignore");
    let beside_docker = sidecar(dockerfile, ".dockerignore");
    if beside_container.is_file() {
        chosen = Some(beside_container);
    }
    if beside_docker.is_file() {
        chosen = Some(beside_docker);
    }
    if chosen.is_some() {
        return chosen;
    }
    let root_container = context.join(".containerignore");
    if root_file(context, &root_container) {
        return Some(root_container);
    }
    let root_docker = context.join(".dockerignore");
    if root_file(context, &root_docker) {
        return Some(root_docker);
    }
    None
}

fn sidecar(dockerfile: &Path, suffix: &str) -> PathBuf {
    let mut name = dockerfile.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn root_file(context: &Path, candidate: &Path) -> bool {
    if !candidate.is_file() {
        return false;
    }
    let Ok(path) = candidate.canonicalize() else {
        return false;
    };
    // `/tmp` on macOS canonicalizes to `/private/tmp`. Compare both canonical.
    let context = context
        .canonicalize()
        .unwrap_or_else(|_| context.to_path_buf());
    path.starts_with(context)
}

/// `imagebuilder.ParseIgnoreReader`: drop blanks and `#` comments, trim `/`.
fn parse_ignore(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let trimmed = line.trim_matches('/');
        if trimmed.is_empty() || trimmed.trim().is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }
    out
}

fn rel_of(context: &Path, path: &Path) -> Result<PathBuf> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    path.strip_prefix(context)
        .map(Path::to_path_buf)
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "dockerfile {} is outside the build context {}",
                    path.display(),
                    context.display()
                ),
                "",
            )
        })
}

fn rel_text(rel: &Path) -> Result<String> {
    let mut out = String::new();
    for component in rel.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let text = name.to_str().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("path is not valid Unicode: {}", rel.display()),
                "",
            )
        })?;
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(text);
    }
    Ok(out)
}

fn omitted_ignore(rel: &str, dockerfile_rel: &str) -> bool {
    rel == ".containerignore"
        || rel == ".dockerignore"
        || rel == format!("{dockerfile_rel}.containerignore")
        || rel == format!("{dockerfile_rel}.dockerignore")
}

fn copy_tree(
    context: &Path,
    dir: &Path,
    dest: &Path,
    dockerfile_rel: &str,
    matcher: &Matcher,
) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(io_err)?;
    for entry in entries {
        let entry = entry.map_err(io_err)?;
        let path = entry.path();
        let rel = path.strip_prefix(context).unwrap_or(&path);
        let rel_text = rel_text(rel)?;
        if rel_text.is_empty() {
            continue;
        }
        let keep_dockerfile = rel_text == dockerfile_rel;
        if !keep_dockerfile
            && (omitted_ignore(&rel_text, dockerfile_rel) || matcher.excludes(&rel_text))
        {
            continue;
        }
        let target = dest.join(rel);
        let file_type = entry.file_type().map_err(io_err)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
        if file_type.is_symlink() {
            copy_symlink(&path, &target)?;
        } else if file_type.is_dir() {
            fs::create_dir_all(&target).map_err(io_err)?;
            copy_tree(context, &path, dest, dockerfile_rel, matcher)?;
        } else {
            fs::copy(&path, &target).map_err(io_err)?;
        }
    }
    Ok(())
}

fn copy_symlink(src: &Path, dest: &Path) -> Result<()> {
    let target = fs::read_link(src).map_err(io_err)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest).map_err(io_err)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        fs::copy(src, dest).map_err(io_err)?;
        Ok(())
    }
}

fn io_err(err: std::io::Error) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("staging build context: {err}"),
        "",
    )
}

struct Compiled {
    negate: bool,
    pattern: String,
}

struct Matcher {
    patterns: Vec<Compiled>,
}

impl Matcher {
    fn compile(patterns: &[String]) -> Result<Self> {
        let mut compiled = Vec::new();
        for pattern in patterns {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                continue;
            }
            let cleaned = clean_path(trimmed);
            if let Some(rest) = cleaned.strip_prefix('!') {
                if rest.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "illegal exclusion pattern: \"!\"",
                        "",
                    ));
                }
                compiled.push(Compiled {
                    negate: true,
                    pattern: rest.to_string(),
                });
            } else {
                compiled.push(Compiled {
                    negate: false,
                    pattern: cleaned,
                });
            }
        }
        Ok(Self { patterns: compiled })
    }

    /// Moby `MatchesOrParentMatches`: a matching parent directory excludes
    /// its children, and a later `!` pattern can include again.
    fn excludes(&self, rel: &str) -> bool {
        let path = clean_path(rel);
        if path.is_empty() || path == "." {
            return false;
        }
        let mut matched = false;
        for pattern in &self.patterns {
            if pattern.negate != matched {
                continue;
            }
            let hit = glob_match(&pattern.pattern, &path) || parent_match(&pattern.pattern, &path);
            if hit {
                matched = !pattern.negate;
            }
        }
        matched
    }
}

fn parent_match(pattern: &str, path: &str) -> bool {
    let mut acc = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 2 {
        return false;
    }
    for part in &parts[..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        if glob_match(pattern, &acc) {
            return true;
        }
    }
    false
}

/// `filepath.Clean` for slash-separated patterns. `**` is an ordinary name.
fn clean_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        if absolute {
            "/".to_string()
        } else {
            ".".to_string()
        }
    } else if absolute {
        format!("/{}", out.join("/"))
    } else {
        out.join("/")
    }
}

/// Docker dockerignore match: `*` and `?` do not cross `/`, `**` does.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_bytes(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    while pi < pat.len() {
        if pat[pi] == b'*' {
            let double = pi + 1 < pat.len() && pat[pi + 1] == b'*';
            if double {
                pi += 2;
                if pi < pat.len() && pat[pi] == b'/' {
                    pi += 1;
                }
                if pi == pat.len() {
                    return true;
                }
                if glob_bytes(&pat[pi..], &text[ti..]) {
                    return true;
                }
                let mut k = ti;
                while k < text.len() {
                    if text[k] == b'/' && glob_bytes(&pat[pi..], &text[k + 1..]) {
                        return true;
                    }
                    k += 1;
                }
                return false;
            }
            pi += 1;
            loop {
                if glob_bytes(&pat[pi..], &text[ti..]) {
                    return true;
                }
                if ti >= text.len() || text[ti] == b'/' {
                    return false;
                }
                ti += 1;
            }
        } else if pat[pi] == b'?' {
            if ti >= text.len() || text[ti] == b'/' {
                return false;
            }
            pi += 1;
            ti += 1;
        } else if pat[pi] == b'\\' {
            pi += 1;
            if pi >= pat.len() || ti >= text.len() || text[ti] != pat[pi] {
                return false;
            }
            pi += 1;
            ti += 1;
        } else if pat[pi] == b'[' {
            let Some((next, matched)) = match_class(pat, pi, text, ti) else {
                return false;
            };
            if !matched {
                return false;
            }
            pi = next;
            ti += 1;
        } else {
            if ti >= text.len() || text[ti] != pat[pi] {
                return false;
            }
            pi += 1;
            ti += 1;
        }
    }
    ti == text.len()
}

fn match_class(pat: &[u8], pi: usize, text: &[u8], ti: usize) -> Option<(usize, bool)> {
    if ti >= text.len() || text[ti] == b'/' {
        return None;
    }
    let mut i = pi + 1;
    let negate = i < pat.len() && pat[i] == b'^';
    if negate {
        i += 1;
    }
    let start = i;
    while i < pat.len() && pat[i] != b']' {
        i += 1;
    }
    if i >= pat.len() {
        return None;
    }
    let class = &pat[start..i];
    let ch = text[ti];
    let mut found = false;
    let mut k = 0;
    while k < class.len() {
        if k + 2 < class.len() && class[k + 1] == b'-' {
            if ch >= class[k] && ch <= class[k + 2] {
                found = true;
                break;
            }
            k += 3;
        } else {
            if ch == class[k] {
                found = true;
                break;
            }
            k += 1;
        }
    }
    Some((i + 1, found ^ negate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rob-ignore-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn touch(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn excluded(rel: &str, patterns: &[&str]) -> bool {
        let owned: Vec<String> = patterns.iter().map(|p| (*p).to_string()).collect();
        is_excluded(rel, &owned).unwrap()
    }

    #[test]
    fn root_containerignore_and_dockerignore_exclude_a_file() {
        let root = scratch("roots");
        let with_container = root.join("container");
        fs::create_dir_all(&with_container).unwrap();
        let dockerfile = with_container.join("Dockerfile");
        touch(&dockerfile, "FROM scratch\n");
        touch(&with_container.join("drop.txt"), "x");
        touch(&with_container.join("keep.txt"), "y");
        touch(&with_container.join("only-docker.txt"), "z");
        touch(
            &with_container.join(".containerignore"),
            "# comment\n\ndrop.txt\n",
        );
        touch(&with_container.join(".dockerignore"), "only-docker.txt\n");
        let patterns = collect_excludes(&with_container, &dockerfile, &[]).unwrap();
        assert!(is_excluded("drop.txt", &patterns).unwrap());
        assert!(!is_excluded("only-docker.txt", &patterns).unwrap());
        assert!(!is_excluded("keep.txt", &patterns).unwrap());

        let with_docker = root.join("docker");
        fs::create_dir_all(&with_docker).unwrap();
        let dockerfile = with_docker.join("Dockerfile");
        touch(&dockerfile, "FROM scratch\n");
        touch(&with_docker.join("drop.txt"), "x");
        touch(&with_docker.join(".dockerignore"), "drop.txt\n");
        let patterns = collect_excludes(&with_docker, &dockerfile, &[]).unwrap();
        assert!(is_excluded("drop.txt", &patterns).unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dockerfile_dockerignore_beats_a_root_containerignore() {
        let root = scratch("sidecar");
        let dockerfile = root.join("Dockerfile");
        touch(&dockerfile, "FROM scratch\n");
        touch(&root.join("secret.txt"), "no");
        touch(&root.join("root-only.txt"), "no");
        touch(&root.join(".containerignore"), "root-only.txt\n");
        touch(&root.join("Dockerfile.dockerignore"), "secret.txt\n");
        touch(
            &root.join("Dockerfile.containerignore"),
            "not-selected.txt\n",
        );
        let patterns = collect_excludes(&root, &dockerfile, &[]).unwrap();
        assert!(is_excluded("secret.txt", &patterns).unwrap());
        assert!(!is_excluded("root-only.txt", &patterns).unwrap());
        assert!(!is_excluded("not-selected.txt", &patterns).unwrap());
        assert_eq!(patterns, vec!["secret.txt".to_string()]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dot_env_star_does_not_exclude_a_nested_file() {
        assert!(!excluded("nested/.env.synthetic", &[".env*"]));
        assert!(excluded(".env.synthetic", &[".env*"]));
        assert!(excluded("nested/.env.synthetic", &["**/.env*"]));
        assert!(excluded(
            "nested/.env.synthetic",
            &["**/nested/.env.synthetic"]
        ));
        assert!(!excluded("keep.txt", &["*.txt", "!keep.txt"]));
        assert!(excluded("drop.txt", &["*.txt", "!keep.txt"]));
        assert!(excluded("secret/token.txt", &["secret"]));
        assert!(excluded("foo/bar/baz", &["foo/**"]));
        assert!(!excluded("foo", &["foo/**"]));
    }

    #[test]
    fn excludes_are_appended_after_the_selected_file() {
        let root = scratch("extra");
        let dockerfile = root.join("Dockerfile");
        touch(&dockerfile, "FROM scratch\n");
        touch(&root.join(".dockerignore"), "skip-me.txt\n");
        touch(&root.join("nested").join(".env.synthetic"), "s");
        let extra = vec!["**/.env*".to_string()];
        let patterns = collect_excludes(&root, &dockerfile, &extra).unwrap();
        assert!(is_excluded("skip-me.txt", &patterns).unwrap());
        assert!(is_excluded("nested/.env.synthetic", &patterns).unwrap());
        assert!(!is_excluded("nested/.env.synthetic", &patterns[..1]).unwrap());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn staged_tree_omits_excluded_files_and_keeps_the_dockerfile() {
        let root = scratch("stage");
        let context = root.join("ctx");
        fs::create_dir_all(context.join("nested")).unwrap();
        fs::create_dir_all(context.join("secret")).unwrap();
        let dockerfile = context.join("Dockerfile");
        touch(&dockerfile, "FROM scratch\n");
        touch(&context.join("keep.txt"), "keep");
        touch(&context.join("skip-me.txt"), "no");
        touch(&context.join("secret").join("token.txt"), "tok");
        touch(&context.join("nested").join(".env.synthetic"), "env");
        touch(&context.join("nested").join("ok.txt"), "ok");
        touch(
            &context.join(".dockerignore"),
            "skip-me.txt\nsecret\nDockerfile\n.env*\n",
        );
        let patterns = collect_excludes(
            &context,
            &dockerfile,
            &["**/nested/.env.synthetic".to_string()],
        )
        .unwrap();
        let dest = root.join("staged");
        fs::create_dir_all(&dest).unwrap();
        stage_context(&context, &dockerfile, &patterns, &dest).unwrap();
        assert!(dest.join("Dockerfile").is_file());
        assert!(dest.join("keep.txt").is_file());
        assert!(dest.join("nested").join("ok.txt").is_file());
        assert!(!dest.join("skip-me.txt").exists());
        assert!(!dest.join("secret").join("token.txt").exists());
        assert!(!dest.join("nested").join(".env.synthetic").exists());
        assert!(!dest.join(".dockerignore").exists());
        let _ = fs::remove_dir_all(&root);
    }
}
