// SPDX-License-Identifier: Apache-2.0

//! Parser for the initramfs attestation `cargo xtask guest` writes.
//!
//! `build.rs` compiles this file on its own, before the library exists, so it
//! stays limited to `std`. Diagnose formatting lives in `guest_record.rs`.

pub(crate) struct Attestation {
    pub(crate) kernel_sha256: String,
    pub(crate) initramfs_sha256: String,
    /// Initramfs paths in the order the attestation lists them.
    pub(crate) members: Vec<String>,
}

pub(crate) fn parse(json: &str) -> Result<Attestation, String> {
    let kernel_sha256 = string_field(json, "kernel_sha256")?;
    let initramfs_sha256 = string_field(json, "initramfs_sha256")?;
    let members = member_paths(json)?;
    Ok(Attestation {
        kernel_sha256,
        initramfs_sha256,
        members,
    })
}

fn string_field(json: &str, key: &str) -> Result<String, String> {
    let mut rest = json;
    while let Some(pos) = rest.find('"') {
        let (text, after) = parse_json_string(&rest[pos..])?;
        let trimmed = after.trim_start();
        if text == key {
            if let Some(value) = trimmed.strip_prefix(':') {
                let value = value.trim_start();
                let (parsed, _) = parse_json_string(value)
                    .map_err(|_| format!("attestation field {key} is not a string"))?;
                return Ok(parsed);
            }
        }
        rest = after;
    }
    Err(format!("attestation is missing {key}"))
}

fn member_paths(json: &str) -> Result<Vec<String>, String> {
    let interior = members_interior(json)?;
    let mut paths = Vec::new();
    let mut rest = interior;
    while let Some(pos) = rest.find('"') {
        let (text, after) = parse_json_string(&rest[pos..])?;
        let trimmed = after.trim_start();
        if text == "path" {
            if let Some(value) = trimmed.strip_prefix(':') {
                let value = value.trim_start();
                let (path, _) = parse_json_string(value)
                    .map_err(|_| "attestation member path is not a string".to_string())?;
                paths.push(path);
            }
        }
        rest = after;
    }
    Ok(paths)
}

fn members_interior(json: &str) -> Result<&str, String> {
    let mut rest = json;
    while let Some(pos) = rest.find('"') {
        let (text, after) = parse_json_string(&rest[pos..])?;
        let trimmed = after.trim_start();
        if text == "members" {
            if let Some(value) = trimmed.strip_prefix(':') {
                return array_interior(value);
            }
        }
        rest = after;
    }
    Err("attestation is missing members".into())
}

/// Bytes inside the top-level `[...]`, not including the brackets.
fn array_interior(input: &str) -> Result<&str, String> {
    let input = input.trim_start();
    let bytes = input.as_bytes();
    if bytes.first() != Some(&b'[') {
        return Err("attestation members is not an array".into());
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&input[1..index]);
                }
            }
            _ => {}
        }
    }
    Err("unclosed attestation members array".into())
}

fn parse_json_string(input: &str) -> Result<(String, &str), String> {
    let mut chars = input.chars();
    if chars.next() != Some('"') {
        return Err("expected a JSON string".into());
    }
    let mut out = String::new();
    loop {
        let Some(ch) = chars.next() else {
            return Err("unterminated JSON string".into());
        };
        match ch {
            '"' => return Ok((out, chars.as_str())),
            '\\' => {
                let Some(escaped) = chars.next() else {
                    return Err("unterminated JSON escape".into());
                };
                match escaped {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let mut hex = String::new();
                        for _ in 0..4 {
                            let Some(digit) = chars.next() else {
                                return Err("short JSON unicode escape".into());
                            };
                            hex.push(digit);
                        }
                        let code = u32::from_str_radix(&hex, 16)
                            .map_err(|_| format!("bad JSON unicode escape {hex}"))?;
                        let decoded = char::from_u32(code)
                            .ok_or_else(|| format!("bad JSON unicode escape {hex}"))?;
                        out.push(decoded);
                    }
                    other => return Err(format!("bad JSON escape {other}")),
                }
            }
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_keep_attested_order_and_unescaped_paths() {
        let json = r#"{
            "package": "oci-builder",
            "kernel_sha256": "abc",
            "initramfs_sha256": "def",
            "members": [
                {"path": "a/b", "mode": 33261, "size": 1, "sha256": "aa"},
                {"path": "a\"b\\c", "mode": 16877, "size": 0, "sha256": "bb"},
                {"path": "init", "mode": 33261, "size": 4, "sha256": "cc"}
            ]
        }"#;
        let attestation = parse(json).unwrap();
        assert_eq!(attestation.kernel_sha256, "abc");
        assert_eq!(attestation.initramfs_sha256, "def");
        assert_eq!(attestation.members, ["a/b", "a\"b\\c", "init"]);
    }

    #[test]
    fn unicode_escapes_in_paths_decode() {
        let json =
            r#"{"kernel_sha256":"k","initramfs_sha256":"i","members":[{"path":"a\u002fb"}]}"#;
        let attestation = parse(json).unwrap();
        assert_eq!(attestation.members, ["a/b"]);
    }

    #[test]
    fn missing_hash_or_members_is_an_error() {
        assert!(parse(r#"{"initramfs_sha256":"i","members":[]}"#).is_err());
        assert!(parse(r#"{"kernel_sha256":"k","initramfs_sha256":"i"}"#).is_err());
        assert!(parse(r#"{"kernel_sha256":"k","initramfs_sha256":"i","members":{}}"#).is_err());
    }
}
