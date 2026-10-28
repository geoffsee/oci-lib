// SPDX-License-Identifier: Apache-2.0

//! CNI networking for pod sandboxes.
//!
//! Implements the CNI plugin protocol directly: plugins are executables in
//! the configured bin directory, invoked with `CNI_COMMAND=ADD|DEL|CHECK`
//! environment and the network configuration on stdin. The sandbox's network
//! namespace is the infra container's (`/proc/<pid>/ns/net` once running).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::api::PortMapping;
use crate::config::Config;
use crate::error::{Error, ErrorCode, Result};

/// Result of a successful CNI ADD.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CniResult {
    /// IP addresses assigned to the sandbox (`10.0.0.2/24` form).
    pub ips: Vec<String>,
    /// Routes from the plugin result (kept for status/debugging).
    pub routes: Vec<String>,
}

/// Whether CNI is configured (a conf dir with at least one config file).
pub fn configured(config: &Config) -> bool {
    config.cni_conf_dir.is_some()
}

/// Load the merged CNI configuration (first `.conflist`, else first `.conf`)
/// from the configured directory.
pub fn load_config(config: &Config) -> Result<Option<Value>> {
    let Some(dir) = &config.cni_conf_dir else {
        return Ok(None);
    };
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|err| {
            Error::new(
                ErrorCode::Prerequisite,
                format!("reading {}: {err}", dir.display()),
                "",
            )
        })?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "conf" || e == "conflist")
                .unwrap_or(false)
        })
        .collect();
    names.sort();
    let Some(path) = names.into_iter().next() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path).map_err(|err| {
        Error::new(
            ErrorCode::Prerequisite,
            format!("reading {}: {err}", path.display()),
            "",
        )
    })?;
    let value: Value = serde_json::from_str(&text).map_err(|err| {
        Error::new(
            ErrorCode::Prerequisite,
            format!("parsing {}: {err}", path.display()),
            "",
        )
    })?;
    // A conflist already carries its plugin list; a single conf is wrapped.
    if value.get("plugins").is_some() {
        Ok(Some(value))
    } else {
        let name = value
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("oci-cri")
            .to_string();
        Ok(Some(serde_json::json!({
            "cniVersion": value.get("cniVersion").cloned().unwrap_or(serde_json::json!("1.0.0")),
            "name": name,
            "disableCheck": true,
            "plugins": [value],
        })))
    }
}

/// Run CNI ADD for a sandbox. `port_mappings` are embedded in the config the
/// plugins see (the `portmap` plugin consumes them).
pub fn setup(
    config: &Config,
    sandbox_id: &str,
    netns: &Path,
    port_mappings: &[PortMapping],
) -> Result<CniResult> {
    let Some(mut conf) = load_config(config)? else {
        return Ok(CniResult::default());
    };
    if !port_mappings.is_empty() {
        let mappings: Vec<Value> = port_mappings
            .iter()
            .map(|m| {
                serde_json::json!({
                    "hostPort": m.host_port,
                    "containerPort": m.container_port,
                    "protocol": protocol_name(m.protocol),
                    "hostIP": m.host_ip,
                })
            })
            .collect();
        if let Some(plugins) = conf["plugins"].as_array_mut() {
            for plugin in plugins.iter_mut() {
                let kind = plugin["type"].as_str().unwrap_or("");
                if kind == "portmap" {
                    plugin["portMappings"] = Value::Array(mappings.clone());
                }
            }
        }
    }
    let output = invoke(config, "ADD", sandbox_id, netns, &conf)?;
    parse_result(&output)
}

/// Run CNI DEL for a sandbox. Best effort: missing plugins or an already
/// removed namespace are not errors.
pub fn teardown(config: &Config, sandbox_id: &str, netns: &Path) {
    let Ok(Some(conf)) = load_config(config) else {
        return;
    };
    let _ = invoke(config, "DEL", sandbox_id, netns, &conf);
}

/// Run CNI CHECK (used by `Status` to report network readiness).
pub fn check(config: &Config, sandbox_id: &str, netns: &Path) -> bool {
    let Ok(Some(conf)) = load_config(config) else {
        return false;
    };
    invoke(config, "CHECK", sandbox_id, netns, &conf).is_ok()
}

fn invoke(
    config: &Config,
    command: &str,
    sandbox_id: &str,
    netns: &Path,
    conf: &Value,
) -> Result<Vec<u8>> {
    let name = conf
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or(config.runtime_name.as_str())
        .to_string();
    let plugins = conf["plugins"].as_array().cloned().unwrap_or_default();
    if plugins.is_empty() {
        return Ok(Vec::new());
    }
    let mut path_search: Vec<PathBuf> = Vec::new();
    if let Some(dir) = &config.cni_bin_dir {
        path_search.push(dir.clone());
    }
    path_search.extend(config.cni_plugin_dirs.iter().cloned());
    let cni_path = path_search
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    let mut result = Vec::new();
    let list: Vec<&Value> = if command == "DEL" {
        plugins.iter().rev().collect()
    } else {
        plugins.iter().collect()
    };
    for plugin in list {
        let kind = plugin["type"].as_str().unwrap_or_default();
        let bin = path_search
            .iter()
            .map(|dir| dir.join(kind))
            .find(|p| p.is_file());
        let Some(bin) = bin else {
            if command == "DEL" {
                continue;
            }
            return Err(Error::new(
                ErrorCode::Prerequisite,
                format!("CNI plugin {kind} not found in {cni_path}"),
                "",
            ));
        };
        // Each plugin gets the previous result chained as prevResult.
        let mut input = plugin.clone();
        input["name"] = Value::String(name.clone());
        if !result.is_empty() {
            if let Ok(prev) = serde_json::from_slice::<Value>(&result) {
                input["prevResult"] = prev;
            }
        }
        let mut child = Command::new(&bin)
            .env("CNI_COMMAND", command)
            .env("CNI_CONTAINERID", sandbox_id)
            .env("CNI_NETNS", netns.to_string_lossy().into_owned())
            .env("CNI_IFNAME", "eth0")
            .env("CNI_PATH", &cni_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                Error::new(
                    ErrorCode::Prerequisite,
                    format!("running CNI plugin {kind}: {err}"),
                    "",
                )
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.to_string().as_bytes());
        }
        let output = child.wait_with_output().map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("waiting for CNI plugin {kind}: {err}"),
                "",
            )
        })?;
        if !output.status.success() {
            if command == "DEL" {
                continue;
            }
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            return Err(Error::new(
                ErrorCode::Run,
                format!("CNI {command} plugin {kind} failed"),
                if stderr.is_empty() { stdout } else { stderr },
            ));
        }
        result = output.stdout;
    }
    Ok(result)
}

fn parse_result(output: &[u8]) -> Result<CniResult> {
    if output.is_empty() {
        return Ok(CniResult::default());
    }
    let value: Value = serde_json::from_slice(output).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("parsing CNI result: {err}"),
            "",
        )
    })?;
    let ips = value["ips"]
        .as_array()
        .map(|ips| {
            ips.iter()
                .filter_map(|ip| ip["address"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let routes = value["routes"]
        .as_array()
        .map(|routes| {
            routes
                .iter()
                .filter_map(|r| r["dst"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(CniResult { ips, routes })
}

fn protocol_name(protocol: i32) -> &'static str {
    if protocol == crate::api::Protocol::Udp as i32 {
        "udp"
    } else if protocol == crate::api::Protocol::Sctp as i32 {
        "sctp"
    } else {
        "tcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ips_from_a_result() {
        let result = parse_result(
            br#"{"cniVersion":"1.0.0","ips":[{"address":"10.0.0.7/24"}],"routes":[{"dst":"0.0.0.0/0"}]}"#,
        )
        .unwrap();
        assert_eq!(result.ips, ["10.0.0.7/24"]);
        assert_eq!(result.routes, ["0.0.0.0/0"]);
    }

    #[test]
    fn an_unconfigured_runtime_reports_no_cni() {
        let config = Config::default();
        assert!(!configured(&config));
        assert!(load_config(&config).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn runs_a_fake_plugin_for_add() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rok-cni-{}", crate::store::new_id()));
        let bin_dir = dir.join("bin");
        let conf_dir = dir.join("conf");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&conf_dir).unwrap();
        let plugin = bin_dir.join("fakebridge");
        std::fs::write(
            &plugin,
            "#!/bin/sh\ncat >/dev/null\necho '{\"cniVersion\":\"1.0.0\",\"ips\":[{\"address\":\"10.1.0.3/24\"}]}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            conf_dir.join("10-test.conflist"),
            r#"{"cniVersion":"1.0.0","name":"testnet","plugins":[{"type":"fakebridge"}]}"#,
        )
        .unwrap();
        let config = Config {
            cni_bin_dir: Some(bin_dir),
            cni_conf_dir: Some(conf_dir),
            ..Config::default()
        };
        let result = setup(&config, "sandbox1", Path::new("/proc/self/ns/net"), &[]).unwrap();
        assert_eq!(result.ips, ["10.1.0.3/24"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
