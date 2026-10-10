// SPDX-License-Identifier: Apache-2.0

//! Default containers/image signature policy.
//!
//! containers/image fails closed when no `policy.json` exists. The
//! `default-policy` feature (on by default) supplies the containers-common
//! policy instead of a global `insecureAcceptAnything`.

use std::path::{Path, PathBuf};

use crate::error::Result;
#[cfg(feature = "default-policy")]
use crate::error::{Error, ErrorCode};

/// containers-common default: reject, except `docker` localhost and
/// `docker-daemon` with an empty host.
#[cfg_attr(not(any(feature = "default-policy", test)), allow(dead_code))]
pub(crate) const DEFAULT_POLICY_JSON: &str = include_str!("default-policy.json");

/// Policy path to give the engine.
///
/// A caller-supplied path is returned unchanged. With the `default-policy`
/// feature, `None` is written to a temp file and that path is returned.
/// Without the feature, `None` stays `None` and the engine fails closed.
pub(crate) fn effective_signature_policy(configured: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(path) = configured {
        return Ok(Some(path.to_path_buf()));
    }
    #[cfg(feature = "default-policy")]
    {
        Ok(Some(materialize_default_policy()?))
    }
    #[cfg(not(feature = "default-policy"))]
    {
        Ok(None)
    }
}

#[cfg(feature = "default-policy")]
fn materialize_default_policy() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("oci-builder-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("creating default policy directory: {err}"),
            "",
        )
    })?;
    let path = dir.join("policy.json");
    std::fs::write(&path, DEFAULT_POLICY_JSON).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("writing default policy: {err}"),
            "",
        )
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_policy_rejects_by_default_and_allows_localhost() {
        let text = DEFAULT_POLICY_JSON;
        let default_at = text.find("\"default\"").expect("default");
        let reject_at = text.find("\"reject\"").expect("reject");
        let allow_at = text
            .find("insecureAcceptAnything")
            .expect("localhost exception");
        assert!(default_at < reject_at);
        assert!(reject_at < allow_at);
        assert!(text.contains("\"localhost\""));
        assert!(text.contains("\"docker-daemon\""));
        assert!(text.contains("\"docker\""));
        assert!(!text.contains("\"default\": [{\"type\": \"insecureAcceptAnything\"}]"));
    }

    #[test]
    fn caller_policy_is_kept_and_unset_follows_the_feature() {
        let custom = Path::new("/tmp/caller-policy.json");
        let kept = effective_signature_policy(Some(custom)).unwrap();
        assert_eq!(kept.as_deref(), Some(custom));

        let unset = effective_signature_policy(None).unwrap();
        #[cfg(feature = "default-policy")]
        {
            let path = unset.expect("materialized policy");
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(text, DEFAULT_POLICY_JSON);
            assert!(path.is_file());
        }
        #[cfg(not(feature = "default-policy"))]
        {
            assert!(unset.is_none());
        }
    }
}
