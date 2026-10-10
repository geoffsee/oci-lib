//! Small OCI Distribution client used for Notary referrers.
//!
//! Buildah owns image transfer and storage.  This module deliberately only
//! handles the follow-up manifest/blob requests needed by Notary signatures;
//! it does not duplicate image-layer transfer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use oci_util::signature::{
    self, Descriptor, ReferrersIndex, SignatureManifest, TrustPolicyDocument, Verification,
};
use serde::Deserialize;
use ureq::Agent;

use crate::error::{Error, ErrorCode};
use crate::notary::{self, SigningMaterial};

#[derive(Clone, Debug)]
pub(crate) struct Registry {
    base: String,
    repository: String,
    reference: String,
    auth: Option<String>,
    bearer: Arc<Mutex<Option<String>>>,
    agent: Agent,
}

#[derive(Debug, Deserialize)]
struct ImageManifest {
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
    config: Option<ImageConfig>,
}

#[derive(Debug, Deserialize)]
struct ImageConfig {
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
}

impl Registry {
    pub(crate) fn parse(
        destination: &str,
        username: &str,
        password: &str,
        insecure: bool,
    ) -> Result<Self, Error> {
        let value = destination
            .trim()
            .strip_prefix("docker://")
            .or_else(|| destination.trim().strip_prefix("containers-storage://"))
            .unwrap_or(destination.trim());
        let value = value
            .strip_prefix("http://")
            .map(|v| ("http", v))
            .or_else(|| value.strip_prefix("https://").map(|v| ("https", v)))
            .unwrap_or((if insecure { "http" } else { "https" }, value));
        let (scheme, value) = value;
        let (host, path) = value
            .split_once('/')
            .map_or(("docker.io", format!("library/{value}")), |(host, path)| {
                (host, path.to_string())
            });
        let (repository, reference) = split_reference(&path)?;
        let auth = if username.is_empty() && password.is_empty() {
            None
        } else {
            let raw = format!("{username}:{password}");
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            ))
        };
        Ok(Self {
            base: format!("{scheme}://{host}"),
            repository: repository.to_string(),
            reference: reference.to_string(),
            auth,
            bearer: Arc::new(Mutex::new(None)),
            agent: Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        })
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/v2/{}/{}", self.base, self.repository, suffix)
    }

    fn request(&self, method: &str, url: &str) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
        let request = match method {
            "POST" => self.agent.post(url),
            "PUT" => self.agent.put(url),
            _ => self.agent.post(url),
        };
        if let Some(auth) = self.authorization() {
            request.header("Authorization", auth)
        } else {
            request
        }
    }

    fn get(&self, url: &str) -> Result<ureq::http::Response<ureq::Body>, Error> {
        let request = self.agent.get(url).header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/json",
        );
        let request = if let Some(auth) = self.authorization() {
            request.header("Authorization", auth)
        } else {
            request
        };
        let response = request
            .call()
            .map_err(|err| http_error("registry GET failed", err))?;
        if response.status().as_u16() == 401 {
            if let Some(challenge) = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
            {
                let token = self.bearer_token(challenge)?;
                let retry = self.agent.get(url).header("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/json").header("Authorization", token);
                return retry
                    .call()
                    .map_err(|err| http_error("registry GET failed", err));
            }
        }
        Ok(response)
    }

    fn authorization(&self) -> Option<String> {
        self.bearer
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .or_else(|| self.auth.clone())
    }

    fn bearer_token(&self, challenge: &str) -> Result<String, Error> {
        let Some(rest) = challenge.strip_prefix("Bearer ") else {
            return Err(Error::new(
                ErrorCode::Push,
                "registry requires unsupported authentication",
                challenge,
            ));
        };
        let mut values = BTreeMap::new();
        for part in rest.split(',') {
            if let Some((key, value)) = part.trim().split_once('=') {
                values.insert(key.trim(), value.trim().trim_matches('"'));
            }
        }
        let realm = values.get("realm").ok_or_else(|| {
            Error::new(
                ErrorCode::Push,
                "registry bearer challenge has no realm",
                challenge,
            )
        })?;
        let mut request = self.agent.get(*realm);
        if let Some(service) = values.get("service") {
            request = request.query("service", *service);
        }
        if let Some(scope) = values.get("scope") {
            request = request.query("scope", *scope);
        }
        if let Some(auth) = &self.auth {
            request = request.header("Authorization", auth);
        }
        let mut response = request
            .call()
            .map_err(|err| http_error("registry token request failed", err))?;
        if !response.status().is_success() {
            return Err(Error::new(
                ErrorCode::Push,
                "registry token request failed",
                response.status().to_string(),
            ));
        }
        #[derive(Deserialize)]
        struct Token {
            token: Option<String>,
            access_token: Option<String>,
        }
        let token_bytes = response.body_mut().read_to_vec().map_err(|err| {
            Error::new(
                ErrorCode::Push,
                "cannot read registry token response",
                err.to_string(),
            )
        })?;
        let token: Token = serde_json::from_slice(&token_bytes).map_err(|err| {
            Error::new(
                ErrorCode::Push,
                "invalid registry token response",
                err.to_string(),
            )
        })?;
        let value = token.token.or(token.access_token).ok_or_else(|| {
            Error::new(ErrorCode::Push, "registry token response has no token", "")
        })?;
        let header = format!("Bearer {value}");
        if let Ok(mut slot) = self.bearer.lock() {
            *slot = Some(header.clone());
        }
        Ok(header)
    }

    fn put(&self, url: &str, content_type: &str, body: &[u8]) -> Result<(), Error> {
        let request = self
            .request("PUT", url)
            .header("Content-Type", content_type)
            .header("Content-Length", body.len().to_string());
        let mut response = request
            .send(body)
            .map_err(|err| http_error("registry PUT failed", err))?;
        if response.status().as_u16() == 401 {
            if let Some(challenge) = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
            {
                let token = self.bearer_token(challenge)?;
                response = self
                    .request("PUT", url)
                    .header("Authorization", token)
                    .header("Content-Type", content_type)
                    .header("Content-Length", body.len().to_string())
                    .send(body)
                    .map_err(|err| http_error("registry PUT failed", err))?;
            }
        }
        if !(200..300).contains(&response.status().as_u16()) {
            return Err(Error::new(
                ErrorCode::Push,
                format!("registry PUT returned HTTP {}", response.status()),
                url,
            ));
        }
        Ok(())
    }

    fn upload_blob(&self, digest: &str, bytes: &[u8]) -> Result<(), Error> {
        let mut response = self
            .request("POST", &self.url("blobs/uploads/"))
            .send_empty()
            .map_err(|err| http_error("cannot start registry blob upload", err))?;
        if response.status().as_u16() == 401 {
            if let Some(challenge) = response
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
            {
                let token = self.bearer_token(challenge)?;
                response = self
                    .request("POST", &self.url("blobs/uploads/"))
                    .header("Authorization", token)
                    .send_empty()
                    .map_err(|err| http_error("cannot start registry blob upload", err))?;
            }
        }
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Push,
                    "registry did not return an upload location",
                    "",
                )
            })?;
        let location = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_string()
        } else {
            format!("{}{}", self.base, location)
        };
        let separator = if location.contains('?') { '&' } else { '?' };
        self.put(
            &format!("{location}{separator}digest={digest}"),
            "application/octet-stream",
            bytes,
        )
    }

    fn manifest(&self, reference: &str) -> Result<(Vec<u8>, String), Error> {
        let response = self.get(&self.url(&format!("manifests/{reference}")))?;
        let digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut response = response;
        let bytes = response.body_mut().read_to_vec().map_err(|err| {
            Error::new(
                ErrorCode::Push,
                "cannot read registry manifest",
                err.to_string(),
            )
        })?;
        let digest = digest.unwrap_or_else(|| signature::sha256_digest(&bytes));
        Ok((bytes, digest))
    }

    pub(crate) fn sign_push(&self, material: &SigningMaterial) -> Result<String, Error> {
        let (manifest_bytes, digest) = self.manifest(&self.reference)?;
        let parsed: ImageManifest = serde_json::from_slice(&manifest_bytes).map_err(|err| {
            Error::new(
                ErrorCode::Push,
                "registry returned an invalid image manifest",
                err.to_string(),
            )
        })?;
        let media_type = parsed
            .media_type
            .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string());
        let target = Descriptor {
            media_type,
            digest: digest.clone(),
            size: i64::try_from(manifest_bytes.len())
                .map_err(|_| Error::new(ErrorCode::Push, "image manifest is too large", ""))?,
            artifact_type: parsed.config.and_then(|c| c.media_type),
            annotations: None,
        };
        let (signature_manifest, envelope) = notary::sign_manifest(material, target)?;
        self.upload_blob(
            signature::SIGNATURE_CONFIG_DIGEST,
            signature::SIGNATURE_CONFIG_BYTES,
        )?;
        self.upload_blob(&signature::sha256_digest(&envelope), &envelope)?;
        let manifest = signature_manifest.to_bytes().map_err(|err| {
            Error::new(
                ErrorCode::Push,
                "cannot encode signature manifest",
                err.to_string(),
            )
        })?;
        let signature_digest = signature::sha256_digest(&manifest);
        self.put(
            &self.url(&format!("manifests/{signature_digest}")),
            signature::OCI_MANIFEST_MEDIA_TYPE,
            &manifest,
        )?;
        Ok(signature_digest)
    }

    /// Fetch and verify the Notary referrer for the image reference.
    pub(crate) fn verify(
        &self,
        policy: &TrustPolicyDocument,
        anchors: &BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<Verification, Error> {
        let (manifest_bytes, digest) = self.manifest(&self.reference)?;
        let parsed: ImageManifest = serde_json::from_slice(&manifest_bytes).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                "registry returned an invalid image manifest",
                err.to_string(),
            )
        })?;
        let target = Descriptor {
            media_type: parsed
                .media_type
                .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".into()),
            digest,
            size: i64::try_from(manifest_bytes.len()).unwrap_or(i64::MAX),
            artifact_type: parsed.config.and_then(|c| c.media_type),
            annotations: None,
        };
        let statement =
            signature::select_trust_policy(policy, &self.repository).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "trust policy does not apply",
                    err.to_string(),
                )
            })?;
        if statement.signature_verification.level == signature::VerificationLevel::Skip {
            return Ok(Verification::Skipped);
        }
        let response = self.get(&self.url(&format!("referrers/{}", target.digest)))?;
        let mut response = response;
        let index_bytes = response.body_mut().read_to_vec().map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                "cannot read registry referrers index",
                err.to_string(),
            )
        })?;
        let index: ReferrersIndex =
            signature::parse_referrers_index(&index_bytes).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "invalid registry referrers index",
                    err.to_string(),
                )
            })?;
        let candidates = signature::select_notary_referrers(&index);
        let mut last_error = None;
        for candidate in candidates {
            let (sig_bytes, _) = self.manifest(&candidate.digest)?;
            let sig: SignatureManifest =
                SignatureManifest::from_bytes(&sig_bytes).map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "invalid signature manifest",
                        err.to_string(),
                    )
                })?;
            let layer = &sig.layers[0];
            let envelope_url = self.url(&format!("blobs/{}", layer.digest));
            let mut envelope_response = self.get(&envelope_url)?;
            let envelope = envelope_response.body_mut().read_to_vec().map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    "cannot read signature envelope",
                    err.to_string(),
                )
            })?;
            match signature::verify(&signature::VerifyInput {
                envelope: &envelope,
                media_type: &layer.media_type,
                policy: statement,
                trust_anchors: anchors,
                verify_at: current_time(),
                expected_artifact: Some(&target),
            }) {
                Ok(result) => return Ok(result),
                Err(err) => last_error = Some(err.to_string()),
            }
        }
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "no valid signature found for image",
            last_error.unwrap_or_else(|| "registry returned no Notary referrers".into()),
        ))
    }
}

fn split_reference(path: &str) -> Result<(&str, &str), Error> {
    let Some((repository, reference)) = path.rsplit_once('@').or_else(|| path.rsplit_once(':'))
    else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "registry destination must include a tag or digest",
            path,
        ));
    };
    if repository.is_empty() || reference.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "registry destination has an empty repository or reference",
            path,
        ));
    }
    Ok((repository, reference))
}

fn current_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn http_error(context: &str, err: ureq::Error) -> Error {
    Error::new(ErrorCode::Push, context, err.to_string())
}

/// Read the first Docker auth entry. Buildah accepts the same auth-file
/// format; the registry client uses it for pre-pull signature verification.
pub(crate) fn credentials_from_auth_file(
    path: &std::path::Path,
) -> Result<(String, String), Error> {
    #[derive(Deserialize)]
    struct AuthFile {
        auths: BTreeMap<String, AuthEntry>,
    }
    #[derive(Deserialize)]
    struct AuthEntry {
        auth: Option<String>,
        username: Option<String>,
        password: Option<String>,
    }
    let bytes = std::fs::read(path).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            "cannot read registry auth file",
            err.to_string(),
        )
    })?;
    let file: AuthFile = serde_json::from_slice(&bytes).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            "invalid registry auth file",
            err.to_string(),
        )
    })?;
    let Some(entry) = file.auths.values().next() else {
        return Ok((String::new(), String::new()));
    };
    if let (Some(username), Some(password)) = (&entry.username, &entry.password) {
        return Ok((username.clone(), password.clone()));
    }
    let Some(encoded) = &entry.auth else {
        return Ok((String::new(), String::new()));
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                "invalid registry auth encoding",
                err.to_string(),
            )
        })?;
    let value = String::from_utf8(decoded).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            "registry auth is not UTF-8",
            err.to_string(),
        )
    })?;
    let Some((username, password)) = value.split_once(':') else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "registry auth must contain username and password",
            "",
        ));
    };
    Ok((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_references_and_default_docker_library() {
        let explicit = Registry::parse("localhost:5000/team/app:latest", "", "", true).unwrap();
        assert_eq!(explicit.base, "http://localhost:5000");
        assert_eq!(explicit.repository, "team/app");
        assert_eq!(explicit.reference, "latest");

        let implicit = Registry::parse("alpine:3.20", "", "", false).unwrap();
        assert_eq!(implicit.base, "https://docker.io");
        assert_eq!(implicit.repository, "library/alpine");
        assert_eq!(implicit.reference, "3.20");
    }

    #[test]
    fn signature_manifests_handle_mtu_scale_envelopes() {
        let subject = Descriptor {
            media_type: signature::OCI_MANIFEST_MEDIA_TYPE.into(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            size: 128,
            artifact_type: Some("application/vnd.oci.image.config.v1+json".into()),
            annotations: None,
        };
        for size in [0usize, 1, 512, 1500, 8192, 65536] {
            let envelope = vec![0x5a; size];
            let manifest = signature::signature_manifest(
                &subject,
                signature::JWS_MEDIA_TYPE,
                &envelope,
                &[b"test-certificate".as_slice()],
            )
            .unwrap();
            assert_eq!(manifest.layers[0].size, size as i64);
            assert_eq!(
                manifest.layers[0].digest,
                signature::sha256_digest(&envelope)
            );
            assert!(!manifest.to_bytes().unwrap().is_empty());
        }
    }
}
