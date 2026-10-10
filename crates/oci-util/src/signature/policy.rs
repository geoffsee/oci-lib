//! Minimum Notary trust policy: version, trust stores, and verification level.
//!
//! The caller loads trust anchors. This module does not read a Notation trust-store
//! directory. Unknown versions, actions, and identity prefixes fail closed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::error::{ErrorKind, SignatureError};

const IDENTITY_PREFIX: &str = "x509.subject:";

/// Trust policy document, version `1.0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicyDocument {
    /// Must be `1.0`.
    pub version: String,
    /// Statements. Scopes must not overlap, and at most one statement is global.
    #[serde(rename = "trustPolicies")]
    pub trust_policies: Vec<TrustPolicyStatement>,
}

/// One registry scope and the verification rules that apply to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicyStatement {
    /// Statement name.
    pub name: String,
    /// Fully qualified repository URIs, or a single `*` global scope.
    #[serde(rename = "registryScopes")]
    pub registry_scopes: Vec<String>,
    /// Verification level and optional overrides.
    #[serde(rename = "signatureVerification")]
    pub signature_verification: SignatureVerification,
    /// `{type}:{name}` stores. Required unless the level is `skip`.
    #[serde(
        rename = "trustStores",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_stores: Option<Vec<String>>,
    /// `*` or `x509.subject:` DNs. Required unless the level is `skip`.
    #[serde(
        rename = "trustedIdentities",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trusted_identities: Option<Vec<String>>,
}

/// Signature verification level and the switches that adjust it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureVerification {
    /// `strict`, `permissive`, `audit`, or `skip`.
    pub level: VerificationLevel,
    /// Per-step overrides. Rejected when the level is `skip`.
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub verification_override: Option<VerificationOverride>,
    /// When to require a timestamp countersignature. Defaults to `always`.
    #[serde(
        rename = "verifyTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verify_timestamp: Option<TimestampVerification>,
}

/// How a verification step treats failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationLevel {
    /// Enforce integrity, authenticity, authentic timestamp, expiry, and revocation.
    Strict,
    /// Enforce integrity and authenticity. Log the remaining steps.
    Permissive,
    /// Enforce integrity. Log the remaining steps.
    Audit,
    /// Do not verify. Cannot be global and cannot be customized.
    Skip,
}

/// Action applied to one verification step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationAction {
    /// Failure stops verification.
    Enforce,
    /// Failure is recorded and verification continues.
    Log,
    /// The step is not run. Only revocation may use this, and only through an override.
    Skip,
}

/// When `notary.x509` timestamp verification is triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampVerification {
    /// Trigger whenever a `tsa` trust store is configured.
    #[serde(rename = "always")]
    Always,
    /// Trigger only when a certificate is outside its validity window.
    #[serde(rename = "afterCertExpiry")]
    AfterCertExpiry,
}

/// Optional replacements for the level's default actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationOverride {
    /// `enforce` or `log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticity: Option<ValidationAction>,
    /// `enforce` or `log`.
    #[serde(
        rename = "authenticTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authentic_timestamp: Option<ValidationAction>,
    /// `enforce` or `log`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<ValidationAction>,
    /// `enforce`, `log`, or `skip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<ValidationAction>,
}

/// Actions after defaults and overrides are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectivePolicy {
    /// Original level.
    pub level: VerificationLevel,
    /// Always [`ValidationAction::Enforce`] except for [`VerificationLevel::Skip`].
    pub integrity: ValidationAction,
    /// Authenticity action.
    pub authenticity: ValidationAction,
    /// Authentic timestamp action.
    pub authentic_timestamp: ValidationAction,
    /// Expiry action.
    pub expiry: ValidationAction,
    /// Revocation action.
    pub revocation: ValidationAction,
    /// Timestamp trigger. `always` when the document omits `verifyTimestamp`.
    pub verify_timestamp: TimestampVerification,
    /// Whether the statement names a `tsa:` store.
    pub has_tsa_store: bool,
}

impl TrustPolicyDocument {
    /// Parse a trust policy document and reject anything this crate does not understand.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        let document: Self = serde_json::from_slice(bytes).map_err(|err| {
            SignatureError::new(ErrorKind::Policy, format!("invalid trust policy: {err}"))
        })?;
        document.validate()?;
        Ok(document)
    }

    /// Check version, scopes, stores, and identities.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.version != "1.0" {
            return Err(policy_error(format!(
                "unsupported trust policy version `{}`",
                self.version
            )));
        }
        if self.trust_policies.is_empty() {
            return Err(policy_error("trust policy has no statements"));
        }
        let mut seen_scopes = BTreeSet::new();
        let mut globals = 0usize;
        for statement in &self.trust_policies {
            statement.validate()?;
            for scope in &statement.registry_scopes {
                if scope == "*" {
                    globals += 1;
                }
                if !seen_scopes.insert(scope.clone()) {
                    return Err(policy_error(format!(
                        "trust policy scope `{scope}` is ambiguous"
                    )));
                }
            }
        }
        if globals > 1 {
            return Err(policy_error(
                "trust policy contains more than one global scope",
            ));
        }
        Ok(())
    }
}

impl TrustPolicyStatement {
    /// Check this statement on its own.
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.name.is_empty() {
            return Err(policy_error("trust policy statement name is empty"));
        }
        if self.registry_scopes.is_empty() {
            return Err(policy_error(
                "trust policy statement is missing registryScopes",
            ));
        }
        let mut local = BTreeSet::new();
        for scope in &self.registry_scopes {
            if scope.is_empty() || (scope.contains('*') && scope != "*") {
                return Err(policy_error(format!("registry scope `{scope}` is invalid")));
            }
            if !local.insert(scope.clone()) {
                return Err(policy_error(format!(
                    "trust policy scope `{scope}` is repeated"
                )));
            }
        }
        if self.registry_scopes.iter().any(|scope| scope == "*") {
            if self.registry_scopes.len() != 1 {
                return Err(policy_error(
                    "global scope cannot be combined with other registry scopes",
                ));
            }
            if self.signature_verification.level == VerificationLevel::Skip {
                return Err(policy_error("skip cannot be used with a global scope"));
            }
        }
        validate_verification(&self.signature_verification)?;
        match self.signature_verification.level {
            VerificationLevel::Skip => {
                if self.trust_stores.is_some() || self.trusted_identities.is_some() {
                    return Err(policy_error(
                        "skip statements must not set trust stores or trusted identities",
                    ));
                }
            }
            _ => {
                let stores = self
                    .trust_stores
                    .as_ref()
                    .ok_or_else(|| policy_error("trust policy statement is missing trustStores"))?;
                if stores.is_empty() {
                    return Err(policy_error("trustStores is empty"));
                }
                for store in stores {
                    parse_trust_store(store)?;
                }
                let identities = self.trusted_identities.as_ref().ok_or_else(|| {
                    policy_error("trust policy statement is missing trustedIdentities")
                })?;
                parse_identities(identities)?;
            }
        }
        Ok(())
    }

    /// Resolve level defaults and overrides.
    pub fn effective(&self) -> Result<EffectivePolicy, SignatureError> {
        self.validate()?;
        let level = self.signature_verification.level;
        let (authenticity, authentic_timestamp, expiry, revocation) = match level {
            VerificationLevel::Strict => (
                ValidationAction::Enforce,
                ValidationAction::Enforce,
                ValidationAction::Enforce,
                ValidationAction::Enforce,
            ),
            VerificationLevel::Permissive => (
                ValidationAction::Enforce,
                ValidationAction::Log,
                ValidationAction::Log,
                ValidationAction::Log,
            ),
            VerificationLevel::Audit => (
                ValidationAction::Log,
                ValidationAction::Log,
                ValidationAction::Log,
                ValidationAction::Log,
            ),
            VerificationLevel::Skip => (
                ValidationAction::Skip,
                ValidationAction::Skip,
                ValidationAction::Skip,
                ValidationAction::Skip,
            ),
        };
        let mut actions = (authenticity, authentic_timestamp, expiry, revocation);
        if let Some(override_actions) = &self.signature_verification.verification_override {
            if let Some(action) = override_actions.authenticity {
                actions.0 = action;
            }
            if let Some(action) = override_actions.authentic_timestamp {
                actions.1 = action;
            }
            if let Some(action) = override_actions.expiry {
                actions.2 = action;
            }
            if let Some(action) = override_actions.revocation {
                actions.3 = action;
            }
        }
        let has_tsa_store = self.trust_stores.as_ref().is_some_and(|stores| {
            stores
                .iter()
                .any(|store| store.split_once(':').is_some_and(|(kind, _)| kind == "tsa"))
        });
        Ok(EffectivePolicy {
            level,
            integrity: if level == VerificationLevel::Skip {
                ValidationAction::Skip
            } else {
                ValidationAction::Enforce
            },
            authenticity: actions.0,
            authentic_timestamp: actions.1,
            expiry: actions.2,
            revocation: actions.3,
            verify_timestamp: self
                .signature_verification
                .verify_timestamp
                .unwrap_or(TimestampVerification::Always),
            has_tsa_store,
        })
    }

    /// `true` when every notary referrer is eligible before its blob is fetched.
    pub fn identities_unconstrained(&self) -> Result<bool, SignatureError> {
        self.validate()?;
        if self.signature_verification.level == VerificationLevel::Skip {
            return Ok(true);
        }
        let identities = self.trusted_identities.as_deref().unwrap_or(&[]);
        Ok(identities.iter().any(|identity| identity.trim() == "*"))
    }
}

/// Pick the statement for `registry`. Exact scope wins over the global statement.
pub fn select_trust_policy<'a>(
    document: &'a TrustPolicyDocument,
    registry: &str,
) -> Result<&'a TrustPolicyStatement, SignatureError> {
    document.validate()?;
    let exact: Vec<_> = document
        .trust_policies
        .iter()
        .filter(|statement| {
            statement
                .registry_scopes
                .iter()
                .any(|scope| scope == registry)
        })
        .collect();
    if exact.len() > 1 {
        return Err(policy_error(format!(
            "trust policy scope `{registry}` is ambiguous"
        )));
    }
    if let Some(statement) = exact.first() {
        return Ok(*statement);
    }
    let global: Vec<_> = document
        .trust_policies
        .iter()
        .filter(|statement| statement.registry_scopes.iter().any(|scope| scope == "*"))
        .collect();
    if global.len() == 1 {
        return Ok(global[0]);
    }
    Err(policy_error(format!(
        "no trust policy applies to `{registry}`"
    )))
}

/// Parsed `x509.subject` identity, keyed by `C`, `ST`, `L`, `O`, `OU`, or `CN`.
pub fn parse_identities(
    values: &[String],
) -> Result<Vec<BTreeMap<String, String>>, SignatureError> {
    if values.is_empty() {
        return Err(policy_error("trustedIdentities is empty"));
    }
    if values.iter().any(|value| value.trim() == "*") {
        if values.len() != 1 {
            return Err(policy_error(
                "trusted identity wildcard cannot be combined with other identities",
            ));
        }
        return Ok(Vec::new());
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        parsed.push(parse_identity(value)?);
    }
    for (index, identity) in parsed.iter().enumerate() {
        for other in parsed.iter().skip(index + 1) {
            if identities_overlap(identity, other) {
                return Err(policy_error("trustedIdentities overlap"));
            }
        }
    }
    Ok(parsed)
}

fn validate_verification(verification: &SignatureVerification) -> Result<(), SignatureError> {
    if verification.level == VerificationLevel::Skip {
        if verification.verification_override.is_some() {
            return Err(policy_error("skip level cannot be customized"));
        }
        return Ok(());
    }
    let Some(override_actions) = &verification.verification_override else {
        return Ok(());
    };
    check_log_or_enforce("authenticity", override_actions.authenticity)?;
    check_log_or_enforce("authenticTimestamp", override_actions.authentic_timestamp)?;
    check_log_or_enforce("expiry", override_actions.expiry)?;
    if let Some(action) = override_actions.revocation {
        if !matches!(
            action,
            ValidationAction::Enforce | ValidationAction::Log | ValidationAction::Skip
        ) {
            return Err(policy_error("revocation action is not understood"));
        }
    }
    Ok(())
}

fn check_log_or_enforce(
    name: &str,
    action: Option<ValidationAction>,
) -> Result<(), SignatureError> {
    if matches!(action, Some(ValidationAction::Skip)) {
        return Err(policy_error(format!(
            "{name} cannot be skipped by a trust policy override"
        )));
    }
    Ok(())
}

fn parse_trust_store(value: &str) -> Result<(), SignatureError> {
    let Some((kind, name)) = value.split_once(':') else {
        return Err(policy_error(format!("trust store `{value}` is invalid")));
    };
    if !matches!(kind, "ca" | "signingAuthority" | "tsa") {
        return Err(policy_error(format!(
            "trust store type `{kind}` is not supported"
        )));
    }
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
    {
        return Err(policy_error(format!(
            "trust store name `{name}` is invalid"
        )));
    }
    Ok(())
}

fn parse_identity(value: &str) -> Result<BTreeMap<String, String>, SignatureError> {
    let trimmed = value.trim();
    let Some(body) = trimmed.strip_prefix(IDENTITY_PREFIX) else {
        return Err(policy_error(format!(
            "trusted identity `{trimmed}` is not understood"
        )));
    };
    let parts = split_unescaped(body, ',')?;
    if parts.is_empty() {
        return Err(policy_error("trusted identity is empty"));
    }
    let mut attributes = BTreeMap::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            return Err(policy_error("trusted identity contains an empty RDN"));
        }
        let (key, raw_value) = split_once_unescaped(part, '=')
            .ok_or_else(|| policy_error(format!("trusted identity RDN `{part}` is invalid")))?;
        let key = unescape(key.trim())?;
        let rdn_value = unescape(raw_value.trim())?;
        if rdn_value.is_empty() {
            return Err(policy_error("trusted identity RDN value is empty"));
        }
        let normalized = match key.to_ascii_uppercase().as_str() {
            "C" => "C",
            "ST" | "S" => "ST",
            "L" => "L",
            "O" => "O",
            "OU" => "OU",
            "CN" => "CN",
            other => {
                return Err(policy_error(format!(
                    "trusted identity attribute `{other}` is not understood"
                )));
            }
        };
        if attributes
            .insert(normalized.to_string(), rdn_value)
            .is_some()
        {
            return Err(policy_error(
                "trusted identity repeats a distinguished name attribute",
            ));
        }
    }
    if !attributes.contains_key("C")
        || !attributes.contains_key("ST")
        || !attributes.contains_key("O")
    {
        return Err(policy_error(
            "trusted identity must include C, ST, and O attributes",
        ));
    }
    Ok(attributes)
}

fn identities_overlap(left: &BTreeMap<String, String>, right: &BTreeMap<String, String>) -> bool {
    left.iter()
        .all(|(key, value)| right.get(key).is_none_or(|other| other == value))
        && right
            .iter()
            .all(|(key, value)| left.get(key).is_none_or(|other| other == value))
}

fn split_unescaped(input: &str, separator: char) -> Result<Vec<String>, SignatureError> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                return Err(policy_error("trusted identity has a trailing escape"));
            };
            current.push('\\');
            current.push(escaped);
        } else if ch == separator {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    Ok(parts)
}

fn split_once_unescaped(input: &str, separator: char) -> Option<(String, String)> {
    let mut left = String::new();
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            left.push('\\');
            left.push(chars.next()?);
        } else if ch == separator {
            return Some((left, chars.collect()));
        } else {
            left.push(ch);
        }
    }
    None
}

fn unescape(value: &str) -> Result<String, SignatureError> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                return Err(policy_error("trusted identity has a trailing escape"));
            };
            out.push(escaped);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn policy_error(message: impl Into<String>) -> SignatureError {
    SignatureError::new(ErrorKind::Policy, message)
}
