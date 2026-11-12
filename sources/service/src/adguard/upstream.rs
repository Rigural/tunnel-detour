//! Explicit adoption and recoverable ownership of AdGuard's general upstreams.
//!
//! Conditional forwarding and comments remain foreign. This journal coordinates
//! with the domain-forwarding journal in the same manager, never a second writer.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::{AdguardError, DnsInfo};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedUpstream {
    original: Vec<String>,
    applied: Vec<String>,
    pending: Option<Vec<String>>,
    last_approval: String,
}

impl ManagedUpstream {
    pub(super) fn last_approval(&self) -> &str {
        &self.last_approval
    }
    pub(super) fn validate(&self) -> Result<(), AdguardError> {
        validate_general(&self.original)?;
        validate_general(&self.applied)?;
        if let Some(pending) = &self.pending {
            validate_general(pending)?;
        }
        validate_receipt(&self.last_approval)
    }

    fn matches(&self, observed: &[String]) -> bool {
        self.applied == observed || self.pending.as_deref() == Some(observed)
    }
}

/// An administrator explicitly approves a preview of one complete DNS snapshot.
/// The random receipt is a freshness token, not an authentication credential.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamPreview {
    pub receipt: String,
    pub snapshot: DnsInfo,
    pub resolver: SocketAddr,
    pub control: crate::config::AdguardSettings,
    pub expires_at: u64,
}

pub(super) fn validate_receipt(receipt: &str) -> Result<(), AdguardError> {
    if receipt.len() != 32
        || !receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AdguardError::UpstreamApproval);
    }
    Ok(())
}

pub(super) fn general(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| {
            let value = line.trim();
            !value.is_empty() && !value.starts_with('#') && !value.starts_with("[/")
        })
        .cloned()
        .collect()
}

/// Only import an explicitly TCP endpoint. Importing UDP, DoH or DoT as TCP
/// would change its transport while pretending to copy the existing setting.
pub(super) fn import(lines: &[String]) -> Result<SocketAddr, AdguardError> {
    let current = general(lines);
    let [line] = current.as_slice() else {
        return Err(AdguardError::UnsupportedGeneralUpstreams);
    };
    let endpoint = line
        .strip_prefix("tcp://")
        .ok_or(AdguardError::UnsupportedGeneralUpstreams)?;
    plain_endpoint(endpoint)
}

fn plain_endpoint(value: &str) -> Result<SocketAddr, AdguardError> {
    if let Some(address) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let endpoint = SocketAddr::new(
            std::net::IpAddr::V6(
                address
                    .parse()
                    .map_err(|_| AdguardError::UnsupportedGeneralUpstreams)?,
            ),
            53,
        );
        crate::config::validate_tcp_resolver(endpoint)
            .map_err(|_| AdguardError::UnsupportedGeneralUpstreams)?;
        return Ok(endpoint);
    }
    // Unlike UCI's literal address field, a TCP URI requires brackets around
    // its IPv6 host. Do not guess whether a final numeric label was a port.
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(AdguardError::UnsupportedGeneralUpstreams);
    }
    crate::config::parse_resolver_endpoint(value)
        .map_err(|_| AdguardError::UnsupportedGeneralUpstreams)
}

pub(super) fn validate_general(lines: &[String]) -> Result<(), AdguardError> {
    // AdGuard may reinstate factory providers for an empty general list. An
    // explicit, restorable baseline is required before accepting ownership.
    if lines.is_empty() || lines.len() > 64 {
        return Err(AdguardError::UnsupportedGeneralUpstreams);
    }
    for line in lines {
        let value = line.trim();
        if let Some(endpoint) = value.strip_prefix("tcp://") {
            plain_endpoint(endpoint)?;
        } else if value.starts_with('[') {
            plain_endpoint(value)?;
        } else {
            crate::config::parse_resolver_endpoint(value)
                .map_err(|_| AdguardError::UnsupportedGeneralUpstreams)?;
        }
    }
    Ok(())
}

fn replace_general(lines: &[String], replacement: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut inserted = false;
    for line in lines {
        if general(std::slice::from_ref(line)).is_empty() {
            result.push(line.clone());
        } else if !inserted {
            result.extend_from_slice(replacement);
            inserted = true;
        }
    }
    if !inserted {
        result.extend_from_slice(replacement);
    }
    result
}

pub(super) struct UpstreamPlan {
    /// Persist before the API call, including both possible remote outcomes.
    pub before: Option<ManagedUpstream>,
    /// Persist only after the API confirms the exact expected snapshot.
    pub after: Option<ManagedUpstream>,
    pub lines: Vec<String>,
    pub foreign_change_preserved: bool,
}

/// Compute a write without mutating state or trusting the remote API to provide CAS.
/// A pending transition recognizes both sides of a lost API response after restart.
pub(super) fn plan(
    current: &DnsInfo,
    resolver: Option<SocketAddr>,
    owned: Option<&ManagedUpstream>,
    preview: Option<&UpstreamPreview>,
) -> Result<UpstreamPlan, AdguardError> {
    let observed = general(&current.upstream_dns);
    let Some(resolver) = resolver else {
        let (lines, before, changed) = match owned {
            Some(owned) if owned.matches(&observed) => {
                let mut pending = owned.clone();
                pending.applied = observed;
                pending.pending = Some(owned.original.clone());
                (
                    replace_general(&current.upstream_dns, &owned.original),
                    Some(pending),
                    false,
                )
            }
            Some(_) => (current.upstream_dns.clone(), owned.cloned(), true),
            None => (current.upstream_dns.clone(), None, false),
        };
        return Ok(UpstreamPlan {
            before,
            after: None,
            lines,
            foreign_change_preserved: changed,
        });
    };
    current.validate_managed()?;
    let desired = vec![format!("tcp://{resolver}")];
    validate_general(&desired)?;
    let needs_approval = owned.is_none_or(|state| !state.matches(&observed));
    let mut next = match owned {
        Some(state) => state.clone(),
        None => {
            validate_general(&observed)?;
            ManagedUpstream {
                original: observed.clone(),
                applied: observed.clone(),
                pending: None,
                last_approval: String::new(),
            }
        }
    };
    if needs_approval {
        let preview = preview.ok_or(if owned.is_some() {
            AdguardError::ConcurrentChange
        } else {
            AdguardError::UpstreamApproval
        })?;
        validate_receipt(&preview.receipt)?;
        if preview.receipt == next.last_approval {
            return Err(AdguardError::ConcurrentChange);
        }
        if preview.snapshot != *current || preview.resolver != resolver {
            return Err(AdguardError::UpstreamApproval);
        }
        validate_general(&observed)?;
    }
    // A supplied review is consumed by this application even when the existing
    // ownership already permits the change. Otherwise a later foreign edit
    // restoring its snapshot could replay a previously accepted review.
    if let Some(preview) = preview {
        validate_receipt(&preview.receipt)?;
        next.last_approval.clone_from(&preview.receipt);
    }
    next.applied = observed;
    next.pending = Some(desired.clone());
    next.validate()?;
    let mut after = next.clone();
    after.applied = desired.clone();
    after.pending = None;
    Ok(UpstreamPlan {
        before: Some(next),
        after: Some(after),
        lines: replace_general(&current.upstream_dns, &desired),
        foreign_change_preserved: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn snapshot() -> DnsInfo {
        DnsInfo {
            upstream_dns: vec![
                "# administrator comment".into(),
                "192.0.2.53:5353".into(),
                "[/local.example.test/]192.0.2.1".into(),
            ],
            upstream_dns_file: String::new(),
            bootstrap_dns: Some(vec!["192.0.2.53".into()]),
            fallback_dns: Some(vec![]),
        }
    }

    fn preview(current: &DnsInfo, resolver: SocketAddr, receipt: &str) -> UpstreamPreview {
        UpstreamPreview {
            receipt: receipt.into(),
            snapshot: current.clone(),
            resolver,
            control: crate::config::AdguardSettings {
                api_url: "http://127.0.0.1:3000".into(),
                username: None,
                password: None,
            },
            expires_at: u64::MAX,
        }
    }

    #[test]
    fn r091_general_upstream_adoption_requires_fresh_exact_preview_and_preserves_foreign_lines()
    -> TestResult {
        let current = snapshot();
        let resolver = "192.0.2.54:5354".parse()?;
        assert!(plan(&current, Some(resolver), None, None).is_err());
        let approval = preview(&current, resolver, "0123456789abcdef0123456789abcdef");
        let adopted = plan(&current, Some(resolver), None, Some(&approval))?;
        assert_eq!(
            adopted.lines,
            [
                "# administrator comment",
                "tcp://192.0.2.54:5354",
                "[/local.example.test/]192.0.2.1"
            ]
        );
        let mut remote = current.clone();
        remote.upstream_dns = adopted.lines.clone();
        let owned = adopted.after.as_ref().ok_or("missing ownership")?;
        assert_eq!(
            plan(&remote, Some(resolver), Some(owned), None)?.lines,
            remote.upstream_dns
        );
        // An editor restoring the old snapshot must not replay the consumed
        // adoption receipt and automatically authorize another overwrite.
        assert!(plan(&current, Some(resolver), Some(owned), Some(&approval)).is_err());
        let mut changed = current.clone();
        changed.bootstrap_dns = Some(vec!["192.0.2.55".into()]);
        assert!(plan(&changed, Some(resolver), None, Some(&approval)).is_err());
        let fresh = preview(&current, resolver, "1123456789abcdef0123456789abcdef");
        assert!(plan(&current, Some(resolver), Some(owned), Some(&fresh)).is_ok());
        let next_resolver = "192.0.2.55:5355".parse()?;
        let reviewed_update = preview(&remote, next_resolver, "2123456789abcdef0123456789abcdef");
        let update = plan(
            &remote,
            Some(next_resolver),
            Some(owned),
            Some(&reviewed_update),
        )?;
        let updated = update.after.as_ref().ok_or("missing updated ownership")?;
        assert!(
            plan(
                &remote,
                Some(next_resolver),
                Some(updated),
                Some(&reviewed_update)
            )
            .is_err(),
            "a review accepted during normal managed operation was reused after a foreign restoration"
        );
        let mut missing = current.clone();
        missing.upstream_dns = vec!["[/local.example.test/]192.0.2.1".into()];
        assert!(plan(&missing, Some(resolver), None, None).is_err());
        let mut encrypted = current;
        encrypted.upstream_dns = vec!["https://resolver.example.test/dns-query".into()];
        assert!(
            plan(
                &encrypted,
                Some(resolver),
                None,
                Some(&preview(&encrypted, resolver, &fresh.receipt))
            )
            .is_err()
        );
        assert!(import(&encrypted.upstream_dns).is_err());
        assert!(import(&["192.0.2.53".into()]).is_err());
        assert_eq!(import(&["tcp://192.0.2.54:5354".into()])?, resolver);
        let resolver6 = "[2001:db8::53]:5353".parse()?;
        assert_eq!(import(&["tcp://[2001:db8::53]:5353".into()])?, resolver6);
        assert_eq!(
            import(&["tcp://[2001:db8::53]".into()])?,
            "[2001:db8::53]:53".parse()?
        );
        assert!(import(&["tcp://2001:db8::53".into()]).is_err());
        assert!(import(&["tls://[2001:db8::53]:853".into()]).is_err());
        assert!(import(&["[2001:db8::53]:5353".into()]).is_err());
        let bracketed = vec![
            "[2001:db8::53]:5353".into(),
            "[/local.example.test/]192.0.2.1".into(),
        ];
        assert_eq!(general(&bracketed), ["[2001:db8::53]:5353"]);
        validate_general(&general(&bracketed))?;
        let reviewed6 = preview(&remote, resolver6, "3123456789abcdef0123456789abcdef");
        assert_eq!(
            plan(&remote, Some(resolver6), Some(owned), Some(&reviewed6))?.lines,
            [
                "# administrator comment",
                "tcp://[2001:db8::53]:5353",
                "[/local.example.test/]192.0.2.1"
            ]
        );
        Ok(())
    }

    #[test]
    fn r092_pending_upstream_recovery_recognizes_both_outcomes_and_cleanup_preserves_foreign_edits()
    -> TestResult {
        let original = snapshot();
        let resolver = "192.0.2.54:5354".parse()?;
        let receipt = preview(&original, resolver, "0123456789abcdef0123456789abcdef");
        let adoption = plan(&original, Some(resolver), None, Some(&receipt))?;
        let pending = adoption.before.as_ref().ok_or("missing pending state")?;
        let recovered = plan(&original, Some(resolver), Some(pending), None)?;
        assert_eq!(recovered.lines, adoption.lines);
        let mut applied = original.clone();
        applied.upstream_dns = adoption.lines;
        assert_eq!(
            plan(&applied, Some(resolver), Some(pending), None)?.lines,
            applied.upstream_dns
        );
        let cleanup = plan(&applied, None, Some(pending), None)?;
        assert_eq!(cleanup.lines, original.upstream_dns);
        assert!(cleanup.after.is_none());
        let cleanup_pending = cleanup.before.as_ref().ok_or("missing cleanup journal")?;
        assert_eq!(
            plan(&original, None, Some(cleanup_pending), None)?.lines,
            original.upstream_dns
        );
        let mut foreign = applied;
        foreign.upstream_dns[1] = "tcp://192.0.2.55:5355".into();
        assert!(plan(&foreign, Some(resolver), Some(pending), None).is_err());
        let preserved = plan(&foreign, None, Some(pending), None)?;
        assert_eq!(preserved.lines, foreign.upstream_dns);
        assert!(preserved.foreign_change_preserved);
        assert!(preserved.after.is_none());
        Ok(())
    }
}
