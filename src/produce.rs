//! What a producer signs: for some gates that passed on a tree, the payload
//! and every key it is filed under (SPEC.md, "Producing"). amont at pre-push
//! and `git-attest sign` in CI build their blocks here, so both sign the same
//! bytes for the same tree.

use std::path::Path;

use crate::fingerprint::{absent_optional, canon, canon_key, fingerprint, key};
use crate::format::payload;
use crate::spec::{plan_exempt, AtError, PlanExempt, SPEC_PATHS};

/// One attestation, ready to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The payload, trailing newline included.
    pub payload: String,
    /// `(gate, fingerprint)` for each signed gate the spec declares, in spec
    /// order: the payload's `input` lines.
    pub inputs: Vec<(String, String)>,
    /// The canonical tree, when the repository has not opted out.
    pub canon: Option<String>,
    /// The keys in the inputs ref: one per input, then the canonical one.
    pub input_keys: Vec<String>,
}

/// Normalise a gate list the way the payload carries it: one space between
/// names, none around. Whitespace inside the list is the one thing that
/// could break a note.
pub fn gate_list(gates: &str) -> String {
    gates.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The attestation of `gates` (already normalised) on `tree`, which ran on
/// `platform`, by `producer`. `log` gets the reason for every route the
/// block will not carry, in the words `sign.sh` used.
pub fn attestation(
    root: &Path,
    tree: &str,
    gates: &str,
    platform: &str,
    producer: &str,
    log: &mut Vec<String>,
) -> Attestation {
    let signed: Vec<&str> = gates.split_whitespace().collect();
    let mut inputs = Vec::new();
    let mut absent: Vec<String> = Vec::new();
    // A spec that is there and unusable degrades the block to its object key
    // (SPEC.md, "Producing"): no input lines, and no canonical tree either.
    let mut unusable = true;
    match crate::spec::at(root, tree) {
        Ok(None) => unusable = false,
        Ok(Some((_, spec))) => {
            unusable = false;
            for (gate, _) in &spec.gates {
                if !signed.contains(&gate.as_str()) {
                    continue;
                }
                match fingerprint(root, tree, &spec, gate) {
                    Ok(fp) => {
                        absent.extend(absent_optional(root, tree, &spec, gate));
                        inputs.push((gate.clone(), fp));
                    }
                    Err(_) => log.push(format!(
                        "gate {gate}: no fingerprint (a declared path does not exist in the signed tree)"
                    )),
                }
            }
        }
        Err(AtError::Ambiguous) => log.push(format!(
            "both {} and {} exist; no input fingerprints",
            SPEC_PATHS[0], SPEC_PATHS[1]
        )),
        Err(AtError::Unreadable(path)) => log.push(format!(
            "cannot read {path} from the signed tree; no input fingerprints"
        )),
        Err(AtError::Invalid(path, why)) => {
            log.push(format!("{path} {why}; no input fingerprints"))
        }
        Err(AtError::Unlisted) => {
            log.push("cannot list the signed tree; no input fingerprints".into())
        }
    }
    if !absent.is_empty() {
        absent.sort();
        absent.dedup();
        log.push(format!(
            "optional paths absent (their absence is bound): {}",
            absent.join(" ")
        ));
    }
    let canon_oid = match plan_exempt(root, tree) {
        _ if unusable => {
            log.push("the spec is unusable; no canonical tree".into());
            None
        }
        PlanExempt::Off | PlanExempt::OffByAmontConf => {
            log.push("planExempt is off here; no canonical tree".into());
            None
        }
        PlanExempt::Unreadable => {
            log.push("cannot read amont.conf or attest-inputs; no canonical tree".into());
            None
        }
        PlanExempt::On => {
            let c = canon(root, tree).ok();
            if c.is_none() {
                log.push("cannot compute the canonical tree; none attached".into());
            }
            c
        }
    };
    let mut input_keys: Vec<String> = inputs
        .iter()
        .filter_map(|(g, fp)| key(root, g, fp).ok())
        .collect();
    if let Some(c) = &canon_oid {
        if let Ok(k) = canon_key(root, c) {
            input_keys.push(k);
        }
    }
    Attestation {
        payload: payload(
            tree,
            gates,
            platform,
            &inputs,
            canon_oid.as_deref(),
            producer,
        ),
        inputs,
        canon: canon_oid,
        input_keys,
    }
}
