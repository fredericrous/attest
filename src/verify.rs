//! The verifier: given a repository and an `allowed_signers`, what does a
//! valid attestation cover for the tree checked out there?
//!
//! `SPEC.md` is the contract; this module and `verify.sh` are two
//! implementations of it, kept honest by `tests/conformance.sh`.
//!
//! Every failure is the same failure. No note, no signers file, an unreadable
//! key, a tree that moved, a signature that does not verify — all mean "not
//! covered", and not covered means the caller runs its tests. Nothing here can
//! let an untested tree skip CI; it can only cost a redundant run. That is why
//! this module returns verdicts rather than errors.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::fingerprint::{canon, canon_key, fingerprint, key};
use crate::format::{
    canon_claim, field, input_fp, platform_matches, split_blocks, FORMAT, INPUTS_REF, LOCAL_PREFIX,
    MAX_BLOCKS, NAMESPACE, NOTES_REF,
};
use crate::git;
use crate::notes::{sync_mirrors, Mirror};
use crate::spec::{plan_exempt, AtError, PlanExempt, Spec, DEPRECATED_OPT_OUT, SPEC_PATHS};

/// How many signatures one invocation verifies, over every candidate. A
/// verification is one call of [`verify`]; blocks the cheap checks reject and
/// blocks already judged do not count.
pub const MAX_VERIFICATIONS: usize = 64;

/// What the verifier concluded, and how it got there.
///
/// The trail is not decoration. Fail-open's worst property is silence: when a
/// skip does not happen, nothing tells you whether the attestation was absent,
/// stale, signed by another key, or minted on another platform. Carrying the
/// reasons out of the same code path that made the decision is what keeps
/// `explain` from becoming a second, drifting implementation of `covered`.
pub struct Verdict {
    /// Covered gate names, first-appearance order, no duplicates. Empty means
    /// nothing is covered.
    pub gates: Vec<String>,
    pub trail: Vec<String>,
    /// What became of `refs/notes/amont-attest` and `…-inputs`, in that
    /// order; `None` when the verifier stopped before reading any notes.
    pub notes: Option<(Mirror, Mirror)>,
    /// Lines that report a change to the repository's refs. They are shown
    /// even without `explain`: data went away, and they say how to restore it.
    pub loud: Vec<String>,
    /// Lines that say something committed is deprecated, also in the trail
    /// where they arose. Shown even without `explain`, so the repository
    /// hears it before the old form stops working.
    pub warnings: Vec<String>,
}

impl Verdict {
    fn nothing(reason: impl Into<String>) -> Self {
        Verdict {
            gates: Vec::new(),
            trail: vec![reason.into()],
            notes: None,
            loud: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Record a reason, unless it repeats the one before it.
fn push_reason(trail: &mut Vec<String>, reason: String) {
    if trail.last() != Some(&reason) {
        trail.push(reason);
    }
}

/// A lock a killed git left on a MIRROR fails every later update of it; say
/// so, with the command, rather than lose coverage in silence.
fn lock_reason(root: &Path, notes_ref: &str) -> Option<String> {
    let lock = format!("refs/notes/{notes_ref}.lock");
    let path = git::stdout_in(root, &["rev-parse", "--git-path", &lock])?;
    // `--git-path` answers relative to where git ran.
    let path = root.join(path).display().to_string();
    Path::new(&path).exists().then(|| {
        format!("a git that was killed left a lock on refs/notes/{notes_ref}; if no git is running: rm {path}")
    })
}

/// The line that says why a mirror was not judged, if it was not.
fn state_reason(notes_ref: &str, state: Mirror) -> Option<String> {
    match state {
        Mirror::Unreachable => Some(format!(
            "cannot fetch refs/notes/{notes_ref} from origin (no credentials? persist-credentials: false?); local mirror not judged, running everything"
        )),
        Mirror::TimedOut => Some(format!(
            "origin did not answer within {} s for refs/notes/{notes_ref}; local mirror not judged, running everything",
            git::REMOTE_BUDGET_SECS
        )),
        Mirror::Unwritable => Some(format!(
            "cannot update refs/notes/{notes_ref} to origin's copy; local mirror not judged"
        )),
        Mirror::Undeletable => Some(format!(
            "origin has no refs/notes/{notes_ref} but the local mirror could not be deleted (read-only .git?); local mirror not judged"
        )),
        _ => None,
    }
}

/// Where a repository keeps its `allowed_signers` when the caller does not say.
///
/// Resolved from the REPOSITORY ROOT, not the working directory. A workflow
/// that sets `working-directory` — a monorepo matrix running inside
/// `packages/<x>` — puts the step in a subdirectory, where a relative
/// `.github/allowed_signers` does not exist. The verifier would then find no
/// signers, cover nothing, and fail open FOREVER: the suite still runs, CI
/// still passes, and nothing anywhere says the gate is dead.
pub fn default_signers(dir: &Path) -> Option<PathBuf> {
    let root = git::stdout_in(dir, &["rev-parse", "--show-toplevel"]).map(PathBuf::from);
    [".forgejo/allowed_signers", ".github/allowed_signers"]
        .into_iter()
        .map(|rel| match &root {
            Some(root) => root.join(rel),
            None => dir.join(rel),
        })
        .find(|p| p.exists())
}

/// A caller-supplied signers path, resolved the way the default is: relative
/// to the REPOSITORY ROOT, not the working directory. Absolute paths pass
/// through.
pub fn resolve_signers(dir: &Path, given: &str) -> PathBuf {
    let path = PathBuf::from(given);
    if path.is_absolute() {
        return path;
    }
    match git::stdout_in(dir, &["rev-parse", "--show-toplevel"]) {
        Some(root) => PathBuf::from(root).join(path),
        None => dir.join(path),
    }
}

/// Add names not already present, keeping first-appearance order.
pub(crate) fn union<'a>(into: &mut Vec<String>, names: impl Iterator<Item = &'a str>) {
    for name in names {
        if !into.iter().any(|g| g == name) {
            into.push(name.to_string());
        }
    }
}

/// The uniform rule, as a pure function: a gate of a verified block is
/// covered if the block's tree IS the checked-out tree, or its canonical tree
/// is the checked-out one's, or if the block claims a fingerprint for that gate
/// equal to the one computed here.
pub fn covered_gates<'a>(
    tree_matches: bool,
    canon_matches: bool,
    gates: &'a str,
    fp_of_block: impl Fn(&str) -> Option<&'a str>,
    mut fp_head: impl FnMut(&str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for g in gates.split_whitespace() {
        let ok = tree_matches
            || canon_matches
            || match (fp_of_block(g), fp_head(g)) {
                (Some(claimed), Some(here)) => claimed == here,
                _ => false,
            };
        if ok {
            union(&mut out, std::iter::once(g));
        }
    }
    out
}

/// Everything one invocation accumulates while judging notes, so the same
/// loop serves the object-keyed candidates and the fingerprint-keyed ones.
struct Judge<'a> {
    root: PathBuf,
    head_tree: String,
    signers: &'a Path,
    principal: Option<&'a str>,
    require_platform: Option<&'a str>,
    anywhere: &'a [String],
    spec: Option<Spec>,
    fp_memo: Vec<(String, Option<String>)>,
    canon_memo: Option<Option<String>>,
    canon_used: bool,
    warnings: Vec<String>,
    covered: Vec<String>,
    trail: Vec<String>,
    seen_notes: Vec<String>,
    seen_blocks: Vec<u64>,
    verifications: usize,
    exhausted: bool,
    tried: bool,
}

impl Judge<'_> {
    /// The fingerprint of `gate` on the checked-out tree, computed once.
    fn fp_head(&mut self, gate: &str) -> Option<String> {
        if let Some((_, fp)) = self.fp_memo.iter().find(|(g, _)| g == gate) {
            return fp.clone();
        }
        let fp = self
            .spec
            .as_ref()
            .and_then(|s| fingerprint(&self.root, &self.head_tree, s, gate).ok());
        self.fp_memo.push((gate.to_string(), fp.clone()));
        fp
    }

    /// The canonical fingerprint of the checked-out tree, computed once; `None`
    /// when the repository opted out (`set planExempt off`) or git failed.
    fn canon_here(&mut self) -> Option<String> {
        if let Some(c) = &self.canon_memo {
            return c.clone();
        }
        let c = match plan_exempt(&self.root, &self.head_tree) {
            how @ (PlanExempt::Off | PlanExempt::OffByAmontConf) => {
                push_reason(
                    &mut self.trail,
                    "planExempt is off here; canonical trees are not used".into(),
                );
                if how == PlanExempt::OffByAmontConf {
                    push_reason(&mut self.trail, DEPRECATED_OPT_OUT.into());
                    union(&mut self.warnings, std::iter::once(DEPRECATED_OPT_OUT));
                }
                None
            }
            PlanExempt::Unreadable => {
                push_reason(
                    &mut self.trail,
                    "cannot read amont.conf or attest-inputs; canonical trees are not used".into(),
                );
                None
            }
            PlanExempt::On => {
                let c = canon(&self.root, &self.head_tree).ok();
                if c.is_none() {
                    push_reason(
                        &mut self.trail,
                        "cannot compute the canonical tree; canonical trees are not used".into(),
                    );
                }
                c
            }
        };
        self.canon_memo = Some(c.clone());
        c
    }

    /// Judge every block of the note on `object` in `notes_ref`.
    fn judge(&mut self, notes_ref: &str, object: &str, at: &str) {
        if self.exhausted {
            return;
        }
        let Some(listing) =
            git::stdout_in(&self.root, &["notes", "--ref", notes_ref, "list", object])
        else {
            return;
        };
        let note_oid = listing.split_whitespace().next().unwrap_or("").to_string();
        if self.seen_notes.contains(&note_oid) {
            return;
        }
        self.seen_notes.push(note_oid);
        let Some(body) = git::stdout_in(&self.root, &["notes", "--ref", notes_ref, "show", object])
        else {
            return;
        };
        self.tried = true;

        // LF only, the whole note: `verify.sh` applies the same test before
        // any tool sees the bytes, because some awks drop carriage returns.
        if body.contains('\r') {
            push_reason(
                &mut self.trail,
                format!("note on {at} contains carriage returns; the format is LF-only"),
            );
            return;
        }

        let (blocks, truncated) = split_blocks(&body);
        if truncated {
            push_reason(
                &mut self.trail,
                format!("note on {at} has more than {MAX_BLOCKS} blocks; the rest were ignored"),
            );
        }
        if blocks.is_empty() {
            push_reason(
                &mut self.trail,
                format!("note on {at} carries no signature block"),
            );
            return;
        }
        let several = blocks.len() > 1;
        for (i, block) in blocks.iter().enumerate() {
            let where_ = if several {
                format!("{at} block {}", i + 1)
            } else {
                at.to_string()
            };
            let payload = &block.payload;
            if payload.split('\n').next() != Some(FORMAT) {
                push_reason(
                    &mut self.trail,
                    format!("note on {where_} is not {FORMAT} — a newer producer wrote it"),
                );
                continue;
            }
            let (Some(tree), Some(gates), Some(ran_on)) = (
                field(payload, "tree"),
                field(payload, "gates"),
                field(payload, "platform"),
            ) else {
                push_reason(
                    &mut self.trail,
                    format!("note on {where_} is missing a required field"),
                );
                continue;
            };
            if gates.is_empty() {
                push_reason(
                    &mut self.trail,
                    "attestation lists no gates — a signed way of saying nothing".into(),
                );
                continue;
            }
            // The same block reached through another key has the same
            // verdict: its content and HEAD are all that decide it.
            let mut h = std::collections::hash_map::DefaultHasher::new();
            block.payload.hash(&mut h);
            block.signature.hash(&mut h);
            let bh = h.finish();
            if self.seen_blocks.contains(&bh) {
                continue;
            }
            self.seen_blocks.push(bh);
            if self.verifications >= MAX_VERIFICATIONS {
                push_reason(
                    &mut self.trail,
                    format!("the budget of {MAX_VERIFICATIONS} signature verifications is spent; remaining candidates were not read"),
                );
                self.exhausted = true;
                return;
            }
            self.verifications += 1;
            // Signature BEFORE anything the block's claims could buy it: the
            // `anywhere` list and the input fingerprints may only admit gates
            // from a block that actually verified.
            let signer = match crate::sign::verify(
                NAMESPACE,
                payload,
                &block.signature,
                self.signers,
                self.principal,
            ) {
                Ok(signer) => signer,
                Err(why) => {
                    push_reason(&mut self.trail, format!("note on {where_}: {why}"));
                    continue;
                }
            };
            // The uniform rule, per gate: the tree is the checked-out tree,
            // or the block's fingerprint for that gate is the one computed
            // here.
            let tree_matches = tree == self.head_tree;
            // The canonical tree, for a block of another tree that claims
            // one: asked of the checked-out tree, so a block filed under
            // several keys is judged the same wherever it is first met.
            let canon_matches = !tree_matches
                && match (
                    canon_claim(payload),
                    canon_claim(payload).and_then(|_| self.canon_here()),
                ) {
                    (Some(claimed), Some(here)) => claimed == here,
                    _ => false,
                };
            let kept = covered_gates(
                tree_matches,
                canon_matches,
                gates,
                |g| input_fp(payload, g),
                |g| self.fp_head(g),
            );
            if kept.is_empty() {
                push_reason(
                    &mut self.trail,
                    format!(
                        "attested tree {tree} is not the checked-out tree {} and neither its canonical tree nor an input fingerprint of {where_} matches",
                        self.head_tree
                    ),
                );
                continue;
            }
            let how = if tree_matches {
                ""
            } else if canon_matches {
                " (by canonical tree)"
            } else {
                " (by input fingerprint)"
            };
            let kept_str = kept.join(" ");
            // A pass is a pass ON SOMETHING: a macOS `cargo test` is no
            // evidence about the Windows leg of a matrix.
            if platform_matches(self.require_platform, ran_on) {
                union(&mut self.covered, kept.iter().map(String::as_str));
                self.canon_used |= canon_matches;
                push_reason(
                    &mut self.trail,
                    format!("covered by {signer} on {ran_on}{how}: {kept_str}"),
                );
                continue;
            }
            let accepted: Vec<&str> = kept
                .iter()
                .map(String::as_str)
                .filter(|g| self.anywhere.iter().any(|a| a == g))
                .collect();
            union(&mut self.covered, accepted.iter().copied());
            self.canon_used |= canon_matches && !accepted.is_empty();
            let want = self.require_platform.unwrap_or("any");
            let mut reason = format!("attested on {ran_on} by {signer}{how}, this leg is {want}");
            if !accepted.is_empty() {
                reason.push_str("; accepted anywhere: ");
                reason.push_str(&accepted.join(" "));
            }
            push_reason(&mut self.trail, reason);
        }
    }
}

/// The spec at the checked-out tree, or the reason there is none to use.
fn load_spec(root: &Path, head_tree: &str, trail: &mut Vec<String>) -> Option<Spec> {
    match crate::spec::at(root, head_tree) {
        Ok(found) => found.map(|(_, spec)| spec),
        Err(AtError::Ambiguous) => {
            push_reason(
                trail,
                format!(
                    "both {} and {} exist; input fingerprints disabled",
                    SPEC_PATHS[0], SPEC_PATHS[1]
                ),
            );
            None
        }
        Err(AtError::Unreadable(path)) => {
            push_reason(
                trail,
                format!("cannot read {path} from HEAD's tree; input fingerprints disabled"),
            );
            None
        }
        Err(AtError::Invalid(path, why)) => {
            push_reason(trail, format!("{path} {why}; input fingerprints disabled"));
            None
        }
    }
}

/// The whole decision, trail included.
///
/// `principal` of `None` means "whoever the signature says, if that key is in
/// the file"; `Some` narrows it to one identity. `require_platform` of `None`
/// means the caller has stated this suite's result does not depend on where
/// it ran. `anywhere` names gates the caller accepts from any platform — its
/// committed statement that THOSE checks cannot depend on where they ran — and
/// only ever admits gates from a block whose signature verified.
pub fn evaluate(
    dir: &Path,
    signers: &Path,
    principal: Option<&str>,
    require_platform: Option<&str>,
    anywhere: &[String],
    include_local: bool,
) -> Verdict {
    let mut trail = Vec::new();
    let mut loud = Vec::new();

    if !signers.is_file() {
        return Verdict::nothing(format!("{} does not exist", signers.display()));
    }

    // The repository first, as verify.sh does: outside one there is nothing
    // to sync, and `notes=` stays empty.
    let Some(root) = git::stdout_in(dir, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
    else {
        push_reason(&mut trail, "not a git repository".into());
        return Verdict {
            gates: Vec::new(),
            trail,
            notes: None,
            loud,
            warnings: Vec::new(),
        };
    };

    let (st_main, st_inputs) = sync_mirrors(&root, &mut loud);
    let notes = Some((st_main, st_inputs));
    for (r, st) in [(NOTES_REF, st_main), (INPUTS_REF, st_inputs)] {
        if let Some(why) = state_reason(r, st) {
            push_reason(&mut trail, why);
        }
        if let Some(why) = lock_reason(&root, r) {
            push_reason(&mut trail, why);
        }
    }
    if !include_local {
        for r in [NOTES_REF, INPUTS_REF] {
            let local = format!("refs/notes/{LOCAL_PREFIX}{r}");
            // A ref that holds notes: `git notes remove` of the last one
            // leaves the ref behind, and that is nothing to report.
            if git::stdout_in(
                &root,
                &["notes", "--ref", &format!("{LOCAL_PREFIX}{r}"), "list"],
            )
            .is_some()
            {
                push_reason(
                    &mut trail,
                    format!("{local} holds unpushed blocks, ignored without --include-local"),
                );
            }
        }
    }
    // The refs each lookup reads, in order: the mirror, then the unpushed.
    let refs = |mirror: &str, st: Mirror| -> Vec<String> {
        let mut v = Vec::new();
        if st.judged() {
            v.push(mirror.to_string());
        }
        if include_local {
            v.push(format!("{LOCAL_PREFIX}{mirror}"));
        }
        v
    };
    let refs_main = refs(NOTES_REF, st_main);
    let refs_inputs = refs(INPUTS_REF, st_inputs);

    let Some(head_tree) = git::stdout_in(&root, &["rev-parse", "HEAD^{tree}"]) else {
        push_reason(
            &mut trail,
            "cannot resolve HEAD^{tree} — not a git repository?".into(),
        );
        return Verdict {
            gates: Vec::new(),
            trail,
            notes,
            loud,
            warnings: Vec::new(),
        };
    };

    let spec = load_spec(&root, &head_tree, &mut trail);
    let mut judge = Judge {
        root,
        head_tree: head_tree.clone(),
        signers,
        principal,
        require_platform,
        anywhere,
        spec,
        fp_memo: Vec::new(),
        canon_memo: None,
        canon_used: false,
        warnings: Vec::new(),
        covered: Vec::new(),
        trail,
        seen_notes: Vec::new(),
        seen_blocks: Vec::new(),
        verifications: 0,
        exhausted: false,
        tried: false,
    };

    // The TREE first: it is what the signature covers, so it is the only key
    // that survives a squash-merge, an amend or a rebase. HEAD and HEAD^2
    // follow for notes written by a producer that keyed by commit only —
    // HEAD^2 because a PR checkout is a merge commit git made a moment ago,
    // whose second parent is the pushed tip that carries the note.
    for candidate in [head_tree.as_str(), "HEAD", "HEAD^2"] {
        let Some(object) = git::stdout_in(
            &judge.root,
            &["rev-parse", "--verify", "--quiet", candidate],
        ) else {
            continue;
        };
        for r in &refs_main {
            judge.judge(r, &object, &label(r, candidate));
        }
    }

    // Then, lazily, the fingerprint-keyed notes: only for gates the spec
    // declares and nothing above covered. Each costs a few git processes and
    // one notes lookup; the common case (the tree matched) costs nothing.
    let spec_gates: Vec<String> = judge
        .spec
        .as_ref()
        .map(|s| s.gates.iter().map(|(g, _)| g.clone()).collect())
        .unwrap_or_default();
    for gate in spec_gates {
        if judge.exhausted || judge.covered.contains(&gate) {
            continue;
        }
        let Some(fp) = judge.fp_head(&gate) else {
            push_reason(
                &mut judge.trail,
                format!("gate {gate}: no fingerprint here (a declared path does not exist in this tree)"),
            );
            continue;
        };
        let Ok(k) = key(&judge.root, &gate, &fp) else {
            continue;
        };
        let at = format!("input {gate} {}", &fp[..12]);
        for r in &refs_inputs {
            judge.judge(r, &k, &label(r, &at));
        }
    }

    // Last, the canonical-tree key: one more note lookup, for a block signed
    // on another tree whose canonical form is this one's.
    if !judge.exhausted {
        if let Some(c) = judge.canon_here() {
            if let Ok(k) = canon_key(&judge.root, &c) {
                let at = format!("canon {}", &c[..12]);
                for r in &refs_inputs {
                    judge.judge(r, &k, &label(r, &at));
                }
                if judge.canon_used {
                    push_reason(&mut judge.trail, format!("canonical tree {c}, key {k}"));
                }
            }
        }
    }

    if !judge.tried {
        push_reason(
            &mut judge.trail,
            format!("no attestation found for tree {head_tree}"),
        );
    }
    Verdict {
        gates: judge.covered,
        trail: judge.trail,
        notes,
        loud,
        warnings: judge.warnings,
    }
}

/// How a note is named in the trail: unpushed blocks say so.
fn label(notes_ref: &str, at: &str) -> String {
    if notes_ref.starts_with(LOCAL_PREFIX) {
        format!("{at} (unpushed)")
    } else {
        at.to_string()
    }
}
