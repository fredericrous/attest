//! The notes refs as origin's mirror (SPEC.md, "Which refs are read").

use std::path::Path;
use std::process::{Command, Stdio};

use crate::format::{INPUTS_REF, NOTES_REF};
use crate::git;

/// What became of one notes ref. SPEC.md, "Lookup".
///
/// `refs/notes/amont-attest[-inputs]` are ORIGIN'S MIRROR, and origin is the
/// only place an attestation can be revoked, so only a mirror that is
/// origin's ref right now — or a repository with no origin at all, which is
/// for fixtures and local use — is judged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mirror {
    /// Fetched: the mirror is origin's ref.
    Fresh,
    /// No remote named origin: the local ref is judged as it is.
    NoOrigin,
    /// Origin answered and has no such ref: the mirror was deleted.
    Deleted,
    /// As `Deleted`, but the delete failed: the stale mirror is not judged.
    Undeletable,
    /// Origin is configured and did not answer: not judged.
    Unreachable,
    /// As `Unreachable`, because the deadline cut the call off.
    TimedOut,
    /// Origin's copy was fetched but could not be made the local ref (a
    /// stale lock, say): the stale local copy is not judged.
    Unwritable,
}

impl Mirror {
    pub fn as_str(self) -> &'static str {
        match self {
            Mirror::Fresh => "fetched",
            Mirror::NoOrigin => "no-origin",
            Mirror::Deleted => "absent",
            Mirror::Undeletable => "undeletable",
            Mirror::Unreachable | Mirror::TimedOut => "unreachable",
            Mirror::Unwritable => "unwritable",
        }
    }
    pub fn judged(self) -> bool {
        matches!(self, Mirror::Fresh | Mirror::NoOrigin)
    }
}

/// Delete the mirror of `notes_ref` because origin has none.
fn drop_mirror(root: &Path, loud: &mut Vec<String>, notes_ref: &str) -> Mirror {
    let full = format!("refs/notes/{notes_ref}");
    let Some(oid) = git::stdout_in(root, &["rev-parse", "--verify", "--quiet", &full]) else {
        return Mirror::Deleted;
    };
    if git::succeeds_in(root, &["update-ref", "-d", &full, &oid]) {
        loud.push(format!(
            "origin has no {full}; deleted the local mirror (was {oid}); restore: git update-ref {full} {oid}"
        ));
        Mirror::Deleted
    } else {
        Mirror::Undeletable
    }
}

/// Where fetches land before they become the mirror: outside `refs/notes/`,
/// one directory per process id, so no notes push or pruning fetch ever
/// touches them.
pub(crate) const TMP_NS: &str = "refs/attest-tmp/";

/// Remove the throwaways of runs killed before their cleanup — only those
/// whose process is gone, so a concurrent run in the same clone keeps its
/// own. Where liveness cannot be asked, nothing is swept: a leftover outside
/// `refs/notes/` is inert.
fn sweep_tmp_refs(root: &Path) {
    let Some(refs) = git::stdout_in(root, &["for-each-ref", "--format=%(refname)", TMP_NS]) else {
        return;
    };
    let me = std::process::id().to_string();
    for r in refs.lines() {
        let Some(pid) = r
            .strip_prefix(TMP_NS)
            .and_then(|rest| rest.split('/').next())
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        if pid != me && process_gone(pid) {
            let _ = git::succeeds_in(root, &["update-ref", "-d", r]);
        }
    }
}

/// True only on a positive "no such process" (read in the C locale); any
/// other answer, or none, counts as alive, so nothing live is swept.
fn process_gone(pid: &str) -> bool {
    if !cfg!(unix) {
        return false;
    }
    Command::new("kill")
        .args(["-0", pid])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .is_ok_and(|o| {
            !o.status.success()
                && String::from_utf8_lossy(&o.stderr)
                    .to_lowercase()
                    .contains("no such process")
        })
}

/// Make the fetched copy in `tmp` the mirror of `notes_ref`, by a
/// compare-and-swap against `old` (what was there before the fetch). A kill
/// can only ever half-write the throwaway, never the mirror. When the swap
/// fails, the mirror is judged only if it now holds EXACTLY origin's copy (a
/// concurrent run got there first, or origin is unchanged under a lock).
fn adopt(root: &Path, notes_ref: &str, tmp: &str, old: Option<&str>) -> Mirror {
    let full = format!("refs/notes/{notes_ref}");
    let Some(new) = git::stdout_in(root, &["rev-parse", "--verify", "--quiet", tmp]) else {
        return Mirror::Unwritable;
    };
    if git::succeeds_in(root, &["update-ref", &full, &new, old.unwrap_or("")]) {
        return Mirror::Fresh;
    }
    match git::stdout_in(root, &["rev-parse", "--verify", "--quiet", &full]) {
        Some(now) if now == new => Mirror::Fresh,
        _ => Mirror::Unwritable,
    }
}

/// Bring both mirrors in line with origin: one fetch of both refs into
/// throwaways and, when that fails without timing out, one `ls-remote` to
/// tell "origin has no such ref" from "origin did not answer" — then, if some
/// refs exist, one more fetch of those. A silent origin costs one call (15 s
/// at most), a dead one two (30 s), the worst case three (45 s).
pub fn sync_mirrors(root: &Path, loud: &mut Vec<String>) -> (Mirror, Mirror) {
    if !git::succeeds_in(root, &["remote", "get-url", "origin"]) {
        return (Mirror::NoOrigin, Mirror::NoOrigin);
    }
    sweep_tmp_refs(root);
    let pid = std::process::id();
    let full = |r: &str| format!("refs/notes/{r}");
    let tmp = |r: &str| format!("{TMP_NS}{pid}/{r}");
    let spec = |r: &str| format!("+{}:{}", full(r), tmp(r));
    // Our own throwaways, and any lock a dead run with our pid left on them.
    // Known limits: a remove that fails leaves the fetch to fail and read as
    // unreachable (safe: nothing judged); a killed fetch's lock with no ref
    // beside it is not swept, only replaced when its pid comes round again.
    for r in [NOTES_REF, INPUTS_REF] {
        let _ = git::succeeds_in(root, &["update-ref", "-d", &tmp(r)]);
        if let Some(lock) = git::stdout_in(
            root,
            &["rev-parse", "--git-path", &format!("{}.lock", tmp(r))],
        ) {
            // `--git-path` answers relative to where git ran.
            let _ = std::fs::remove_file(root.join(lock));
        }
    }
    let old_main = git::stdout_in(
        root,
        &["rev-parse", "--verify", "--quiet", &full(NOTES_REF)],
    );
    let old_inputs = git::stdout_in(
        root,
        &["rev-parse", "--verify", "--quiet", &full(INPUTS_REF)],
    );
    let adopt_both = || {
        (
            adopt(root, NOTES_REF, &tmp(NOTES_REF), old_main.as_deref()),
            adopt(root, INPUTS_REF, &tmp(INPUTS_REF), old_inputs.as_deref()),
        )
    };
    let states = match git::remote(
        root,
        &[
            "fetch",
            "--quiet",
            "origin",
            &spec(NOTES_REF),
            &spec(INPUTS_REF),
        ],
    ) {
        git::Remote::Done(0, _) => adopt_both(),
        // Origin did not answer; asking again would only double the wait.
        git::Remote::TimedOut => (Mirror::TimedOut, Mirror::TimedOut),
        _ => match git::remote(
            root,
            &[
                "ls-remote",
                "--exit-code",
                "origin",
                &full(NOTES_REF),
                &full(INPUTS_REF),
            ],
        ) {
            git::Remote::Done(0, listing) => {
                let listed = |r: &str| {
                    let f = full(r);
                    listing
                        .lines()
                        .any(|l| l.split_whitespace().nth(1) == Some(f.as_str()))
                };
                let (has_main, has_inputs) = (listed(NOTES_REF), listed(INPUTS_REF));
                let mut want = Vec::new();
                if has_main {
                    want.push(spec(NOTES_REF));
                }
                if has_inputs {
                    want.push(spec(INPUTS_REF));
                }
                let fetched = if want.is_empty() {
                    None
                } else {
                    let mut args = vec!["fetch", "--quiet", "origin"];
                    args.extend(want.iter().map(String::as_str));
                    Some(git::remote(root, &args))
                };
                let one = |present: bool, r: &str, old: Option<&str>, loud: &mut Vec<String>| {
                    if !present {
                        return drop_mirror(root, loud, r);
                    }
                    match &fetched {
                        Some(git::Remote::Done(0, _)) => adopt(root, r, &tmp(r), old),
                        Some(git::Remote::TimedOut) => Mirror::TimedOut,
                        _ => Mirror::Unreachable,
                    }
                };
                let m = one(has_main, NOTES_REF, old_main.as_deref(), loud);
                let i = one(has_inputs, INPUTS_REF, old_inputs.as_deref(), loud);
                (m, i)
            }
            git::Remote::Done(2, _) => (
                drop_mirror(root, loud, NOTES_REF),
                drop_mirror(root, loud, INPUTS_REF),
            ),
            git::Remote::TimedOut => (Mirror::TimedOut, Mirror::TimedOut),
            _ => (Mirror::Unreachable, Mirror::Unreachable),
        },
    };
    for r in [NOTES_REF, INPUTS_REF] {
        let _ = git::succeeds_in(root, &["update-ref", "-d", &tmp(r)]);
    }
    states
}
