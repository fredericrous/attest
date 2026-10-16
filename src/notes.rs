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

// ---------------------------------------------------------------------------
// Publishing (SPEC.md, "Producing")
// ---------------------------------------------------------------------------

/// How a publish is carried out. Every producer and every signed-notes ref
/// (attestations, their inputs, provenance) goes through the same loop.
pub struct Publish<'a> {
    /// The remote to publish to.
    pub remote: &'a str,
    /// How many fetch-append-push rounds before a lost race is given up.
    pub attempts: u32,
    /// Wait between rounds, growing with the attempt (`sign.sh` in CI); a
    /// hook on the commit path does not wait.
    pub pause: bool,
    /// The committer of the notes commit, for a runner with no identity of
    /// its own; `None` uses the repository's.
    pub identity: Option<(&'a str, &'a str)>,
    /// Extra environment for the push itself (amont marks its own notes push
    /// so its pre-push hook yields).
    pub push_env: &'a [(&'a str, &'a str)],
}

/// What a publish came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Published {
    /// The remote now holds every block.
    Pushed,
    /// Every block was already there: nothing was pushed.
    AlreadyPresent,
    /// Written to the local ref only (see [`publish_local`]).
    Local,
    /// The push failed, after retries if the failure was a lost race.
    PushFailed,
    /// A note could not be written at all.
    Error,
}

/// Why a push that exited non-zero failed, read from git's stderr.
///
/// A lost race is worth one more fetch-and-try; an unreachable remote says
/// nothing about the push itself; everything else is a refusal to report
/// verbatim. An unrecognised message is `Refused`, the direction that never
/// claims a push was merely unlucky.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushFailure {
    Raced,
    Unreachable,
    Refused,
}

/// The markers behind [`PushFailure`]. Raced wins over Unreachable: a
/// message naming both is a race that happened on a reachable remote. A
/// hook's own output rides the same stream, so Unreachable is read only from
/// the lines git and ssh themselves print.
pub fn classify_push(stderr: &str) -> PushFailure {
    const RACED: [&str; 5] = [
        "non-fast-forward",
        "fetch first",
        "stale info",
        "cannot lock ref",
        "failed to lock",
    ];
    const UNREACHABLE: [&str; 5] = [
        "Could not resolve host",
        "Connection refused",
        "Connection timed out",
        "unable to access",
        "Could not read from remote repository",
    ];
    let own = |l: &&str| {
        let l = l.trim_start();
        l.starts_with("fatal:") || l.starts_with("ssh:") || l.starts_with("error:")
    };
    if RACED.iter().any(|m| stderr.contains(m)) {
        PushFailure::Raced
    } else if stderr
        .lines()
        .filter(own)
        .any(|l| UNREACHABLE.iter().any(|m| l.contains(m)))
    {
        PushFailure::Unreachable
    } else {
        PushFailure::Refused
    }
}

/// `git notes` writes a commit on the notes ref, and needs an identity.
fn notes_git(root: &Path, identity: Option<(&str, &str)>) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(root).stdin(Stdio::null());
    if let Some((name, email)) = identity {
        cmd.args([
            "-c",
            &format!("user.name={name}"),
            "-c",
            &format!("user.email={email}"),
        ]);
    }
    cmd
}

/// Append `block` to the note on `object` in `notes_ref`, unless that exact
/// block is already there. `Some(true)` when it appended, `Some(false)` when
/// the block was present, `None` when the note could not be written.
fn append(
    root: &Path,
    identity: Option<(&str, &str)>,
    notes_ref: &str,
    object: &str,
    block: &str,
) -> Option<bool> {
    let existing =
        git::stdout_in(root, &["notes", "--ref", notes_ref, "show", object]).unwrap_or_default();
    if existing.contains(block.trim_end()) {
        return Some(false);
    }
    notes_git(root, identity)
        .args(["notes", "--ref", notes_ref, "append", "-m", block, object])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?
        .success()
        .then_some(true)
}

/// Attach each `(object, block)` on the REMOTE's copy of `notes_ref` (short
/// name, under `refs/notes/`) and push. Never `notes add -f`, which erases
/// every other producer's block, and never a push of the local ref, which
/// would re-publish a block origin revoked:
///
/// 1. fetch the remote's ref into a temporary ref;
/// 2. append each block that is not already there (ed25519 signatures are
///    deterministic, so a re-run produces the same bytes);
/// 3. push the temporary ref; a lost race goes back to 1.
///
/// After a push to `origin` the local ref is set to what was published;
/// another remote's content never enters it. The temporary ref is removed on
/// every path. `log` gets one line per retry or refusal, credentials in a
/// remote URL removed.
pub fn publish(
    root: &Path,
    how: &Publish,
    notes_ref: &str,
    items: &[(String, String)],
    log: &mut Vec<String>,
) -> Published {
    let full = format!("refs/notes/{notes_ref}");
    let tref = format!("attest-publish-{}-{notes_ref}", std::process::id());
    let tfull = format!("refs/notes/{tref}");
    let mut attempt = 0;
    let outcome = loop {
        attempt += 1;
        let _ = git::succeeds_in(root, &["update-ref", "-d", &tfull]);
        // A remote with no such ref yet fails the fetch, harmlessly: append
        // then creates the note from nothing.
        let _ = git::succeeds_in(
            root,
            &["fetch", "--quiet", how.remote, &format!("+{full}:{tfull}")],
        );
        let mut appended = false;
        for (object, block) in items {
            match append(root, how.identity, &tref, object, block) {
                Some(true) => appended = true,
                Some(false) => {}
                None => return cleanup(root, &tfull, Published::Error),
            }
        }
        if !appended {
            break Published::AlreadyPresent;
        }
        let out = Command::new("git")
            .current_dir(root)
            .args(["push", "--quiet", how.remote, &format!("{tfull}:{full}")])
            .envs(how.push_env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .output();
        let Ok(out) = out else {
            log.push(format!("push of {full} could not run git"));
            break Published::PushFailed;
        };
        if out.status.success() {
            if how.remote == "origin" {
                let _ = git::succeeds_in(root, &["update-ref", &full, &tfull]);
            }
            break Published::Pushed;
        }
        let why = scrub(&String::from_utf8_lossy(&out.stderr));
        match classify_push(&why) {
            PushFailure::Raced if attempt < how.attempts => {
                log.push(format!(
                    "push of {full} rejected, another job attested this tree meanwhile; retrying"
                ));
                if how.pause {
                    std::thread::sleep(std::time::Duration::from_secs(
                        u64::from(attempt) + u64::from(std::process::id() % 3),
                    ));
                }
            }
            PushFailure::Raced => {
                log.push(format!("gave up on {full} after {attempt} attempts: {why}"));
                break Published::PushFailed;
            }
            _ => {
                log.push(format!("push of {full} refused: {why}"));
                break Published::PushFailed;
            }
        }
    };
    cleanup(root, &tfull, outcome)
}

fn cleanup(root: &Path, tfull: &str, outcome: Published) -> Published {
    let _ = git::succeeds_in(root, &["update-ref", "-d", tfull]);
    outcome
}

/// git's stderr on one line, with any `user:token@` in a remote URL removed.
pub(crate) fn scrub(stderr: &str) -> String {
    let mut out = String::new();
    for word in stderr.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        match word.find("://") {
            Some(i) => {
                let (scheme, rest) = word.split_at(i + 3);
                let host_start = match rest.find('/') {
                    Some(slash) => rest[..slash].rfind('@').map(|a| a + 1).unwrap_or(0),
                    None => rest.rfind('@').map(|a| a + 1).unwrap_or(0),
                };
                out.push_str(scheme);
                out.push_str(&rest[host_start..]);
            }
            None => out.push_str(word),
        }
    }
    out
}

/// The same, into the local `notes_ref` only, with no remote involved: what
/// `sign --no-push` writes under `refs/notes/attest-local/`.
pub fn publish_local(
    root: &Path,
    identity: Option<(&str, &str)>,
    notes_ref: &str,
    items: &[(String, String)],
) -> Published {
    let mut appended = false;
    for (object, block) in items {
        match append(root, identity, notes_ref, object, block) {
            Some(true) => appended = true,
            Some(false) => {}
            None => return Published::Error,
        }
    }
    if appended {
        Published::Local
    } else {
        Published::AlreadyPresent
    }
}
