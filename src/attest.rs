//! The verifier: given a repository and an `allowed_signers`, what does a
//! valid attestation cover for the tree checked out here?
//!
//! This is the consumer half of the format `amont` produces at pre-push. The
//! producer — key handling, signing, pushing the notes ref — deliberately
//! stays there: it needs the gate names only amont's dispatcher knows. What
//! travels is a signed document, and reading a signed document is the part
//! every other repository needs.
//!
//! `SPEC.md` is the contract; this file and `verify.sh` are two
//! implementations of it, kept honest by `tests/conformance.sh`.
//!
//! Every failure is the same failure. No note, no signers file, an unreadable
//! key, a tree that moved, a signature that does not verify — all mean "not
//! covered", and not covered means the caller runs its tests. Nothing here can
//! let an untested tree skip CI; it can only cost a redundant run. That is why
//! the whole module returns verdicts rather than errors.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::git;

/// First token of every payload. A verifier that does not recognise this
/// string must treat the note as absent: an unknown version may mean anything,
/// and "run the tests" is the only safe reading of anything.
pub const FORMAT: &str = "amont-attest-v2";

/// The notes ref, as `git notes --ref` wants it.
pub const NOTES_REF: &str = "amont-attest";

/// The `ssh-keygen -Y` namespace. Namespaces exist so a signature minted for
/// one purpose cannot be replayed for another; an `allowed_signers` entry
/// pinned to this namespace accepts nothing else.
pub const NAMESPACE: &str = "amont-attest";

/// Where a suite ran, as `<arch>-<os>`. Coarser than a target triple on
/// purpose: the libc flavour is not something `std` can answer, and the
/// question a CI matrix actually asks is "did this run on MY leg".
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// What the verifier concluded, and how it got there.
///
/// The trail is not decoration. Fail-open's worst property is silence: when a
/// skip does not happen, nothing tells you whether the attestation was absent,
/// stale, signed by another key, or minted on another platform. Carrying the
/// reasons out of the same code path that made the decision is what keeps
/// `explain` from becoming a second, drifting implementation of `covered`.
pub struct Verdict {
    pub gates: Option<Vec<String>>,
    pub trail: Vec<String>,
}

impl Verdict {
    fn nothing(reason: impl Into<String>) -> Self {
        Verdict {
            gates: None,
            trail: vec![reason.into()],
        }
    }
}

/// Record a reason, unless it repeats the one before it.
///
/// A producer writes its note to BOTH the tree and the commit, so the
/// candidate loop below meets the same note twice and would otherwise report
/// every rejection twice — which reads like two separate problems rather than
/// one seen from two angles.
fn push_reason(trail: &mut Vec<String>, reason: String) {
    if trail.last() != Some(&reason) {
        trail.push(reason);
    }
}

/// The armored signature as a file, because `ssh-keygen -Y` takes it no other
/// way. Removed on drop, so no early return below can leak it.
struct SigFile(PathBuf);

impl SigFile {
    fn new(sig: &str) -> Option<Self> {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "attest-verify-{}-{:p}.sig",
            std::process::id(),
            &sig
        ));
        // `create_new` refuses an existing path, symlink included, rather than
        // following it — the temp dir is shared with every other process.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .ok()?;
        f.write_all(sig.as_bytes()).ok()?;
        f.write_all(b"\n").ok()?;
        Some(SigFile(path))
    }
}

impl Drop for SigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// WHO signed, read from the signature and the file rather than guessed.
///
/// `ssh-keygen -Y verify` requires a principal and checks it against the
/// principal column, so a guessed one rejects a perfectly good signature —
/// quietly, since every rejection means "run the tests". The templates this
/// replaced hardcoded `-I you@example.com`; the first release guessed the
/// file's first entry, which silently uncovered every other signer on a team.
/// `find-principals` answers from the key that actually signed.
fn find_principal(sig_file: &Path, allowed_signers: &Path) -> Option<String> {
    let out = Command::new("ssh-keygen")
        .args(["-Y", "find-principals", "-s"])
        .arg(sig_file)
        .arg("-f")
        .arg(allowed_signers)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// `ssh-keygen -Y verify` over the exact signed bytes, as `principal` — or, when
/// none is given, as whoever the signature says. `Ok` carries the identity the
/// signature verified as; `Err` carries the reason it did not.
pub fn verify(
    payload: &str,
    sig: &str,
    allowed_signers: &Path,
    principal: Option<&str>,
) -> Result<String, String> {
    use std::io::Write;
    let Some(sig_file) = SigFile::new(sig) else {
        return Err("cannot create a temporary file for the signature".into());
    };
    let signer = match principal {
        Some(p) => p.to_string(),
        None => find_principal(&sig_file.0, allowed_signers).ok_or_else(|| {
            format!(
                "signature was not made by any key in {}",
                allowed_signers.display()
            )
        })?,
    };
    let ok = (|| {
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-n", NAMESPACE, "-I", &signer, "-f"])
            .arg(allowed_signers)
            .arg("-s")
            .arg(&sig_file.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(payload.as_bytes()).ok()?;
        child.wait().ok().map(|s| s.success())
    })()
    .unwrap_or(false);
    if ok {
        Ok(signer)
    } else {
        Err(format!(
            "signature does not verify as {signer} against {}",
            allowed_signers.display()
        ))
    }
}

/// Fetch the notes ref from origin, and say so when that fails for a reason
/// other than "origin has no such ref".
///
/// A repository never pushed with attest enabled has no such ref, and that is
/// not an error. A fetch that fails for any OTHER reason — no credentials
/// because the checkout step set `persist-credentials: false`, a remote not
/// named origin, no network — is the worst shape a fail-open can take: nothing
/// covered, forever, with CI green and a log that reads as "no attestation".
fn fetch_notes(trail: &mut Vec<String>) {
    let refspec = format!("+refs/notes/{NOTES_REF}:refs/notes/{NOTES_REF}");
    if git::succeeds(&["fetch", "origin", &refspec]) {
        return;
    }
    // ls-remote exits 2 when the ref simply is not there; anything else is the
    // remote being unreachable or refusing us.
    let remote_ref = format!("refs/notes/{NOTES_REF}");
    if git::exit_code(&["ls-remote", "--exit-code", "origin", &remote_ref]) == Some(2) {
        return;
    }
    if git::succeeds(&["rev-parse", "--verify", "--quiet", &remote_ref]) {
        return;
    }
    push_reason(
        trail,
        format!(
            "cannot fetch refs/notes/{NOTES_REF} from origin and no local copy exists \
             (no credentials on the checkout? remote not named origin?)"
        ),
    );
}

/// Where a repository keeps its `allowed_signers` when the caller does not say.
///
/// Resolved from the REPOSITORY ROOT, not the working directory. A workflow
/// that sets `working-directory` — a monorepo matrix running inside
/// `packages/<x>` — puts the step in a subdirectory, where a relative
/// `.github/allowed_signers` does not exist. The verifier would then find no
/// signers, cover nothing, and fail open FOREVER: the suite still runs, CI
/// still passes, and nothing anywhere says the gate is dead.
pub fn default_signers() -> Option<PathBuf> {
    let root = git::stdout(&["rev-parse", "--show-toplevel"]).map(PathBuf::from);
    [".forgejo/allowed_signers", ".github/allowed_signers"]
        .into_iter()
        .map(|rel| match &root {
            Some(root) => root.join(rel),
            None => PathBuf::from(rel),
        })
        .find(|p| p.exists())
}

/// A caller-supplied signers path, resolved the way the default is: relative
/// to the REPOSITORY ROOT, not the working directory. Absolute paths pass
/// through.
pub fn resolve_signers(given: &str) -> PathBuf {
    let path = PathBuf::from(given);
    if path.is_absolute() {
        return path;
    }
    match git::stdout(&["rev-parse", "--show-toplevel"]) {
        Some(root) => PathBuf::from(root).join(path),
        None => path,
    }
}

/// A note body back into the exact bytes that were signed, plus the signature.
///
/// The blank-line split ate the payload's trailing newline; it is part of the
/// signed bytes, so it goes back.
pub fn split_note(body: &str) -> Option<(String, String)> {
    let (payload, sig) = body.split_once("\n\n")?;
    if !sig.starts_with("-----BEGIN SSH SIGNATURE-----") {
        return None;
    }
    Some((format!("{payload}\n"), sig.to_string()))
}

/// Read a payload field BY PREFIX, never by line position: the payload has
/// grown a line once already (v1 -> v2 added `platform`), and a positional
/// reader silently mis-assigns every field after an insertion rather than
/// failing. First match wins, so a second `gates` line cannot smuggle a value
/// past the caller.
fn field<'a>(payload: &'a str, name: &str) -> Option<&'a str> {
    payload
        .lines()
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
        .map(str::trim)
}

/// The whole decision, trail included.
///
/// `principal` of `None` means "whoever the signature says, if that key is in
/// the file"; `Some` narrows it to one identity. `require_platform` of `None`
/// means the caller has stated this suite's result does not depend on where
/// it ran.
pub fn evaluate(
    signers: &Path,
    principal: Option<&str>,
    require_platform: Option<&str>,
) -> Verdict {
    let mut trail = Vec::new();

    if !signers.is_file() {
        return Verdict::nothing(format!("{} does not exist", signers.display()));
    }

    fetch_notes(&mut trail);

    let Some(head_tree) = git::stdout(&["rev-parse", "HEAD^{tree}"]) else {
        push_reason(
            &mut trail,
            "cannot resolve HEAD^{tree} — not a git repository?".into(),
        );
        return Verdict { gates: None, trail };
    };

    // The TREE first: it is what the signature covers, so it is the only key
    // that survives a squash-merge, an amend or a rebase. HEAD and HEAD^2
    // follow for notes written by a producer that keyed by commit only —
    // HEAD^2 because a PR checkout is a merge commit git made a moment ago,
    // whose second parent is the pushed tip that carries the note.
    let mut tried = false;
    for candidate in [head_tree.as_str(), "HEAD", "HEAD^2"] {
        let Some(object) = git::stdout(&["rev-parse", "--verify", "--quiet", candidate]) else {
            continue;
        };
        let Some(body) = git::stdout(&["notes", "--ref", NOTES_REF, "show", &object]) else {
            continue;
        };
        tried = true;
        let Some((payload, sig)) = split_note(&body) else {
            push_reason(
                &mut trail,
                format!("note on {candidate} carries no signature block"),
            );
            continue;
        };
        if payload.lines().next() != Some(FORMAT) {
            push_reason(
                &mut trail,
                format!("note on {candidate} is not {FORMAT} — a newer producer wrote it"),
            );
            continue;
        }
        let (Some(tree), Some(gates), Some(ran_on)) = (
            field(&payload, "tree"),
            field(&payload, "gates"),
            field(&payload, "platform"),
        ) else {
            push_reason(
                &mut trail,
                format!("note on {candidate} is missing a required field"),
            );
            continue;
        };
        if tree != head_tree {
            push_reason(
                &mut trail,
                format!("attested tree {tree} is not the checked-out tree {head_tree}"),
            );
            continue;
        }
        if gates.is_empty() {
            push_reason(
                &mut trail,
                "attestation lists no gates — a signed way of saying nothing".into(),
            );
            continue;
        }
        // A pass is a pass ON SOMETHING: a macOS `cargo test` is no evidence
        // about the Windows leg of a matrix.
        if let Some(want) = require_platform {
            if want != ran_on {
                push_reason(
                    &mut trail,
                    format!("attested on {ran_on}, this leg is {want}"),
                );
                continue;
            }
        }
        match verify(&payload, &sig, signers, principal) {
            Ok(signer) => {
                push_reason(&mut trail, format!("covered by {signer}: {gates}"));
                return Verdict {
                    gates: Some(gates.split_whitespace().map(str::to_string).collect()),
                    trail,
                };
            }
            Err(why) => push_reason(&mut trail, format!("note on {candidate}: {why}")),
        }
    }

    if !tried {
        push_reason(
            &mut trail,
            format!("no attestation found for tree {head_tree}"),
        );
    }
    Verdict { gates: None, trail }
}
