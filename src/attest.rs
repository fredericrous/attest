//! The verifier: given a repository and an `allowed_signers`, what does a
//! valid attestation cover for the tree checked out here?
//!
//! This is the consumer half of the format `amont` produces at pre-push and
//! `sign/sign.sh` produces in CI. What travels is a signed document, and
//! reading a signed document is the part every other repository needs.
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

/// How many blocks of one note are read. Every block costs two `ssh-keygen`
/// runs, and the notes ref is writable by anyone with push access.
pub const MAX_BLOCKS: usize = 32;

const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

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
    /// Covered gate names, first-appearance order, no duplicates. Empty means
    /// nothing is covered.
    pub gates: Vec<String>,
    pub trail: Vec<String>,
}

impl Verdict {
    fn nothing(reason: impl Into<String>) -> Self {
        Verdict {
            gates: Vec::new(),
            trail: vec![reason.into()],
        }
    }
}

/// Record a reason, unless it repeats the one before it.
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
        if !sig.ends_with('\n') {
            f.write_all(b"\n").ok()?;
        }
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

/// One signed statement out of a note: the exact bytes that were signed
/// (trailing newline included) and the armored signature over them.
#[derive(Debug, PartialEq)]
pub struct Block {
    pub payload: String,
    pub signature: String,
}

/// A note into its blocks. Since 1.2.0 a note may hold several — a laptop's
/// and a CI job's, each on its own platform — separated by blank lines, which
/// is exactly what `git notes append` produces.
///
/// The grammar (SPEC.md): skip blank lines; a payload runs to the first blank
/// line; skip blank lines; the next line must be the BEGIN marker, or parsing
/// STOPS and what was collected so far stands; the signature runs to the END
/// marker, and end of input closes an open one. Lines are split on LF only, so
/// a `\r` is content: a CRLF note has no blank line, yields no block, and
/// covers nothing — the same answer `verify.sh` gives it.
///
/// Returns the blocks and whether more than `MAX_BLOCKS` were present.
pub fn split_blocks(body: &str) -> (Vec<Block>, bool) {
    enum State {
        Between,
        Payload,
        WaitingForSignature,
        Signature,
    }
    let mut blocks = Vec::new();
    let mut state = State::Between;
    let mut payload = String::new();
    let mut signature = String::new();
    let close = |blocks: &mut Vec<Block>, payload: &str, signature: &str| -> bool {
        if blocks.len() == MAX_BLOCKS {
            return true;
        }
        blocks.push(Block {
            payload: payload.to_string(),
            signature: signature.to_string(),
        });
        false
    };
    for line in body.split('\n') {
        match state {
            State::Between => {
                if line.is_empty() {
                    continue;
                }
                payload.clear();
                payload.push_str(line);
                payload.push('\n');
                state = State::Payload;
            }
            State::Payload => {
                if line.is_empty() {
                    state = State::WaitingForSignature;
                } else {
                    payload.push_str(line);
                    payload.push('\n');
                }
            }
            State::WaitingForSignature => {
                if line.is_empty() {
                    continue;
                }
                if line != BEGIN {
                    return (blocks, false);
                }
                signature.clear();
                signature.push_str(line);
                signature.push('\n');
                state = State::Signature;
            }
            State::Signature => {
                signature.push_str(line);
                signature.push('\n');
                if line == END {
                    if close(&mut blocks, &payload, &signature) {
                        return (blocks, true);
                    }
                    state = State::Between;
                }
            }
        }
    }
    if let State::Signature = state {
        if close(&mut blocks, &payload, &signature) {
            return (blocks, true);
        }
    }
    (blocks, false)
}

/// The first block of a note, for tests that only want one.
#[cfg(test)]
pub fn split_note(body: &str) -> Option<(String, String)> {
    split_blocks(body)
        .0
        .into_iter()
        .next()
        .map(|b| (b.payload, b.signature))
}

/// Does an attestation minted on `ran_on` satisfy what the caller asked for?
///
/// `None` is "anywhere". A value with a dash is an exact `<arch>-<os>`. A value
/// without one is an OS alone, compared to the part after the LAST dash of
/// `ran_on` — never as a substring, so `inux` matches nothing and `x86_64`
/// does not match `x86_64-linux`.
pub fn platform_matches(want: Option<&str>, ran_on: &str) -> bool {
    match want {
        None => true,
        Some(want) if want.contains('-') => want == ran_on,
        Some(want) => ran_on.rsplit_once('-').is_some_and(|(_, os)| os == want),
    }
}

/// Add names not already present, keeping first-appearance order.
fn union<'a>(into: &mut Vec<String>, names: impl Iterator<Item = &'a str>) {
    for name in names {
        if !into.iter().any(|g| g == name) {
            into.push(name.to_string());
        }
    }
}

/// Read a payload field BY PREFIX, never by line position: the payload has
/// grown a line once already (v1 -> v2 added `platform`), and a positional
/// reader silently mis-assigns every field after an insertion rather than
/// failing. First match wins, so a second `gates` line cannot smuggle a value
/// past the caller.
///
/// Byte-strict, like `verify.sh`: lines are split on LF only and nothing is
/// trimmed but the separating spaces, so a `\r` or a trailing space is part
/// of the value and a `tree` line that carries one matches nothing.
fn field<'a>(payload: &'a str, name: &str) -> Option<&'a str> {
    payload
        .split('\n')
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
        .map(|v| v.trim_start_matches(' '))
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
    signers: &Path,
    principal: Option<&str>,
    require_platform: Option<&str>,
    anywhere: &[String],
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
        return Verdict {
            gates: Vec::new(),
            trail,
        };
    };

    let mut covered: Vec<String> = Vec::new();
    // A producer writes its note to BOTH the tree and the commit, so the
    // candidate loop meets the same note twice; it is judged once, by oid.
    let mut seen: Vec<String> = Vec::new();
    let mut tried = false;

    // The TREE first: it is what the signature covers, so it is the only key
    // that survives a squash-merge, an amend or a rebase. HEAD and HEAD^2
    // follow for notes written by a producer that keyed by commit only —
    // HEAD^2 because a PR checkout is a merge commit git made a moment ago,
    // whose second parent is the pushed tip that carries the note.
    for candidate in [head_tree.as_str(), "HEAD", "HEAD^2"] {
        let Some(object) = git::stdout(&["rev-parse", "--verify", "--quiet", candidate]) else {
            continue;
        };
        let Some(listing) = git::stdout(&["notes", "--ref", NOTES_REF, "list", &object]) else {
            continue;
        };
        let note_oid = listing.split_whitespace().next().unwrap_or("").to_string();
        if seen.contains(&note_oid) {
            continue;
        }
        seen.push(note_oid);
        let Some(body) = git::stdout(&["notes", "--ref", NOTES_REF, "show", &object]) else {
            continue;
        };
        tried = true;

        let (blocks, truncated) = split_blocks(&body);
        if truncated {
            push_reason(
                &mut trail,
                format!(
                    "note on {candidate} has more than {MAX_BLOCKS} blocks; the rest were ignored"
                ),
            );
        }
        if blocks.is_empty() {
            push_reason(
                &mut trail,
                format!("note on {candidate} carries no signature block"),
            );
            continue;
        }
        let several = blocks.len() > 1;
        for (i, block) in blocks.iter().enumerate() {
            let at = if several {
                format!("{candidate} block {}", i + 1)
            } else {
                candidate.to_string()
            };
            let payload = &block.payload;
            if payload.split('\n').next() != Some(FORMAT) {
                push_reason(
                    &mut trail,
                    format!("note on {at} is not {FORMAT} — a newer producer wrote it"),
                );
                continue;
            }
            let (Some(tree), Some(gates), Some(ran_on)) = (
                field(payload, "tree"),
                field(payload, "gates"),
                field(payload, "platform"),
            ) else {
                push_reason(
                    &mut trail,
                    format!("note on {at} is missing a required field"),
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
            // Signature BEFORE platform: the `anywhere` list may only admit
            // gates from a block that actually verified.
            let signer = match verify(payload, &block.signature, signers, principal) {
                Ok(signer) => signer,
                Err(why) => {
                    push_reason(&mut trail, format!("note on {at}: {why}"));
                    continue;
                }
            };
            // A pass is a pass ON SOMETHING: a macOS `cargo test` is no
            // evidence about the Windows leg of a matrix.
            if platform_matches(require_platform, ran_on) {
                union(&mut covered, gates.split_whitespace());
                push_reason(
                    &mut trail,
                    format!("covered by {signer} on {ran_on}: {gates}"),
                );
                continue;
            }
            let accepted: Vec<&str> = gates
                .split_whitespace()
                .filter(|g| anywhere.iter().any(|a| a == g))
                .collect();
            union(&mut covered, accepted.iter().copied());
            let want = require_platform.unwrap_or("any");
            let mut reason = format!("attested on {ran_on} by {signer}, this leg is {want}");
            if !accepted.is_empty() {
                reason.push_str("; accepted anywhere: ");
                reason.push_str(&accepted.join(" "));
            }
            push_reason(&mut trail, reason);
        }
    }

    if !tried {
        push_reason(
            &mut trail,
            format!("no attestation found for tree {head_tree}"),
        );
    }
    Verdict {
        gates: covered,
        trail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----";

    fn block(n: u32) -> String {
        format!("amont-attest-v2\ntree t{n}\ngates g{n}\nplatform p{n}\n\n{SIG}")
    }

    #[test]
    fn platform_matching_is_exact_or_os_only_never_a_substring() {
        assert!(platform_matches(None, "s390x-aix"));
        assert!(platform_matches(Some("x86_64-linux"), "x86_64-linux"));
        assert!(!platform_matches(Some("x86_64-linux"), "aarch64-linux"));
        assert!(platform_matches(Some("linux"), "x86_64-linux"));
        assert!(platform_matches(Some("linux"), "aarch64-linux"));
        assert!(!platform_matches(Some("inux"), "x86_64-linux"));
        assert!(!platform_matches(Some("x86_64"), "x86_64-linux"));
        assert!(!platform_matches(Some("linux"), "linux"));
    }

    #[test]
    fn one_block_restores_the_signed_trailing_newline() {
        let (blocks, truncated) = split_blocks(&block(1));
        assert!(!truncated);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0].payload,
            "amont-attest-v2\ntree t1\ngates g1\nplatform p1\n"
        );
        assert_eq!(blocks[0].signature, format!("{SIG}\n"));
    }

    #[test]
    fn two_blocks_as_git_notes_append_writes_them() {
        let body = format!("{}\n\n{}", block(1), block(2));
        let (blocks, _) = split_blocks(&body);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[1].payload.starts_with("amont-attest-v2\ntree t2\n"));
        // extra blank lines between blocks are tolerated
        let body = format!("{}\n\n\n\n{}\n", block(1), block(2));
        assert_eq!(split_blocks(&body).0.len(), 2);
    }

    #[test]
    fn end_of_input_closes_an_open_signature() {
        let body = "amont-attest-v2\ntree abc\n\n-----BEGIN SSH SIGNATURE-----\nx";
        let (payload, sig) = split_note(body).unwrap();
        assert_eq!(payload, "amont-attest-v2\ntree abc\n");
        assert_eq!(sig, "-----BEGIN SSH SIGNATURE-----\nx\n");
    }

    #[test]
    fn framing_errors_stop_parsing_and_keep_what_came_before() {
        assert!(split_note("no blank line here").is_none());
        assert!(split_note("payload\n\nnot a signature").is_none());
        // a second block whose signature never begins: block 1 stands alone
        let body = format!("{}\n\npayload2\n\nnot a signature", block(1));
        assert_eq!(split_blocks(&body).0.len(), 1);
        // a block that never ends swallows the valid one after it
        let body = format!("p\n\n-----BEGIN SSH SIGNATURE-----\nx\n\n{}", block(2));
        let (blocks, _) = split_blocks(&body);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].signature.contains("tree t2"));
        // garbage after the last block is ignored
        let body = format!("{}\n\ngarbage", block(1));
        assert_eq!(split_blocks(&body).0.len(), 1);
    }

    #[test]
    fn a_crlf_note_has_no_blank_line_and_therefore_no_block() {
        let body = block(1).replace('\n', "\r\n");
        assert!(split_blocks(&body).0.is_empty());
    }

    #[test]
    fn at_most_max_blocks_are_read() {
        let body: Vec<String> = (0..40).map(block).collect();
        let (blocks, truncated) = split_blocks(&body.join("\n\n"));
        assert_eq!(blocks.len(), MAX_BLOCKS);
        assert!(truncated);
        let body: Vec<String> = (0..MAX_BLOCKS as u32).map(block).collect();
        let (blocks, truncated) = split_blocks(&body.join("\n\n"));
        assert_eq!(blocks.len(), MAX_BLOCKS);
        assert!(!truncated);
    }

    #[test]
    fn union_keeps_first_appearance_order_without_duplicates() {
        let mut v = vec!["a".to_string()];
        union(&mut v, "b a c b".split_whitespace());
        assert_eq!(v, ["a", "b", "c"]);
    }
}
