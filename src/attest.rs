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

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::git;

/// First token of every payload. A verifier that does not recognise this
/// string must treat the note as absent: an unknown version may mean anything,
/// and "run the tests" is the only safe reading of anything.
pub const FORMAT: &str = "amont-attest-v2";

/// The notes ref, as `git notes --ref` wants it.
pub const NOTES_REF: &str = "amont-attest";

/// The second notes ref, keyed by input fingerprint rather than by object.
/// Every key there is a synthetic oid that is not an object, which is why it
/// is a separate ref: `git notes prune` on it would drop everything, and the
/// main ref keeps its 1.x invariant that every key is real.
pub const INPUTS_REF: &str = "amont-attest-inputs";

/// The `ssh-keygen -Y` namespace. Namespaces exist so a signature minted for
/// one purpose cannot be replayed for another; an `allowed_signers` entry
/// pinned to this namespace accepts nothing else.
pub const NAMESPACE: &str = "amont-attest";

/// How many blocks of one note are read. Every block costs two `ssh-keygen`
/// runs, and the notes ref is writable by anyone with push access.
pub const MAX_BLOCKS: usize = 32;

/// How many signatures one invocation verifies, over every candidate. A
/// verification is one call of [`verify`]; blocks the cheap checks reject and
/// blocks already judged do not count.
pub const MAX_VERIFICATIONS: usize = 64;

/// Where a repository declares which paths each gate reads, in order of
/// precedence. Both are always part of every fingerprint's listing.
pub const SPEC_PATHS: [&str; 2] = [".forgejo/attest-inputs", ".github/attest-inputs"];
pub const MAX_SPEC_BYTES: usize = 65536;
pub const MAX_SPEC_GATES: usize = 64;
pub const MAX_SPEC_PATHS: usize = 64;

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

/// Fetch a notes ref from origin, and say so when that fails for a reason
/// other than "origin has no such ref".
///
/// A repository never pushed with attest enabled has no such ref, and that is
/// not an error. A fetch that fails for any OTHER reason — no credentials
/// because the checkout step set `persist-credentials: false`, a remote not
/// named origin, no network — is the worst shape a fail-open can take: nothing
/// covered, forever, with CI green and a log that reads as "no attestation".
fn fetch_notes(trail: &mut Vec<String>, notes_ref: &str) {
    let refspec = format!("+refs/notes/{notes_ref}:refs/notes/{notes_ref}");
    if git::succeeds(&["fetch", "origin", &refspec]) {
        return;
    }
    // ls-remote exits 2 when the ref simply is not there; anything else is the
    // remote being unreachable or refusing us.
    let remote_ref = format!("refs/notes/{notes_ref}");
    if git::exit_code(&["ls-remote", "--exit-code", "origin", &remote_ref]) == Some(2) {
        return;
    }
    if git::succeeds(&["rev-parse", "--verify", "--quiet", &remote_ref]) {
        return;
    }
    push_reason(
        trail,
        format!(
            "cannot fetch refs/notes/{notes_ref} from origin and no local copy exists \
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
/// marker, and end of input closes an open one. Lines are split on LF only;
/// `evaluate` rejects any note containing a carriage return before this runs.
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

// ---------------------------------------------------------------------------
// Input fingerprints (1.3.0)
// ---------------------------------------------------------------------------

/// The committed declaration of which paths each gate reads.
#[derive(Debug, PartialEq)]
pub struct Spec {
    pub gates: Vec<(String, Vec<String>)>,
}

impl Spec {
    pub fn paths_of(&self, gate: &str) -> Option<&[String]> {
        self.gates
            .iter()
            .find(|(g, _)| g == gate)
            .map(|(_, p)| p.as_slice())
    }
}

/// A gate name as the spec allows it: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
fn valid_gate(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    name.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

/// Why a path token is not a literal, root-relative file or directory —
/// `None` when it is. `git ls-tree` does not glob, so a wildcard would match
/// nothing and silently fingerprint nothing; every other shape here is a
/// path git would interpret rather than look up.
fn path_error(tok: &str) -> Option<String> {
    let bad = |why: &str| Some(format!("path `{tok}` {why}"));
    if tok.starts_with(':') {
        return bad("starts with `:` (pathspec magic is not allowed)");
    }
    if tok.starts_with('/') {
        return bad("is absolute; paths are relative to the repository root");
    }
    if tok.starts_with("./") || tok.starts_with("../") {
        return bad("starts with `./` or `../`");
    }
    if tok.ends_with('/') {
        return bad("ends with `/`; name the directory without it");
    }
    if let Some(c) = tok
        .chars()
        .find(|c| matches!(c, '*' | '?' | '[' | ']' | '\\'))
    {
        return bad(&format!(
            "contains `{c}`; git ls-tree does not glob, only literal paths are accepted"
        ));
    }
    if tok
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return bad("has an empty, `.` or `..` component");
    }
    None
}

/// The spec grammar, byte-strict. Every violation is a distinct reason, and
/// any violation invalidates the WHOLE spec: a line that silently dropped out
/// would be one the author believes is protecting something.
pub fn parse_spec(bytes: &[u8]) -> Result<Spec, String> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(format!("is larger than {MAX_SPEC_BYTES} bytes"));
    }
    if let Some(b) = bytes
        .iter()
        .find(|&&b| !(b == b' ' || b == b'\t' || b == b'\n' || (0x21..=0x7e).contains(&b)))
    {
        return Err(format!(
            "contains byte 0x{b:02x}; only printable ASCII, space, tab and LF are allowed"
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let mut gates: Vec<(String, Vec<String>)> = Vec::new();
    for (n, line) in text.split('\n').enumerate() {
        let n = n + 1;
        let mut toks = line.split([' ', '\t']).filter(|t| !t.is_empty());
        let Some(gate) = toks.next() else { continue };
        if gate.starts_with('#') {
            continue;
        }
        if !valid_gate(gate) {
            return Err(format!("line {n}: gate name `{gate}` is not [A-Za-z0-9][A-Za-z0-9._-]* of at most 64 characters"));
        }
        if gates.iter().any(|(g, _)| g == gate) {
            return Err(format!("line {n}: gate `{gate}` is declared twice"));
        }
        let paths: Vec<String> = toks.map(String::from).collect();
        if paths.is_empty() {
            return Err(format!("line {n}: gate `{gate}` declares no paths"));
        }
        if paths.len() > MAX_SPEC_PATHS {
            return Err(format!(
                "line {n}: gate `{gate}` declares more than {MAX_SPEC_PATHS} paths"
            ));
        }
        for p in &paths {
            if let Some(why) = path_error(p) {
                return Err(format!("line {n}: {why}"));
            }
        }
        gates.push((gate.to_string(), paths));
        if gates.len() > MAX_SPEC_GATES {
            return Err(format!("declares more than {MAX_SPEC_GATES} gates"));
        }
    }
    Ok(Spec { gates })
}

/// The paths every fingerprint lists besides the gate's own: both spec
/// locations (so adding, removing or editing either invalidates),
/// `.gitmodules`, and `.gitattributes` at the root and at every ancestor
/// directory of every token — they change the bytes a checkout yields without
/// changing any listed blob. Deduplicated; order does not affect the value.
pub fn implicit_inputs(tokens: &[String]) -> Vec<String> {
    let mut attrs: Vec<String> = vec![".gitattributes".to_string()];
    for t in tokens {
        let comps: Vec<&str> = t.split('/').collect();
        let mut prefix = String::new();
        for c in &comps[..comps.len().saturating_sub(1)] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(c);
            attrs.push(format!("{prefix}/.gitattributes"));
        }
    }
    attrs.sort();
    attrs.dedup();
    let mut out: Vec<String> = SPEC_PATHS.iter().map(|s| s.to_string()).collect();
    out.push(".gitmodules".to_string());
    out.extend(attrs);
    out
}

/// A 40- or 64-hex object id, as `hash-object` prints one.
fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The fingerprint of `gate` on `tree`, or `None` when the gate has none
/// there: not in the spec, a token that does not resolve, git failing at any
/// step, or an empty listing (which would hash to the same value on every
/// tree and is refused as an assertion).
pub fn fingerprint(root: &Path, tree: &str, spec: &Spec, gate: &str) -> Option<String> {
    let paths = spec.paths_of(gate)?;
    // Every token must resolve — one `cat-file --batch-check` for all of
    // them, never one process per token.
    let names: String = paths.iter().map(|p| format!("{tree}:{p}\n")).collect();
    let answers =
        git::stdout_with_input_in(root, &["cat-file", "--batch-check"], names.as_bytes())?;
    if answers.lines().count() != paths.len() || answers.lines().any(|l| l.ends_with(" missing")) {
        return None;
    }
    let mut args: Vec<String> = vec![
        "ls-tree".into(),
        "-r".into(),
        "-z".into(),
        "--full-tree".into(),
        tree.to_string(),
        "--".into(),
    ];
    args.extend(implicit_inputs(paths));
    args.extend(paths.iter().cloned());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let listing = git::stdout_bytes_in(root, &argv)?;
    if listing.is_empty() {
        return None;
    }
    git::stdout_with_input_in(root, &["hash-object", "--stdin"], &listing).filter(|s| is_oid(s))
}

/// The bytes a fingerprint key is hashed from.
pub fn key_preimage(gate: &str, fp: &str) -> String {
    format!("amont-attest-input {gate} {fp}\n")
}

/// The synthetic note key for (gate, fingerprint): an oid that is not an
/// object, which `git notes` accepts as a key all the same.
pub fn key(root: &Path, gate: &str, fp: &str) -> Option<String> {
    git::stdout_with_input_in(
        root,
        &["hash-object", "--stdin"],
        key_preimage(gate, fp).as_bytes(),
    )
    .filter(|s| is_oid(s))
}

/// The fingerprint a block claims for `gate`: an `input <gate> <fp>` line of
/// exactly three blank-separated fields, first occurrence wins. Byte-strict
/// like [`field`]; a fourth field or a malformed oid is not a claim.
pub fn input_fp<'a>(payload: &'a str, gate: &str) -> Option<&'a str> {
    payload.split('\n').find_map(|line| {
        let f: Vec<&str> = line.split([' ', '\t']).filter(|t| !t.is_empty()).collect();
        (f.len() == 3 && f[0] == "input" && f[1] == gate && is_oid(f[2])).then(|| f[2])
    })
}

/// The uniform rule, as a pure function: a gate of a verified block is
/// covered if the block's tree IS the checked-out tree, or if the block claims
/// a fingerprint for that gate equal to the one computed here.
pub fn covered_gates<'a>(
    tree_matches: bool,
    gates: &'a str,
    fp_of_block: impl Fn(&str) -> Option<&'a str>,
    mut fp_head: impl FnMut(&str) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for g in gates.split_whitespace() {
        let ok = tree_matches
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
            .and_then(|s| fingerprint(&self.root, &self.head_tree, s, gate));
        self.fp_memo.push((gate.to_string(), fp.clone()));
        fp
    }

    /// Judge every block of the note on `object` in `notes_ref`.
    fn judge(&mut self, notes_ref: &str, object: &str, at: &str) {
        if self.exhausted {
            return;
        }
        let Some(listing) = git::stdout(&["notes", "--ref", notes_ref, "list", object]) else {
            return;
        };
        let note_oid = listing.split_whitespace().next().unwrap_or("").to_string();
        if self.seen_notes.contains(&note_oid) {
            return;
        }
        self.seen_notes.push(note_oid);
        let Some(body) = git::stdout(&["notes", "--ref", notes_ref, "show", object]) else {
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
            let signer = match verify(payload, &block.signature, self.signers, self.principal) {
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
            let kept = covered_gates(
                tree_matches,
                gates,
                |g| input_fp(payload, g),
                |g| self.fp_head(g),
            );
            if kept.is_empty() {
                push_reason(
                    &mut self.trail,
                    format!(
                        "attested tree {tree} is not the checked-out tree {} and no input fingerprint of {where_} matches",
                        self.head_tree
                    ),
                );
                continue;
            }
            let how = if tree_matches {
                ""
            } else {
                " (by input fingerprint)"
            };
            let kept_str = kept.join(" ");
            // A pass is a pass ON SOMETHING: a macOS `cargo test` is no
            // evidence about the Windows leg of a matrix.
            if platform_matches(self.require_platform, ran_on) {
                union(&mut self.covered, kept.iter().map(String::as_str));
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
/// Read from the TREE, never the working copy: the bytes hashed into every
/// fingerprint and the bytes parsed here are then the same object.
fn load_spec(root: &Path, head_tree: &str, trail: &mut Vec<String>) -> Option<Spec> {
    let present: Vec<&str> = SPEC_PATHS
        .iter()
        .copied()
        .filter(|p| git::succeeds_in(root, &["cat-file", "-e", &format!("{head_tree}:{p}")]))
        .collect();
    let path = match present.as_slice() {
        [] => return None,
        [one] => *one,
        _ => {
            push_reason(
                trail,
                format!(
                    "both {} and {} exist; input fingerprints disabled",
                    SPEC_PATHS[0], SPEC_PATHS[1]
                ),
            );
            return None;
        }
    };
    let Some(bytes) =
        git::stdout_bytes_in(root, &["cat-file", "blob", &format!("{head_tree}:{path}")])
    else {
        push_reason(
            trail,
            format!("cannot read {path} from HEAD's tree; input fingerprints disabled"),
        );
        return None;
    };
    match parse_spec(&bytes) {
        Ok(spec) => Some(spec),
        Err(why) => {
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
    signers: &Path,
    principal: Option<&str>,
    require_platform: Option<&str>,
    anywhere: &[String],
) -> Verdict {
    let mut trail = Vec::new();

    if !signers.is_file() {
        return Verdict::nothing(format!("{} does not exist", signers.display()));
    }

    fetch_notes(&mut trail, NOTES_REF);
    fetch_notes(&mut trail, INPUTS_REF);

    let Some(root) = git::stdout(&["rev-parse", "--show-toplevel"]).map(PathBuf::from) else {
        push_reason(&mut trail, "not a git repository".into());
        return Verdict {
            gates: Vec::new(),
            trail,
        };
    };
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
        let Some(object) = git::stdout(&["rev-parse", "--verify", "--quiet", candidate]) else {
            continue;
        };
        judge.judge(NOTES_REF, &object, candidate);
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
        let Some(k) = key(&judge.root, &gate, &fp) else {
            continue;
        };
        let at = format!("input {gate} {}", &fp[..12]);
        judge.judge(INPUTS_REF, &k, &at);
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

    // --- input fingerprints -------------------------------------------------

    fn spec_of(s: &str) -> Result<Spec, String> {
        parse_spec(s.as_bytes())
    }

    #[test]
    fn spec_parses_gates_comments_tabs_and_a_missing_final_newline() {
        let s =
            spec_of("# a comment\n\nci-fmt\tsrc  Cargo.toml\n  # indented comment\ntest src tests")
                .unwrap();
        assert_eq!(
            s.gates,
            vec![
                (
                    "ci-fmt".to_string(),
                    vec!["src".to_string(), "Cargo.toml".to_string()]
                ),
                (
                    "test".to_string(),
                    vec!["src".to_string(), "tests".to_string()]
                ),
            ]
        );
        assert_eq!(s.paths_of("test").unwrap().len(), 2);
        assert!(s.paths_of("nope").is_none());
    }

    #[test]
    fn spec_rejects_every_byte_outside_printable_ascii_first() {
        for bad in [
            b"g src\r\n".as_slice(),
            b"g src\0",
            b"g sr\xc3\xa9",
            b"g\xc2\xa0src",
            b"g s\x01rc",
        ] {
            assert!(parse_spec(bad).unwrap_err().contains("byte 0x"), "{bad:?}");
        }
        assert!(parse_spec(&vec![b'\n'; MAX_SPEC_BYTES + 1])
            .unwrap_err()
            .contains("larger"));
        // exactly the limit, mostly newlines, is fine
        let mut ok = b"g src".to_vec();
        ok.resize(MAX_SPEC_BYTES, b'\n');
        assert!(parse_spec(&ok).is_ok());
    }

    #[test]
    fn spec_rejects_bad_gates_paths_duplicates_and_caps() {
        assert!(spec_of("g").unwrap_err().contains("no paths"));
        assert!(spec_of("g src\ng tests").unwrap_err().contains("twice"));
        assert!(spec_of("-g src").unwrap_err().contains("gate name"));
        assert!(spec_of("g/x src").unwrap_err().contains("gate name"));
        assert!(spec_of(&format!("{} src", "a".repeat(65)))
            .unwrap_err()
            .contains("gate name"));
        for p in [
            "tests/*.sh",
            "a?",
            "a[b]",
            "a\\b",
            ":!x",
            ":(glob)x",
            ":/x",
            "./x",
            "../x",
            "/x",
            "x/",
            "a/../b",
            "a/./b",
            "a//b",
        ] {
            assert!(spec_of(&format!("g {p}")).is_err(), "{p} should be invalid");
        }
        let many: String = (0..65).map(|i| format!("g{i} src\n")).collect();
        assert!(spec_of(&many).unwrap_err().contains("more than 64 gates"));
        let wide = format!("g {}", vec!["src"; 65].join(" "));
        assert!(spec_of(&wide).unwrap_err().contains("more than 64 paths"));
        // 64 of each is fine
        let many: String = (0..64).map(|i| format!("g{i} src\n")).collect();
        assert!(spec_of(&many).is_ok());
    }

    #[test]
    fn implicit_inputs_cover_both_specs_gitmodules_and_ancestor_attributes() {
        let v = implicit_inputs(&[
            "src".into(),
            "crates/foo/src".into(),
            "crates/bar/Cargo.toml".into(),
        ]);
        assert_eq!(
            v,
            vec![
                ".forgejo/attest-inputs",
                ".github/attest-inputs",
                ".gitmodules",
                ".gitattributes",
                "crates/.gitattributes",
                "crates/bar/.gitattributes",
                "crates/foo/.gitattributes",
            ]
        );
    }

    #[test]
    fn input_lines_need_exactly_three_fields_and_a_real_oid() {
        let fp = "a".repeat(40);
        let p = format!("amont-attest-v2\ninput g1 {fp}\ninput g2 {fp} junk\ninput g3 abc\ninput\tg4\t{fp}\ninput g1 {}\n", "b".repeat(40));
        assert_eq!(input_fp(&p, "g1"), Some(fp.as_str()));
        assert_eq!(input_fp(&p, "g2"), None);
        assert_eq!(input_fp(&p, "g3"), None);
        assert_eq!(input_fp(&p, "g4"), Some(fp.as_str()));
        assert_eq!(input_fp(&p, "g"), None);
        assert_eq!(input_fp(&p, "g10"), None);
        let sha256 = "c".repeat(64);
        assert_eq!(
            input_fp(&format!("input g {sha256}\n"), "g"),
            Some(sha256.as_str())
        );
        assert_eq!(
            input_fp(&format!("input g {}\n", "C".repeat(40)), "g"),
            None
        );
    }

    #[test]
    fn key_preimage_is_exact() {
        assert_eq!(
            key_preimage("ci-fmt", "abc"),
            "amont-attest-input ci-fmt abc\n"
        );
    }

    #[test]
    fn the_uniform_rule_per_gate() {
        let fp = |g: &str| match g {
            "g1" => Some("f1"),
            "g2" => Some("f2"),
            _ => None,
        };
        let head = |g: &str| match g {
            "g1" => Some("f1".to_string()),
            "g2" => Some("other".to_string()),
            _ => None,
        };
        // tree matches: every gate, fingerprints irrelevant
        assert_eq!(
            covered_gates(true, "g1 g2 g3", fp, head),
            ["g1", "g2", "g3"]
        );
        // tree differs: only a gate whose claimed fp equals the one here
        assert_eq!(covered_gates(false, "g1 g2 g3", fp, head), ["g1"]);
        // a claim for a gate not in `gates` buys nothing
        assert_eq!(
            covered_gates(false, "g2 g3", fp, head),
            Vec::<String>::new()
        );
        // duplicates in `gates` are listed once
        assert_eq!(covered_gates(true, "g1 g1", fp, head), ["g1"]);
    }
}
