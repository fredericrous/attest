//! The attestation format: the payload's fields, the note's blocks, and the
//! names every producer and verifier shares (SPEC.md, "The note").

/// First token of every payload written (the GREEN name since 1.10.0; see
/// [`WRITE`]; the LEGACY one is still read). A verifier that does not recognise this
/// string must treat the note as absent: an unknown version may mean anything,
/// and "run the tests" is the only safe reading of anything.
pub const FORMAT: &str = WRITE.format;

/// The notes ref, as `git notes --ref` wants it.
pub const NOTES_REF: &str = WRITE.notes_ref;

/// The second notes ref, keyed by input fingerprint rather than by object.
/// Every key there is a synthetic oid that is not an object, which is why it
/// is a separate ref: `git notes prune` on it would drop everything, and the
/// main ref keeps its 1.x invariant that every key is real.
pub const INPUTS_REF: &str = WRITE.inputs_ref;

/// Where `sign.sh --no-push` keeps blocks that never reached origin, under
/// `refs/notes/`, prefixed to either ref name above. Origin cannot revoke
/// them, so a verifier reads them only when asked (`--include-local`).
pub const LOCAL_PREFIX: &str = "attest-local/";

/// The `ssh-keygen -Y` namespace. Namespaces exist so a signature minted for
/// one purpose cannot be replayed for another; an `allowed_signers` entry
/// pinned to this namespace accepts nothing else.
pub const NAMESPACE: &str = WRITE.namespace;

/// One complete set of the names a signed attestation lives under: its header,
/// the two notes refs, the SSH namespace, the two fingerprint domains and the
/// payload's producer-line word. A note is read WHOLE under one set (SPEC.md,
/// "Names"): its header says which, and the namespace, the domains and the
/// inputs ref follow, so the two sets never mix inside one note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Names {
    /// First line of every payload.
    pub format: &'static str,
    /// The notes ref, as `git notes --ref` wants it.
    pub notes_ref: &'static str,
    /// The fingerprint-keyed notes ref.
    pub inputs_ref: &'static str,
    /// The `ssh-keygen -Y` namespace.
    pub namespace: &'static str,
    /// Domain of the input-fingerprint lookup key.
    pub input_domain: &'static str,
    /// Domain of the canonical-tree lookup key.
    pub canon_domain: &'static str,
    /// The word that starts the producer line of a payload.
    pub producer: &'static str,
}

/// The names notes were written under from 1.0 to 1.9. Still read during the
/// 30-day window (ADR-0068); removed at the census (2.0.0).
pub const LEGACY: Names = Names {
    format: "amont-attest-v2",
    notes_ref: "amont-attest",
    inputs_ref: "amont-attest-inputs",
    namespace: "amont-attest",
    input_domain: "amont-attest-input",
    canon_domain: "amont-attest-canon",
    producer: "amont",
};

/// The names notes are signed under since 1.10.0. Verifiers read them first
/// and fall back to [`LEGACY`] (SPEC.md, "Names").
pub const GREEN: Names = Names {
    format: "greengate-attest-v2",
    notes_ref: "greengate-attest",
    inputs_ref: "greengate-attest-inputs",
    namespace: "greengate-attest",
    input_domain: "greengate-attest-input",
    canon_domain: "greengate-attest-canon",
    producer: "greengate",
};

/// The ONE owner of what is written: [`FORMAT`], [`NOTES_REF`],
/// [`INPUTS_REF`], [`NAMESPACE`], the producer word of [`payload`] and the
/// set-less functions (`fingerprint::key`, `canon_key`, their preimages,
/// `notes::sync_mirrors`) all derive from it. [`GREEN`] since 1.10.0 (LEGACY
/// before), together with the name assignments at the top of `sign/sign.sh`,
/// held equal to these by `tests/sign.sh`, which reads back what both
/// signers write.
pub const WRITE: Names = GREEN;

/// How many blocks of one note are read. Every block costs two `ssh-keygen`
/// runs, and the notes ref is writable by anyone with push access.
pub const MAX_BLOCKS: usize = 32;

pub(crate) const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
pub(crate) const END: &str = "-----END SSH SIGNATURE-----";

/// Where a suite ran, as `<arch>-<os>`. Coarser than a target triple on
/// purpose: the libc flavour is not something `std` can answer, and the
/// question a CI matrix actually asks is "did this run on MY leg".
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// The platform a signer principal is bound to: the text after its last `@`
/// when that is `<arch>-<os>` over the closed sets below, else `None`. A
/// principal that names no platform (`ci@relais`, an email address) is
/// unbound, and so is one whose suffix has any other shape
/// (`x@x86_64-linux-gnu`, `x@riscv64-linux`).
pub fn bound_platform(principal: &str) -> Option<&str> {
    const ARCHES: [&str; 2] = ["x86_64", "aarch64"];
    const SYSTEMS: [&str; 3] = ["linux", "macos", "windows"];
    let (_, suffix) = principal.rsplit_once('@')?;
    let (arch, system) = suffix.split_once('-')?;
    (ARCHES.contains(&arch) && SYSTEMS.contains(&system)).then_some(suffix)
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

/// The first block of a note, as payload and signature.
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

/// Read a payload field BY PREFIX, never by line position: the payload has
/// grown a line once already (v1 -> v2 added `platform`), and a positional
/// reader silently mis-assigns every field after an insertion rather than
/// failing. First match wins, so a second `gates` line cannot smuggle a value
/// past the caller.
///
/// Byte-strict, like `verify.sh`: lines are split on LF only and nothing is
/// trimmed but the separating spaces, so a `\r` or a trailing space is part
/// of the value and a `tree` line that carries one matches nothing.
pub fn field<'a>(payload: &'a str, name: &str) -> Option<&'a str> {
    payload
        .split('\n')
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' ')))
        .map(|v| v.trim_start_matches(' '))
}

/// A 40- or 64-hex object id, as `hash-object` prints one.
pub fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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

/// The canonical fingerprint a block claims: a `canon <oid>` line of exactly
/// two blank-separated fields, first occurrence wins. A malformed oid is not
/// a claim.
pub fn canon_claim(payload: &str) -> Option<&str> {
    payload.split('\n').find_map(|line| {
        let f: Vec<&str> = line.split([' ', '\t']).filter(|t| !t.is_empty()).collect();
        (f.len() == 2 && f[0] == "canon" && is_oid(f[1])).then(|| f[1])
    })
}

/// The payload of an attestation, in the exact shape SPEC.md gives: `tree`,
/// `gates`, `platform`, the `input` lines in spec order, `canon`, then the
/// producer line, each followed by LF. The same inputs give the same bytes,
/// so a re-run recognises its own block.
pub fn payload(
    tree: &str,
    gates: &str,
    platform: &str,
    inputs: &[(String, String)],
    canon: Option<&str>,
    producer: &str,
) -> String {
    let mut out = format!("{FORMAT}\ntree {tree}\ngates {gates}\nplatform {platform}\n");
    for (gate, fp) in inputs {
        out.push_str(&format!("input {gate} {fp}\n"));
    }
    if let Some(c) = canon {
        out.push_str(&format!("canon {c}\n"));
    }
    out.push_str(&format!("{} {producer}\n", WRITE.producer));
    out
}

/// A signed block as a note holds it: the payload without its trailing
/// newline, a blank line, the armored signature without its own.
pub fn block(payload: &str, signature: &str) -> String {
    format!(
        "{}\n\n{}",
        payload.trim_end_matches('\n'),
        signature.trim_end_matches('\n')
    )
}
