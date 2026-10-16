//! The attestation format: the payload's fields, the note's blocks, and the
//! names every producer and verifier shares (SPEC.md, "The note").

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

/// Where `sign.sh --no-push` keeps blocks that never reached origin, under
/// `refs/notes/`, prefixed to either ref name above. Origin cannot revoke
/// them, so a verifier reads them only when asked (`--include-local`).
pub const LOCAL_PREFIX: &str = "attest-local/";

/// The `ssh-keygen -Y` namespace. Namespaces exist so a signature minted for
/// one purpose cannot be replayed for another; an `allowed_signers` entry
/// pinned to this namespace accepts nothing else.
pub const NAMESPACE: &str = "amont-attest";

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
