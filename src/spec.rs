//! The `attest-inputs` declaration (SPEC.md, "Input fingerprints") and the
//! canonical-tree opt-out it governs (SPEC.md, "Canonical tree").

use std::path::Path;

use crate::git;

/// Where a repository declares which paths each gate reads, in order of
/// precedence. Both are always part of every fingerprint's listing.
pub const SPEC_PATHS: [&str; 2] = [".forgejo/attest-inputs", ".github/attest-inputs"];
pub const MAX_SPEC_BYTES: usize = 65536;
pub const MAX_SPEC_GATES: usize = 64;
pub const MAX_SPEC_PATHS: usize = 64;

// ---------------------------------------------------------------------------
// Input fingerprints (1.3.0)
// ---------------------------------------------------------------------------

/// One declared path. `?src/build.rs` in the spec is `optional`: it may be
/// absent, and its absence is then part of the fingerprint. The marker is
/// stripped here, once, so no consumer can ever hand `?x` to git — where it
/// would match nothing and silently drop out of the fingerprint.
#[derive(Debug, PartialEq, Clone)]
pub struct PathTok {
    pub path: String,
    pub optional: bool,
}

/// The committed declaration of which paths each gate reads.
#[derive(Debug, PartialEq)]
pub struct Spec {
    pub gates: Vec<(String, Vec<PathTok>)>,
}

impl Spec {
    pub fn paths_of(&self, gate: &str) -> Option<&[PathTok]> {
        self.gates
            .iter()
            .find(|(g, _)| g == gate)
            .map(|(_, p)| p.as_slice())
    }
}

/// A gate name as the spec allows it: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
pub(crate) fn valid_gate(name: &str) -> bool {
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
pub(crate) fn path_error(tok: &str) -> Option<String> {
    // One leading `?` marks an optional path; the rest obeys every rule
    // below, so `??x` (a wildcard) and `?/x` (absolute) fail them.
    let tok = match tok.strip_prefix('?') {
        Some("") => return Some("path `?` names nothing".into()),
        Some(rest) => rest,
        None => tok,
    };
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
    let mut gates: Vec<(String, Vec<PathTok>)> = Vec::new();
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
        let paths = paths
            .into_iter()
            .map(|p| match p.strip_prefix('?') {
                Some(rest) => PathTok {
                    path: rest.to_string(),
                    optional: true,
                },
                None => PathTok {
                    path: p,
                    optional: false,
                },
            })
            .collect();
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

/// Does this `amont.conf` say `set planExempt off`? One tolerant reading,
/// shared with amont and `verify.sh`: strip CR, trim blanks, split on blanks,
/// and compare the three words `set`, `planExempt` and `off` ASCII
/// case-insensitively. A line that is not exactly those three words (a
/// trailing comment, another value) does not match; any match anywhere is off.
pub fn conf_says_plan_exempt_off(bytes: &[u8]) -> bool {
    bytes.split(|&b| b == b'\n').any(|line| {
        let line: Vec<u8> = line.iter().copied().filter(|&b| b != b'\r').collect();
        let words: Vec<&[u8]> = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|w| !w.is_empty())
            .collect();
        words.len() == 3
            && words[0].eq_ignore_ascii_case(b"set")
            && words[1].eq_ignore_ascii_case(b"planExempt")
            && words[2].eq_ignore_ascii_case(b"off")
    })
}

/// What `tree:amont.conf` says about the canonical route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanExempt {
    /// A successful `ls-tree` that lists no `amont.conf`, or one without the
    /// `set planExempt off` line.
    On,
    /// The committed `amont.conf` opts out.
    Off,
    /// A failing `ls-tree`, or a listed `amont.conf` whose blob cannot be
    /// read. Fails narrow: callers treat it as off; only the log differs.
    Unreadable,
}

/// Is the canonical route switched off for `tree`? Read from the bytes of
/// `tree:amont.conf` itself, never through amont's trust-gated settings: `off`
/// only narrows, so it is honoured whoever wrote it.
pub fn plan_exempt(root: &Path, tree: &str) -> PlanExempt {
    let Some(listing) =
        git::stdout_bytes_in(root, &["ls-tree", "--full-tree", tree, "--", "amont.conf"])
    else {
        return PlanExempt::Unreadable;
    };
    if listing.is_empty() {
        return PlanExempt::On;
    }
    match git::stdout_bytes_in(root, &["cat-file", "blob", &format!("{tree}:amont.conf")]) {
        Some(bytes) if conf_says_plan_exempt_off(&bytes) => PlanExempt::Off,
        Some(_) => PlanExempt::On,
        None => PlanExempt::Unreadable,
    }
}
