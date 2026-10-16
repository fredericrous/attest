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

/// Why a path token is not a literal, root-relative file or directory.
/// `git ls-tree` does not glob, so a wildcard would match nothing and
/// silently fingerprint nothing; every other shape here is a path git would
/// interpret rather than look up.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathProblem {
    /// `?` alone.
    NamesNothing,
    /// Starts with `:`, git's pathspec magic.
    Magic,
    /// Starts with `/`.
    Absolute,
    /// Starts with `./` or `../`.
    Relative,
    /// Ends with `/`.
    TrailingSlash,
    /// Contains a glob or escape character.
    Glob(char),
    /// Has an empty, `.` or `..` component.
    BadComponent,
}

/// Why a spec is invalid. Any one invalidates the whole spec. `Display` is
/// the reason the verifier reports, after the spec's path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Larger than [`MAX_SPEC_BYTES`].
    TooLarge,
    /// A byte outside printable ASCII, space, tab and LF.
    Byte(u8),
    /// A gate name outside `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
    GateName { line: usize, gate: String },
    /// A gate declared on two lines.
    Duplicate { line: usize, gate: String },
    /// A gate with no paths.
    NoPaths { line: usize, gate: String },
    /// A gate with more than [`MAX_SPEC_PATHS`] paths.
    TooManyPaths { line: usize, gate: String },
    /// A path that is not a literal, root-relative path.
    Path {
        line: usize,
        path: String,
        problem: PathProblem,
    },
    /// More than [`MAX_SPEC_GATES`] gates.
    TooManyGates,
}

impl std::fmt::Display for PathProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathProblem::NamesNothing => write!(f, "names nothing"),
            PathProblem::Magic => write!(f, "starts with `:` (pathspec magic is not allowed)"),
            PathProblem::Absolute => {
                write!(f, "is absolute; paths are relative to the repository root")
            }
            PathProblem::Relative => write!(f, "starts with `./` or `../`"),
            PathProblem::TrailingSlash => write!(f, "ends with `/`; name the directory without it"),
            PathProblem::Glob(c) => write!(
                f,
                "contains `{c}`; git ls-tree does not glob, only literal paths are accepted"
            ),
            PathProblem::BadComponent => write!(f, "has an empty, `.` or `..` component"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLarge => write!(f, "is larger than {MAX_SPEC_BYTES} bytes"),
            Error::Byte(b) => write!(
                f,
                "contains byte 0x{b:02x}; only printable ASCII, space, tab and LF are allowed"
            ),
            Error::GateName { line, gate } => write!(
                f,
                "line {line}: gate name `{gate}` is not [A-Za-z0-9][A-Za-z0-9._-]* of at most 64 characters"
            ),
            Error::Duplicate { line, gate } => {
                write!(f, "line {line}: gate `{gate}` is declared twice")
            }
            Error::NoPaths { line, gate } => {
                write!(f, "line {line}: gate `{gate}` declares no paths")
            }
            Error::TooManyPaths { line, gate } => write!(
                f,
                "line {line}: gate `{gate}` declares more than {MAX_SPEC_PATHS} paths"
            ),
            Error::Path {
                line,
                path,
                problem,
            } => write!(f, "line {line}: path `{path}` {problem}"),
            Error::TooManyGates => write!(f, "declares more than {MAX_SPEC_GATES} gates"),
        }
    }
}

impl std::error::Error for Error {}

/// What is wrong with one path token, and the token as reported (without
/// its `?` marker); `None` when it is a literal, root-relative path.
pub(crate) fn path_error(tok: &str) -> Option<(String, PathProblem)> {
    // One leading `?` marks an optional path; the rest obeys every rule
    // below, so `??x` (a wildcard) and `?/x` (absolute) fail them.
    let tok = match tok.strip_prefix('?') {
        Some("") => return Some(("?".into(), PathProblem::NamesNothing)),
        Some(rest) => rest,
        None => tok,
    };
    let bad = |p: PathProblem| Some((tok.to_string(), p));
    if tok.starts_with(':') {
        return bad(PathProblem::Magic);
    }
    if tok.starts_with('/') {
        return bad(PathProblem::Absolute);
    }
    if tok.starts_with("./") || tok.starts_with("../") {
        return bad(PathProblem::Relative);
    }
    if tok.ends_with('/') {
        return bad(PathProblem::TrailingSlash);
    }
    if let Some(c) = tok
        .chars()
        .find(|c| matches!(c, '*' | '?' | '[' | ']' | '\\'))
    {
        return bad(PathProblem::Glob(c));
    }
    if tok
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return bad(PathProblem::BadComponent);
    }
    None
}

/// The spec grammar, byte-strict. Every violation is a distinct reason, and
/// any violation invalidates the WHOLE spec: a line that silently dropped out
/// would be one the author believes is protecting something.
pub fn parse_spec(bytes: &[u8]) -> Result<Spec, Error> {
    if bytes.len() > MAX_SPEC_BYTES {
        return Err(Error::TooLarge);
    }
    if let Some(&b) = bytes
        .iter()
        .find(|&&b| !(b == b' ' || b == b'\t' || b == b'\n' || (0x21..=0x7e).contains(&b)))
    {
        return Err(Error::Byte(b));
    }
    // Every byte is ASCII by the check above.
    let text = std::str::from_utf8(bytes).expect("ASCII is UTF-8");
    let mut gates: Vec<(String, Vec<PathTok>)> = Vec::new();
    for (n, line) in text.split('\n').enumerate() {
        let line_no = n + 1;
        let mut toks = line.split([' ', '\t']).filter(|t| !t.is_empty());
        let Some(gate) = toks.next() else { continue };
        if gate.starts_with('#') {
            continue;
        }
        let at = |gate: &str| (line_no, gate.to_string());
        if !valid_gate(gate) {
            let (line, gate) = at(gate);
            return Err(Error::GateName { line, gate });
        }
        if gates.iter().any(|(g, _)| g == gate) {
            let (line, gate) = at(gate);
            return Err(Error::Duplicate { line, gate });
        }
        let paths: Vec<String> = toks.map(String::from).collect();
        if paths.is_empty() {
            let (line, gate) = at(gate);
            return Err(Error::NoPaths { line, gate });
        }
        if paths.len() > MAX_SPEC_PATHS {
            let (line, gate) = at(gate);
            return Err(Error::TooManyPaths { line, gate });
        }
        for p in &paths {
            if let Some((path, problem)) = path_error(p) {
                return Err(Error::Path {
                    line: line_no,
                    path,
                    problem,
                });
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
            return Err(Error::TooManyGates);
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

/// Why a tree has a spec that cannot be used. Each disables the
/// input-fingerprint route only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AtError {
    /// Both locations hold a spec.
    Ambiguous,
    /// The spec at this path could not be read from the tree.
    Unreadable(&'static str),
    /// The spec at this path is invalid.
    Invalid(&'static str, Error),
}

/// The spec committed in `tree` and where it was found; `Ok(None)` when the
/// tree has none. Read from the TREE, never the working copy: the bytes
/// hashed into every fingerprint and the bytes parsed here are then the same
/// object.
pub fn at(root: &Path, tree: &str) -> Result<Option<(&'static str, Spec)>, AtError> {
    let present: Vec<&'static str> = SPEC_PATHS
        .iter()
        .copied()
        .filter(|p| git::succeeds_in(root, &["cat-file", "-e", &format!("{tree}:{p}")]))
        .collect();
    let path = match present.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        _ => return Err(AtError::Ambiguous),
    };
    let bytes = git::stdout_bytes_in(root, &["cat-file", "blob", &format!("{tree}:{path}")])
        .ok_or(AtError::Unreadable(path))?;
    parse_spec(&bytes)
        .map(|spec| Some((path, spec)))
        .map_err(|e| AtError::Invalid(path, e))
}

// ---------------------------------------------------------------------------
// Completeness: does a declaration cover every tracked file?
// ---------------------------------------------------------------------------

/// Paths no gate reads, exempt from the coverage check: the plans a change
/// keeps rewriting. Everything else a repository tracks is either declared or
/// the check fails.
pub const EXEMPT: [&str; 1] = ["docs/plans/"];

/// How many offending paths one gate lists before the rest are counted.
const LIST_CAP: usize = 50;

/// Why the coverage question cannot be answered. A guard that cannot answer
/// fails, unlike the verifier, whose contract is fail-open.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoverageError {
    /// The tree holds no spec.
    Missing,
    /// Both locations hold one.
    Ambiguous,
    /// The spec at this path is unreadable or invalid.
    Invalid(&'static str),
    /// git could not list the tree, or it is empty.
    Unlisted,
}

impl CoverageError {
    /// The one line a person reads when the spec itself cannot be used.
    pub fn render(&self, tree: &str) -> String {
        match self {
            CoverageError::Missing => format!(
                "check-attest-inputs: no {} or {} on {tree}",
                SPEC_PATHS[0], SPEC_PATHS[1]
            ),
            CoverageError::Ambiguous => format!(
                "check-attest-inputs: both {} and {} exist on {tree}; that disables the route",
                SPEC_PATHS[0], SPEC_PATHS[1]
            ),
            CoverageError::Invalid(path) => format!(
                "check-attest-inputs: {path} is invalid on {tree} (one violation invalidates the whole spec; see attest SPEC, \"Input fingerprints\")"
            ),
            CoverageError::Unlisted => {
                format!("check-attest-inputs: git could not list {tree}, or it is empty")
            }
        }
    }
}

/// What [`check_coverage`] found. Empty means every required gate declares
/// every tracked file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Findings {
    /// Required gates the spec does not declare at all.
    pub undeclared: Vec<String>,
    /// Declared gates that cannot be fingerprinted on the tree.
    pub unfingerprintable: Vec<String>,
    /// Per gate, the tracked files no declared path is, or is an ancestor of.
    pub uncovered: Vec<(String, Vec<String>)>,
}

impl Findings {
    /// Everything wrong, for stderr: every gate and path, indented, then the
    /// two ways out.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for g in &self.undeclared {
            out.push_str(&format!(
                "check-attest-inputs: {g}: not declared in the spec\n"
            ));
        }
        for g in &self.unfingerprintable {
            out.push_str(&format!(
                "check-attest-inputs: {g}: cannot be fingerprinted (a required path is missing)\n"
            ));
        }
        for (g, paths) in &self.uncovered {
            out.push_str(&format!("check-attest-inputs: {g}: not covered:\n"));
            for p in paths.iter().take(LIST_CAP) {
                out.push_str(&format!("  {p}\n"));
            }
            if paths.len() > LIST_CAP {
                out.push_str(&format!("  ... and {} more\n", paths.len() - LIST_CAP));
            }
        }
        out.push_str(
            "check-attest-inputs: fix: declare each path above for that gate (a directory \
             covers everything under it); only a path no gate reads may be exempt, and that \
             is a code-review decision. An undeclared path makes CI and the hooks skip \
             wrongly the day it changes.\n",
        );
        out
    }

    pub fn is_empty(&self) -> bool {
        self.undeclared.is_empty() && self.unfingerprintable.is_empty() && self.uncovered.is_empty()
    }
}

/// The files every fingerprint lists whatever a gate declares: both spec
/// locations, and the root `.gitmodules` and `.gitattributes`.
fn is_implicit(file: &[u8]) -> bool {
    SPEC_PATHS.iter().any(|p| p.as_bytes() == file)
        || file == b".gitmodules"
        || file == b".gitattributes"
}

/// Is `file` covered by the declared path `decl`: the file itself, or a file
/// under that directory? Bytes, not text: a name outside printable ASCII can
/// never be declared and is covered only through an ASCII ancestor.
fn covers(decl: &str, file: &[u8]) -> bool {
    let d = decl.as_bytes();
    file == d || (file.len() > d.len() && file.starts_with(d) && file[d.len()] == b'/')
}

/// The pure half of [`check_coverage`]: coverage of `files` by each required
/// gate of `spec`, with the fingerprint question answered by
/// `can_fingerprint`.
pub fn coverage(
    spec: &Spec,
    required: &[String],
    files: &[Vec<u8>],
    can_fingerprint: impl Fn(&str) -> bool,
) -> Findings {
    let mut out = Findings::default();
    for gate in required {
        let Some(toks) = spec.paths_of(gate) else {
            out.undeclared.push(gate.clone());
            continue;
        };
        if !can_fingerprint(gate) {
            out.unfingerprintable.push(gate.clone());
        }
        let missing: Vec<String> = files
            .iter()
            .filter(|f| !EXEMPT.iter().any(|e| f.starts_with(e.as_bytes())))
            .filter(|f| !is_implicit(f))
            .filter(|f| !toks.iter().any(|t| covers(&t.path, f)))
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect();
        if !missing.is_empty() {
            out.uncovered.push((gate.clone(), missing));
        }
    }
    out
}

/// Do the required gates declare, completely, everything `tree` tracks?
///
/// Declared inputs are only as good as their completeness: a gate whose spec
/// omits something it reads is skipped wrongly the day that something
/// changes. This is the proof that closes the gap: per gate, by real
/// ancestry, never by union and never by first path component. The spec is
/// read from the tree, not the working copy.
pub fn check_coverage(
    root: &Path,
    tree: &str,
    required: &[String],
) -> Result<Findings, CoverageError> {
    let spec = match at(root, tree) {
        Ok(Some((_, spec))) => spec,
        Ok(None) => return Err(CoverageError::Missing),
        Err(AtError::Ambiguous) => return Err(CoverageError::Ambiguous),
        Err(AtError::Unreadable(p)) | Err(AtError::Invalid(p, _)) => {
            return Err(CoverageError::Invalid(p))
        }
    };
    let listing = git::stdout_bytes_in(
        root,
        &["ls-tree", "-r", "-z", "--full-tree", "--name-only", tree],
    )
    .filter(|l| !l.is_empty())
    .ok_or(CoverageError::Unlisted)?;
    let files: Vec<Vec<u8>> = listing
        .split(|&b| b == 0)
        .filter(|f| !f.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    Ok(coverage(&spec, required, &files, |gate| {
        crate::fingerprint::fingerprint(root, tree, &spec, gate).is_ok()
    }))
}
