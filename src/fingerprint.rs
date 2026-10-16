//! Fingerprints of a tree: a gate's declared inputs, and the canonical tree
//! (SPEC.md, "Input fingerprints", "Canonical tree"), with the synthetic note
//! keys they are filed under.

use std::path::Path;

use crate::format::is_oid;
use crate::git;
use crate::spec::{implicit_inputs, Spec};

/// Why a fingerprint or a key could not be computed. Every one means "no
/// fingerprint here", which can only cost a skip.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The spec declares no such gate.
    NotDeclared,
    /// A required path does not exist in the tree.
    MissingPath,
    /// The listing was empty, which would hash alike on every tree.
    EmptyListing,
    /// The listing was not a well-formed `ls-tree` listing.
    Malformed,
    /// git failed, or printed something that is not an object id.
    Git,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::NotDeclared => "the spec declares no such gate",
            Error::MissingPath => "a declared path does not exist in this tree",
            Error::EmptyListing => "the declared paths list nothing",
            Error::Malformed => "the tree listing is malformed",
            Error::Git => "git failed",
        })
    }
}

impl std::error::Error for Error {}

/// `hash-object --stdin` of `bytes`, as an object id.
fn hash(root: &Path, bytes: &[u8]) -> Result<String, Error> {
    git::stdout_with_input_in(root, &["hash-object", "--stdin"], bytes)
        .filter(|s| is_oid(s))
        .ok_or(Error::Git)
}

/// The fingerprint of `gate` on `tree`. An empty listing would hash to the
/// same value on every tree and is refused as an assertion.
pub fn fingerprint(root: &Path, tree: &str, spec: &Spec, gate: &str) -> Result<String, Error> {
    let toks = spec.paths_of(gate).ok_or(Error::NotDeclared)?;
    let paths: Vec<String> = toks.iter().map(|t| t.path.clone()).collect();
    // Every REQUIRED token must resolve — one `cat-file --batch-check` for
    // all of them, never one process per token. An optional one is listed if
    // it is there and bound by its absence if it is not.
    let required: Vec<&str> = toks
        .iter()
        .filter(|t| !t.optional)
        .map(|t| t.path.as_str())
        .collect();
    if !required.is_empty() {
        let names: String = required.iter().map(|p| format!("{tree}:{p}\n")).collect();
        let answers =
            git::stdout_with_input_in(root, &["cat-file", "--batch-check"], names.as_bytes())
                .ok_or(Error::Git)?;
        if answers.lines().count() != required.len() {
            return Err(Error::Git);
        }
        if answers.lines().any(|l| l.ends_with(" missing")) {
            return Err(Error::MissingPath);
        }
    }
    let mut args: Vec<String> = vec![
        "ls-tree".into(),
        "-r".into(),
        "-z".into(),
        "--full-tree".into(),
        tree.to_string(),
        "--".into(),
    ];
    args.extend(implicit_inputs(&paths));
    args.extend(paths.iter().cloned());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let listing = git::stdout_bytes_in(root, &argv).ok_or(Error::Git)?;
    if listing.is_empty() {
        return Err(Error::EmptyListing);
    }
    hash(root, &listing)
}

/// The bytes a fingerprint key is hashed from.
pub fn key_preimage(gate: &str, fp: &str) -> String {
    format!("amont-attest-input {gate} {fp}\n")
}

/// The synthetic note key for (gate, fingerprint): an oid that is not an
/// object, which `git notes` accepts as a key all the same.
pub fn key(root: &Path, gate: &str, fp: &str) -> Result<String, Error> {
    hash(root, key_preimage(gate, fp).as_bytes())
}

/// The canonical text of an `ls-tree -r --full-tree` listing (paths quoted by
/// `core.quotePath=true`, so one record is one line): the same lines, except
/// that a regular file (`100644`, `100755`) under the top-level `docs/plans/`
/// has its oid replaced by zeros of the same length. Existence stays; content
/// does not count. Symlinks and gitlinks are never neutralised. `None` for an
/// empty or malformed listing.
pub fn canon_text(listing: &str) -> Option<String> {
    let mut out = String::with_capacity(listing.len());
    for line in listing.lines() {
        let (head, path) = line.split_once('\t')?;
        let mut f = head.split(' ');
        let (mode, kind, oid) = (f.next()?, f.next()?, f.next()?);
        if f.next().is_some() {
            return None;
        }
        // A quoted path keeps its first characters: `"docs/plans/...`.
        let under_plans = path.starts_with("docs/plans/") || path.starts_with("\"docs/plans/");
        if matches!(mode, "100644" | "100755") && under_plans {
            out.push_str(&format!(
                "{mode} {kind} {}\t{path}\n",
                "0".repeat(oid.len())
            ));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The canonical fingerprint of `tree`: `canon_text` of its listing, hashed
/// with `git hash-object`.
pub fn canon(root: &Path, tree: &str) -> Result<String, Error> {
    let listing = git::stdout_bytes_in(
        root,
        &[
            "-c",
            "core.quotePath=true",
            "ls-tree",
            "-r",
            "--full-tree",
            tree,
        ],
    )
    .ok_or(Error::Git)?;
    let listing = std::str::from_utf8(&listing).map_err(|_| Error::Malformed)?;
    let text = canon_text(listing).ok_or(Error::Malformed)?;
    hash(root, text.as_bytes())
}

/// The bytes the canonical key is hashed from.
pub fn canon_key_preimage(canon: &str) -> String {
    format!("amont-attest-canon {canon}\n")
}

/// The synthetic note key for a canonical fingerprint, in the inputs ref.
pub fn canon_key(root: &Path, canon: &str) -> Result<String, Error> {
    hash(root, canon_key_preimage(canon).as_bytes())
}
