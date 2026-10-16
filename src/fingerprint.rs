//! Fingerprints of a tree: a gate's declared inputs, and the canonical tree
//! (SPEC.md, "Input fingerprints", "Canonical tree"), with the synthetic note
//! keys they are filed under.

use std::path::Path;

use crate::format::is_oid;
use crate::git;
use crate::spec::{implicit_inputs, Spec};

/// The fingerprint of `gate` on `tree`, or `None` when the gate has none
/// there: not in the spec, a token that does not resolve, git failing at any
/// step, or an empty listing (which would hash to the same value on every
/// tree and is refused as an assertion).
pub fn fingerprint(root: &Path, tree: &str, spec: &Spec, gate: &str) -> Option<String> {
    let toks = spec.paths_of(gate)?;
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
            git::stdout_with_input_in(root, &["cat-file", "--batch-check"], names.as_bytes())?;
        if answers.lines().count() != required.len()
            || answers.lines().any(|l| l.ends_with(" missing"))
        {
            return None;
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
/// with `git hash-object`. `None` when git fails at any step.
pub fn canon(root: &Path, tree: &str) -> Option<String> {
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
    )?;
    let text = canon_text(std::str::from_utf8(&listing).ok()?)?;
    git::stdout_with_input_in(root, &["hash-object", "--stdin"], text.as_bytes())
        .filter(|s| is_oid(s))
}

/// The bytes the canonical key is hashed from.
pub fn canon_key_preimage(canon: &str) -> String {
    format!("amont-attest-canon {canon}\n")
}

/// The synthetic note key for a canonical fingerprint, in the inputs ref.
pub fn canon_key(root: &Path, canon: &str) -> Option<String> {
    git::stdout_with_input_in(
        root,
        &["hash-object", "--stdin"],
        canon_key_preimage(canon).as_bytes(),
    )
    .filter(|s| is_oid(s))
}
