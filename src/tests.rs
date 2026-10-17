//! Unit tests of the library, across its modules.

use crate::fingerprint::*;
use crate::format::*;
use crate::spec::*;
use crate::verify::*;

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
    parse_spec(s.as_bytes()).map_err(|e| e.to_string())
}

#[test]
fn spec_parses_gates_comments_tabs_and_a_missing_final_newline() {
    let s = spec_of("# a comment\n\nci-fmt\tsrc  Cargo.toml\n  # indented comment\ntest src tests")
        .unwrap();
    let req = |p: &str| PathTok {
        path: p.to_string(),
        optional: false,
    };
    assert_eq!(
        s.gates,
        vec![
            ("ci-fmt".to_string(), vec![req("src"), req("Cargo.toml")]),
            ("test".to_string(), vec![req("src"), req("tests")]),
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
        assert!(
            parse_spec(bad).unwrap_err().to_string().contains("byte 0x"),
            "{bad:?}"
        );
    }
    assert!(parse_spec(&vec![b'\n'; MAX_SPEC_BYTES + 1])
        .unwrap_err()
        .to_string()
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
fn optional_paths_are_marked_once_and_stripped() {
    let s = spec_of("g src ?build.rs ?a/b/c").unwrap();
    let toks = s.paths_of("g").unwrap();
    assert_eq!(
        toks.iter()
            .map(|t| (t.path.as_str(), t.optional))
            .collect::<Vec<_>>(),
        [("src", false), ("build.rs", true), ("a/b/c", true)]
    );
    // An all-optional gate is a gate.
    assert!(spec_of("g ?nope").is_ok());
    // The marker is one character, first, and marks a real path.
    for bad in [
        "?", "??x", "?/x", "?./x", "?x/", "?:x", "x?", "?a//b", "?a/../b",
    ] {
        assert!(
            spec_of(&format!("g {bad}")).is_err(),
            "{bad} should be invalid"
        );
    }
    assert!(spec_of("g ?").unwrap_err().contains("names nothing"));
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
        covered_gates(true, false, "g1 g2 g3", fp, head),
        ["g1", "g2", "g3"]
    );
    // tree differs: only a gate whose claimed fp equals the one here
    assert_eq!(covered_gates(false, false, "g1 g2 g3", fp, head), ["g1"]);
    // a claim for a gate not in `gates` buys nothing
    assert_eq!(
        covered_gates(false, false, "g2 g3", fp, head),
        Vec::<String>::new()
    );
    // duplicates in `gates` are listed once
    assert_eq!(covered_gates(true, false, "g1 g1", fp, head), ["g1"]);
    // the canonical tree equal: every gate, fingerprints irrelevant
    assert_eq!(
        covered_gates(false, true, "g1 g2 g3", fp, head),
        ["g1", "g2", "g3"]
    );
}

const O1: &str = "1111111111111111111111111111111111111111";
const O2: &str = "2222222222222222222222222222222222222222";
const Z: &str = "0000000000000000000000000000000000000000";

#[test]
fn canon_text_neutralises_plan_content_and_keeps_everything_else() {
    let a = format!(
        "100644 blob {O1}\tREADME.md\n100644 blob {O1}\tdocs/plans/a.md\n100755 blob {O1}\tdocs/plans/sub/run.sh\n"
    );
    let edited = a.replace(
        &format!("{O1}\tdocs/plans/a.md"),
        &format!("{O2}\tdocs/plans/a.md"),
    );
    // editing a plan changes nothing
    assert_eq!(canon_text(&a), canon_text(&edited));
    assert!(canon_text(&a)
        .unwrap()
        .contains(&format!("100644 blob {Z}\tdocs/plans/a.md\n")));
    // any other path's content, a plan's existence, a rename: all change it
    let other = a.replace(&format!("{O1}\tREADME.md"), &format!("{O2}\tREADME.md"));
    assert_ne!(canon_text(&a), canon_text(&other));
    let added = format!("{a}100644 blob {O1}\tdocs/plans/b.md\n");
    assert_ne!(canon_text(&a), canon_text(&added));
    let renamed = a.replace("docs/plans/a.md", "docs/plans/c.md");
    assert_ne!(canon_text(&a), canon_text(&renamed));
}

/// One case of `tests/vectors/canon.txt`: a name, a listing, and its
/// canonical text (`None`: no canon).
type CanonCase = (String, String, Option<String>);

/// Parse `tests/vectors/canon.txt` (its header says the format). Strict:
/// any line the format does not allow panics, so a damaged file fails the
/// test instead of silently testing less.
fn canon_vectors(text: &str) -> Vec<CanonCase> {
    let mut cases = Vec::new();
    let mut open: Option<(String, String, Option<String>, bool)> = None;
    for (n, line) in text.split('\n').enumerate() {
        let at = n + 1;
        match open.as_mut() {
            None if line.is_empty() || line.starts_with('#') => {}
            None => {
                let name = line
                    .strip_prefix("case ")
                    .unwrap_or_else(|| panic!("canon.txt:{at}: expected `case`: {line:?}"));
                open = Some((name.to_string(), String::new(), None, false));
            }
            Some((_, listing, out, none)) => {
                if line == "end" {
                    let (name, listing, out, none) = open.take().unwrap();
                    assert!(
                        out.is_some() != none,
                        "canon.txt:{at}: `{name}` needs `out` lines or one `none`"
                    );
                    cases.push((name, listing, out));
                } else if line == "none" {
                    assert!(out.is_none() && !*none, "canon.txt:{at}: misplaced `none`");
                    *none = true;
                } else if let Some(rec) = line.strip_prefix("in ") {
                    assert!(
                        out.is_none() && !*none,
                        "canon.txt:{at}: `in` after the answer"
                    );
                    listing.push_str(rec);
                    listing.push('\n');
                } else if let Some(rec) = line.strip_prefix("out ") {
                    assert!(!*none, "canon.txt:{at}: `out` after `none`");
                    let o = out.get_or_insert_with(String::new);
                    o.push_str(rec);
                    o.push('\n');
                } else {
                    panic!("canon.txt:{at}: not a directive: {line:?}");
                }
            }
        }
    }
    assert!(open.is_none(), "canon.txt: the last case has no `end`");
    cases
}

#[test]
fn canon_text_gives_every_known_answer() {
    let cases = canon_vectors(include_str!("../tests/vectors/canon.txt"));
    assert!(cases.iter().any(|c| c.2.is_some()) && cases.iter().any(|c| c.2.is_none()));
    for (name, listing, want) in &cases {
        assert_eq!(canon_text(listing).as_ref(), want.as_ref(), "{name}");
    }
}

#[test]
fn the_vectors_reader_refuses_a_damaged_file() {
    for bad in [
        "stray\n",
        "case x\nin a\tb\n",
        "case x\nend\n",
        "case x\nnone\nout y\nend\n",
        "case x\nout y\nin a\tb\nend\n",
        "case x\nwhat\nend\n",
    ] {
        assert!(
            std::panic::catch_unwind(|| canon_vectors(bad)).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn the_opt_out_is_one_tolerant_reading() {
    for yes in [
        "set planExempt off\n",
        "SET PLANEXEMPT OFF",
        "  set\tplanExempt   off  \r\n",
        "gate x\nset planExempt off\ngate y\n",
        "set planExempt on\nset planExempt off\n",
        "set planExempt off\nset planExempt on\n",
    ] {
        assert!(conf_says_plan_exempt_off(yes.as_bytes()), "{yes:?}");
    }
    for no in [
        "",
        "set planExempt on\n",
        "set planExempt off # trailing comment\n",
        "# set planExempt off\n",
        "set planExempt\n",
        "set planExempt off off\n",
        "setplanExempt off\n",
        "set planexempt of\n",
    ] {
        assert!(!conf_says_plan_exempt_off(no.as_bytes()), "{no:?}");
    }
}

#[test]
fn a_canon_claim_is_two_fields_and_a_real_oid() {
    let p = format!("amont-attest-v2\ncanon {O1}\namont x\n");
    assert_eq!(canon_claim(&p), Some(O1));
    assert_eq!(canon_claim(&format!("canon {O1} extra\n")), None);
    assert_eq!(canon_claim("canon xyz\n"), None);
    assert_eq!(canon_claim("canon\n"), None);
    // first occurrence wins
    assert_eq!(canon_claim(&format!("canon {O1}\ncanon {O2}\n")), Some(O1));
    assert_eq!(canon_key_preimage(O1), format!("amont-attest-canon {O1}\n"));
}

#[test]
fn a_payload_has_the_spec_shape_and_a_block_one_blank_line() {
    let inputs = vec![("lint".to_string(), O1.to_string())];
    let p = payload(
        "t0",
        "lint test",
        "x86_64-linux",
        &inputs,
        Some(O2),
        "attest-sign",
    );
    assert_eq!(
        p,
        format!("amont-attest-v2\ntree t0\ngates lint test\nplatform x86_64-linux\ninput lint {O1}\ncanon {O2}\namont attest-sign\n")
    );
    assert_eq!(
        payload("t", "g", "p", &[], None, "x"),
        "amont-attest-v2\ntree t\ngates g\nplatform p\namont x\n"
    );
    let b = crate::format::block(&p, &format!("{SIG}\n"));
    let (back, sig) = split_note(&b).unwrap();
    assert_eq!(back, p, "the block splits back into the signed bytes");
    assert_eq!(sig.trim_end(), SIG);
}

#[test]
fn a_gate_list_is_one_space_between_names() {
    use crate::produce::gate_list;
    assert_eq!(gate_list("  a\tb\n\nc  "), "a b c");
    assert_eq!(gate_list(" \n "), "");
}

#[test]
fn a_push_failure_is_raced_unreachable_or_refused() {
    use crate::notes::{classify_push, PushFailure};
    assert_eq!(
        classify_push(" ! [rejected] x (non-fast-forward)"),
        PushFailure::Raced
    );
    assert_eq!(
        classify_push("error: failed to push some refs (fetch first)"),
        PushFailure::Raced
    );
    assert_eq!(
        classify_push("fatal: unable to access 'https://h/': Could not resolve host: h"),
        PushFailure::Unreachable
    );
    // a hook's own output naming a connection is not the remote being down
    assert_eq!(
        classify_push("remote: Connection refused by the gate\nerror: hook declined"),
        PushFailure::Refused
    );
    // a race on a reachable remote is a race
    assert_eq!(
        classify_push("fatal: unable to access\n non-fast-forward"),
        PushFailure::Raced
    );
}

#[test]
fn a_credential_in_a_remote_url_never_reaches_the_log() {
    use crate::notes::scrub;
    assert_eq!(
        scrub("fatal: unable to access 'https://x-access-token:s3cr3t@github.com/o/r/':\n  denied"),
        "fatal: unable to access 'https://github.com/o/r/': denied"
    );
    assert_eq!(scrub("ssh://git@host/r"), "ssh://host/r");
}

#[test]
fn coverage_is_per_gate_by_real_ancestry() {
    let spec = parse_spec(b"lint src docs/README.md\ntest src\n").unwrap();
    let files: Vec<Vec<u8>> = [
        "src/main.rs",
        "srcx/other.rs",
        "docs/README.md",
        "docs/plans/p.md",
        ".gitattributes",
        ".github/attest-inputs",
        "Cargo.toml",
    ]
    .iter()
    .map(|f| f.as_bytes().to_vec())
    .collect();
    let req = |g: &[&str]| g.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let f = coverage(&spec, &req(&["lint", "test", "fmt"]), &files, |g| {
        g != "test"
    });
    assert_eq!(f.undeclared, ["fmt"]);
    assert_eq!(f.unfingerprintable, ["test"]);
    // `srcx/` is not under `src/`; plans and the implicit inputs are exempt
    assert_eq!(
        f.uncovered,
        vec![
            (
                "lint".to_string(),
                vec!["srcx/other.rs".to_string(), "Cargo.toml".to_string()]
            ),
            (
                "test".to_string(),
                vec![
                    "srcx/other.rs".to_string(),
                    "docs/README.md".to_string(),
                    "Cargo.toml".to_string()
                ]
            ),
        ]
    );
    assert!(f
        .render()
        .contains("check-attest-inputs: lint: not covered:\n  srcx/other.rs\n"));
    assert!(coverage(&spec, &req(&["lint"]), &files[..1], |_| true).is_empty());
}

/// A scratch repository with one commit: `src/main.rs`, a spec declaring
/// `lint src`, and `.github/allowed_signers`.
fn scratch_repo(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("git-attest-lib-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("src/deep")).unwrap();
    std::fs::create_dir_all(d.join(".github")).unwrap();
    std::fs::write(d.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(d.join(".github/attest-inputs"), "lint src\n").unwrap();
    std::fs::write(
        d.join(".github/allowed_signers"),
        "x namespaces=\"amont-attest\" k\n",
    )
    .unwrap();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .current_dir(&d)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
            .status
            .success());
    };
    git(&["init", "-q", "--template="]);
    git(&["add", "-A"]);
    git(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-qm",
        "init",
    ]);
    d
}

/// Every entry point answers for the repository it is handed, never for the
/// process's working directory (here, this crate's own checkout).
#[test]
fn the_library_answers_for_the_repository_it_is_given() {
    let repo = scratch_repo("cwd");
    let sub = repo.join("src/deep");
    let tree = {
        let out = std::process::Command::new("git")
            .current_dir(&repo)
            .args(["rev-parse", "HEAD^{tree}"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(
        default_signers(&sub).map(|p| p.ends_with(".github/allowed_signers")),
        Some(true)
    );
    let (path, spec) = crate::spec::at(&repo, &tree).unwrap().unwrap();
    assert_eq!(path, ".github/attest-inputs");
    assert!(fingerprint(&repo, &tree, &spec, "lint").is_ok());
    assert!(canon(&repo, &tree).is_ok());
    assert!(check_coverage(&repo, &tree, &["lint".to_string()]).is_ok());
    let mut log = Vec::new();
    let att = crate::produce::attestation(&repo, &tree, "lint", "p", "t", &mut log);
    assert_eq!(att.inputs.len(), 1, "{log:?}");
    assert_eq!(att.input_keys.len(), 2, "one input key, one canonical key");
    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn the_opt_out_directive_is_a_line_of_the_spec_and_nothing_else_is() {
    let s = parse_spec(b"# x\n  @plan-exempt \t off  \nlint src\n").unwrap();
    assert!(s.plan_exempt_off);
    assert_eq!(s.gates.len(), 1);
    assert!(parse_spec(b"@plan-exempt off\n").unwrap().plan_exempt_off);
    assert!(!parse_spec(b"lint src\n").unwrap().plan_exempt_off);
    for bad in [
        "@plan-exempt on\n",
        "@plan-exempt off off\n",
        "@planExempt off\n",
        "@x\n",
    ] {
        let e = parse_spec(bad.as_bytes()).unwrap_err();
        assert!(
            matches!(e, crate::spec::Error::Directive { .. }),
            "{bad:?}: {e}"
        );
    }
    assert!(is_plan_exempt_directive(b" @plan-exempt\toff "));
    assert!(!is_plan_exempt_directive(b"@plan-exempt off\r"));
}

/// One case of a vectors file: its name and its directives, in order.
type Case = (String, Vec<(String, String)>);

/// Parse a `tests/vectors/*.txt` file whose cases hold only the `allowed`
/// directives (its header says which). Strict: a stray line, an unknown
/// directive or an unclosed case panics, so a damaged file fails instead of
/// silently testing less.
fn vectors(name: &str, text: &str, allowed: &[&str]) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut open: Option<Case> = None;
    for (n, line) in text.split('\n').enumerate() {
        let at = n + 1;
        match open.as_mut() {
            None if line.is_empty() || line.starts_with('#') => {}
            None => {
                let case = line
                    .strip_prefix("case ")
                    .unwrap_or_else(|| panic!("{name}:{at}: expected `case`: {line:?}"));
                open = Some((case.to_string(), Vec::new()));
            }
            Some(_) if line == "end" => cases.push(open.take().unwrap()),
            Some((_, lines)) => {
                let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
                assert!(
                    allowed.contains(&word),
                    "{name}:{at}: not a directive: {line:?}"
                );
                lines.push((word.to_string(), rest.to_string()));
            }
        }
    }
    assert!(open.is_none(), "{name}: the last case has no `end`");
    assert!(!cases.is_empty(), "{name}: no cases");
    cases
}

/// The values of every `word` directive of a case.
fn all<'a>(lines: &'a [(String, String)], word: &str) -> Vec<&'a str> {
    lines
        .iter()
        .filter(|(w, _)| w == word)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
fn payload_gives_every_known_answer() {
    let text = include_str!("../tests/vectors/payload.txt");
    let words = [
        "tree", "gates", "platform", "input", "canon", "producer", "payload",
    ];
    for (name, lines) in vectors("payload.txt", text, &words) {
        let one = |w: &str| {
            let v = all(&lines, w);
            assert_eq!(v.len(), 1, "{name}: one `{w}`");
            v[0]
        };
        let inputs: Vec<(String, String)> = all(&lines, "input")
            .iter()
            .map(|i| {
                let (g, fp) = i.split_once(' ').expect("input <gate> <fp>");
                (g.to_string(), fp.to_string())
            })
            .collect();
        let canon = all(&lines, "canon");
        let want: String = all(&lines, "payload")
            .iter()
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(
            payload(
                one("tree"),
                one("gates"),
                one("platform"),
                &inputs,
                canon.first().copied(),
                one("producer")
            ),
            want,
            "{name}"
        );
    }
}

/// A scratch repository of `format`, for hashing.
fn hash_repo(format: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("git-attest-hash-{format}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    assert!(std::process::Command::new("git")
        .current_dir(&d)
        .args([
            "init",
            "-q",
            "--template=",
            &format!("--object-format={format}")
        ])
        .status()
        .unwrap()
        .success());
    d
}

#[test]
fn fingerprint_gives_every_known_answer() {
    let text = include_str!("../tests/vectors/fingerprint.txt");
    let repos = [("sha1", hash_repo("sha1")), ("sha256", hash_repo("sha256"))];
    let repo = |f: &str| {
        &repos
            .iter()
            .find(|(n, _)| *n == f)
            .expect("sha1 or sha256")
            .1
    };
    for (name, lines) in vectors(
        "fingerprint.txt",
        text,
        &["implicit", "key", "canon-key", "out"],
    ) {
        let out: Vec<String> = all(&lines, "out").iter().map(|s| s.to_string()).collect();
        let (word, args) = &lines[0];
        let a: Vec<&str> = args.split(' ').collect();
        let got = match word.as_str() {
            "implicit" => implicit_inputs(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "key" => vec![key(repo(a[0]), a[1], a[2]).unwrap()],
            "canon-key" => vec![canon_key(repo(a[0]), a[1]).unwrap()],
            other => panic!("{name}: a case opens with implicit, key or canon-key, not {other}"),
        };
        assert_eq!(got, out, "{name}");
    }
    for (_, d) in &repos {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn spec_gives_every_known_answer() {
    use crate::spec::Error as E;
    let text = include_str!("../tests/vectors/spec.txt");
    for (name, lines) in vectors("spec.txt", text, &["in", "gate", "exempt", "error"]) {
        let bytes: String = all(&lines, "in").iter().map(|l| format!("{l}\n")).collect();
        let got = parse_spec(bytes.as_bytes());
        match all(&lines, "error").first() {
            Some(want) => {
                let e = got.expect_err(&name);
                let (kind, line) = match &e {
                    E::Byte(_) => ("byte", None),
                    E::GateName { line, .. } => ("gate-name", Some(*line)),
                    E::Duplicate { line, .. } => ("duplicate", Some(*line)),
                    E::NoPaths { line, .. } => ("no-paths", Some(*line)),
                    E::Path { line, .. } => ("path", Some(*line)),
                    E::Directive { line, .. } => ("directive", Some(*line)),
                    other => panic!("{name}: no vector kind for {other:?}"),
                };
                let got = match line {
                    Some(l) => format!("{kind} {l}"),
                    None => kind.to_string(),
                };
                assert_eq!(got, *want, "{name}: {e}");
            }
            None => {
                let spec = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                let gates: Vec<String> = spec
                    .gates
                    .iter()
                    .map(|(g, p)| {
                        let paths: Vec<String> = p
                            .iter()
                            .map(|t| format!("{}{}", if t.optional { "?" } else { "" }, t.path))
                            .collect();
                        format!("{g} {}", paths.join(" "))
                    })
                    .collect();
                assert_eq!(gates, all(&lines, "gate"), "{name}");
                assert_eq!(
                    spec.plan_exempt_off,
                    !all(&lines, "exempt").is_empty(),
                    "{name}"
                );
            }
        }
    }
}

/// "No spec" and "git could not say" are different answers: only the first
/// opens the canonical route.
#[test]
fn a_tree_git_cannot_list_has_no_known_spec() {
    let repo = scratch_repo("unlisted");
    let bogus = "0123456789012345678901234567890123456789";
    assert_eq!(
        crate::spec::at(&repo, bogus).err(),
        Some(crate::spec::AtError::Unlisted)
    );
    assert!(plan_exempt(&repo, bogus).is_off(), "fails narrow");
    let mut log = Vec::new();
    let att = crate::produce::attestation(&repo, bogus, "lint", "p", "t", &mut log);
    assert_eq!(att.canon, None, "{log:?}");
    assert!(att.inputs.is_empty());
    let _ = std::fs::remove_dir_all(&repo);
}

/// A repository whose one commit tracks `files`, and that commit's tree.
fn committed(name: &str, files: &[(&str, &str)]) -> (std::path::PathBuf, String) {
    let d = std::env::temp_dir().join(format!("git-attest-cov-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for (path, body) in files {
        let p = d.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    std::fs::create_dir_all(&d).unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .current_dir(&d)
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q", "--template="]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "fixture"]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    (d, tree)
}

/// What `check_coverage` answers, rendered as the command line prints it.
enum Answer {
    Ok,
    /// Some gate falls short; the report contains each line, and none of
    /// the lines after `!`.
    Short(&'static [&'static str], &'static [&'static str]),
    /// The spec or git cannot answer; the error contains the text.
    Cannot(&'static str),
}

/// Every way a declaration can look complete and not be, through the
/// library's own entry point. These were amont's `attest check-inputs`
/// integration tests; the proof is attest's, so the cases live here
/// (decisions ADR-0037), and amont keeps only its wiring.
#[test]
fn check_coverage_answers_every_way_a_declaration_falls_short() {
    const SPEC: &str = ".github/attest-inputs";
    let cases: &[(&str, &[(&str, &str)], &[&str], Answer)] = &[
        (
            "a gate declaring every tracked file is covered",
            &[
                (SPEC, "g crates README.md\n"),
                ("crates/a/x.rs", "x"),
                ("README.md", "r"),
            ],
            &["g"],
            Answer::Ok,
        ),
        (
            "a subdirectory does not stand for its parent",
            &[
                (SPEC, "g crates/foo\n"),
                ("crates/foo/x.rs", "x"),
                ("crates/bar/y.rs", "y"),
            ],
            &["g"],
            Answer::Short(
                &["g: not covered:", "  crates/bar/y.rs"],
                &["  crates/foo/x.rs"],
            ),
        ),
        (
            "a path omitted from one gate is not rescued by another",
            &[
                (SPEC, "full a.txt b.txt\npartial a.txt\n"),
                ("a.txt", "a"),
                ("b.txt", "b"),
            ],
            &["full", "partial"],
            Answer::Short(
                &["partial: not covered:", "  b.txt"],
                &["full: not covered"],
            ),
        ),
        (
            "a required gate the spec does not declare fails",
            &[(SPEC, "g a.txt\n"), ("a.txt", "a")],
            &["g", "other"],
            Answer::Short(&["other: not declared in the spec"], &[]),
        ),
        (
            "plans are exempt but every other docs child is not",
            &[
                (SPEC, "g README.md\n"),
                ("README.md", "r"),
                ("docs/plans/p.md", "p"),
                ("docs/guide.md", "g"),
            ],
            &["g"],
            Answer::Short(&["  docs/guide.md"], &["docs/plans"]),
        ),
        (
            "the spec itself and the root git files need no declaration",
            &[
                (SPEC, "g a.txt\n"),
                ("a.txt", "a"),
                (".gitattributes", "* text=auto\n"),
                (".gitmodules", ""),
            ],
            &["g"],
            Answer::Ok,
        ),
        (
            "a name outside the grammar is covered by an ASCII ancestor",
            &[(SPEC, "g src\n"), ("src/caf\u{e9}.txt", "x")],
            &["g"],
            Answer::Ok,
        ),
        (
            "a name outside the grammar is not covered without one",
            &[
                (SPEC, "g src\n"),
                ("src/a.txt", "a"),
                ("caf\u{e9}.txt", "x"),
            ],
            &["g"],
            Answer::Short(&["g: not covered:", "caf"], &[]),
        ),
        (
            "an optional path counts as declared even when absent",
            &[(SPEC, "g a.txt ?build.rs\n"), ("a.txt", "a")],
            &["g"],
            Answer::Ok,
        ),
        (
            "a required path that is missing cannot be fingerprinted",
            &[(SPEC, "g a.txt nope\n"), ("a.txt", "a")],
            &["g"],
            Answer::Short(&["g: cannot be fingerprinted"], &[]),
        ),
        (
            "no spec cannot answer",
            &[("a.txt", "a")],
            &["g"],
            Answer::Cannot("no .forgejo/attest-inputs or"),
        ),
        (
            "a glob invalidates the whole spec",
            &[(SPEC, "g src/*\n"), ("a.txt", "a")],
            &["g"],
            Answer::Cannot("is invalid"),
        ),
        (
            "two specs cannot answer",
            &[
                (SPEC, "g a.txt\n"),
                (".forgejo/attest-inputs", "g a.txt\n"),
                ("a.txt", "a"),
            ],
            &["g"],
            Answer::Cannot("both"),
        ),
    ];
    for (i, (case, files, required, want)) in cases.iter().enumerate() {
        let (repo, tree) = committed(&format!("{i}"), files);
        let required: Vec<String> = required.iter().map(|g| g.to_string()).collect();
        match (check_coverage(&repo, &tree, &required), want) {
            (Ok(f), Answer::Ok) => assert!(f.is_empty(), "{case}:\n{}", f.render()),
            (Ok(f), Answer::Short(has, lacks)) => {
                let report = f.render();
                assert!(!f.is_empty(), "{case}: reported covered");
                for line in *has {
                    assert!(report.contains(line), "{case}: no {line:?} in\n{report}");
                }
                for line in *lacks {
                    assert!(!report.contains(line), "{case}: {line:?} in\n{report}");
                }
            }
            (Err(e), Answer::Cannot(text)) => {
                let said = e.render(&tree);
                assert!(said.contains(text), "{case}: no {text:?} in {said}");
            }
            (Ok(f), Answer::Cannot(_)) => panic!("{case}: answered\n{}", f.render()),
            (Err(e), _) => panic!("{case}: could not answer: {}", e.render(&tree)),
        }
        // The spec is read from the tree: a working copy claiming less
        // changes nothing.
        if matches!(want, Answer::Ok) {
            std::fs::write(repo.join(SPEC), "g\n").unwrap();
            let f = check_coverage(&repo, &tree, &required).unwrap();
            assert!(
                f.is_empty(),
                "{case}, after editing the working copy:\n{}",
                f.render()
            );
        }
        let _ = std::fs::remove_dir_all(&repo);
    }
}
