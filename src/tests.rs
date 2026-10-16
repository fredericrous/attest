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
