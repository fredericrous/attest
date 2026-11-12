//! The two note-name sets, `greengate-attest` and the older `amont-attest`,
//! proven with real `ssh-keygen` keys and a real bare origin through the
//! verifier's entry point (SPEC.md, "Names").

use std::path::{Path, PathBuf};
use std::process::Command;

use git_attest::format::{self, Names, GREEN, LEGACY, WRITE};
use git_attest::verify::{evaluate, Verdict};

fn run(dir: &Path, program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Fixture {
    dir: PathBuf,
    origin: Option<PathBuf>,
    tree: String,
}

impl Fixture {
    /// A repository whose signers file lists `namespaces`, with no origin: its
    /// local refs are judged as they are.
    fn local(name: &str, namespaces: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("attest-names-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // a leftover of an earlier run; absent is the normal case
        std::fs::create_dir_all(&dir).unwrap();
        run(
            &dir,
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", "key"],
        );
        run(
            &dir,
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", "stranger"],
        );
        let public = std::fs::read_to_string(dir.join("key.pub")).unwrap();
        std::fs::write(
            dir.join("allowed_signers"),
            format!("ci@example.org namespaces=\"{namespaces}\" {public}"),
        )
        .unwrap();
        run(&dir, "git", &["init", "-q", "--template="]);
        std::fs::write(dir.join("file.txt"), "content\n").unwrap();
        run(&dir, "git", &["add", "file.txt"]);
        run(
            &dir,
            "git",
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "init",
            ],
        );
        let tree = run(&dir, "git", &["rev-parse", "HEAD^{tree}"]);
        Fixture {
            dir,
            origin: None,
            tree,
        }
    }

    /// The same, with an empty bare repository as its origin.
    fn with_origin(name: &str, namespaces: &str) -> Fixture {
        let mut fixture = Fixture::local(name, namespaces);
        let origin = fixture.dir.with_extension("origin.git");
        let _ = std::fs::remove_dir_all(&origin); // a leftover of an earlier run
        let path = origin.to_str().unwrap();
        run(&fixture.dir, "git", &["init", "-q", "--bare", path]);
        run(&fixture.dir, "git", &["remote", "add", "origin", path]);
        fixture.origin = Some(origin);
        fixture
    }

    fn payload(&self, names: &Names, gates: &str) -> String {
        format!(
            "{}\ntree {}\ngates {gates}\nplatform x86_64-linux\n{} 1.0\n",
            names.format, self.tree, names.producer
        )
    }

    /// `payload` signed under `ns` with `key`, as a note block.
    fn block(&self, ns: &str, key: &str, payload: &str) -> String {
        std::fs::write(self.dir.join("payload"), payload).unwrap();
        let _ = std::fs::remove_file(self.dir.join("payload.sig")); // absent on the first call
        run(
            &self.dir,
            "ssh-keygen",
            &["-Y", "sign", "-n", ns, "-f", key, "payload"],
        );
        let sig = std::fs::read_to_string(self.dir.join("payload.sig")).unwrap();
        format!("{}\n\n{}", payload.trim_end(), sig.trim_end())
    }

    /// The note on `object` in `notes_ref`, replaced.
    fn note(&self, notes_ref: &str, object: &str, block: &str) {
        run(
            &self.dir,
            "git",
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "notes",
                "--ref",
                notes_ref,
                "add",
                "-f",
                "-m",
                block,
                object,
            ],
        );
    }

    /// A well-formed note of `names`' set on the tree, signed under `ns`.
    fn attest(&self, names: &Names, ns: &str, gates: &str) {
        let block = self.block(ns, "key", &self.payload(names, gates));
        self.note(names.notes_ref, &self.tree, &block);
    }

    /// Publish `refs` to origin and drop the local copies, so the verifier has
    /// to fetch them: origin's content is the only thing it can see.
    fn publish_only(&self, refs: &[&str]) {
        for r in refs {
            let spec = format!("refs/notes/{r}:refs/notes/{r}");
            run(&self.dir, "git", &["push", "-q", "origin", &spec]);
        }
        for r in refs {
            run(
                &self.dir,
                "git",
                &["update-ref", "-d", &format!("refs/notes/{r}")],
            );
        }
    }

    fn verdict(&self) -> Verdict {
        evaluate(
            &self.dir,
            &self.dir.join("allowed_signers"),
            None,
            Some("x86_64-linux"),
            &[],
            false,
        )
    }

    fn covered(&self) -> Vec<String> {
        self.verdict().gates
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir); // temp dir cleanup; a leftover is harmless
        if let Some(origin) = &self.origin {
            let _ = std::fs::remove_dir_all(origin); // as above
        }
    }
}

fn gates(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

const BOTH: &str = "amont-attest,greengate-attest";

/// Phase 1 must not let a dependent sign new names early: greengate signs with
/// these constants and links this crate by a caret pin.
#[test]
fn the_constants_still_equal_the_legacy_names() {
    assert_eq!(format::FORMAT, LEGACY.format);
    assert_eq!(format::NOTES_REF, LEGACY.notes_ref);
    assert_eq!(format::INPUTS_REF, LEGACY.inputs_ref);
    assert_eq!(format::NAMESPACE, LEGACY.namespace);
    assert_ne!(format::FORMAT, GREEN.format);
    assert_ne!(format::NAMESPACE, GREEN.namespace);
    assert_eq!(WRITE, LEGACY);
}

/// Everything written derives from `WRITE`, so Phase 4 is one line: the
/// set-less keys and the payload's producer word included.
#[test]
fn every_written_name_derives_from_write() {
    use git_attest::fingerprint::{canon_key, canon_key_in, key, key_in};
    let fixture = Fixture::local("write", BOTH);
    let fp = "a".repeat(40);
    assert_eq!(
        key(&fixture.dir, "ci-fmt", &fp),
        key_in(&fixture.dir, &WRITE, "ci-fmt", &fp)
    );
    assert_eq!(
        canon_key(&fixture.dir, &fp),
        canon_key_in(&fixture.dir, &WRITE, &fp)
    );
    let payload = format::payload("t", "g", "p", &[], None, "x");
    assert!(payload.starts_with(&format!("{}\n", WRITE.format)));
    assert!(payload.ends_with(&format!("\n{} x\n", WRITE.producer)));
}

#[test]
fn the_two_sets_spell_every_name() {
    assert_eq!(GREEN.format, "greengate-attest-v2");
    assert_eq!(GREEN.notes_ref, "greengate-attest");
    assert_eq!(GREEN.inputs_ref, "greengate-attest-inputs");
    assert_eq!(GREEN.namespace, "greengate-attest");
    assert_eq!(GREEN.input_domain, "greengate-attest-input");
    assert_eq!(GREEN.canon_domain, "greengate-attest-canon");
    assert_eq!(GREEN.producer, "greengate");
    assert_eq!(LEGACY.format, "amont-attest-v2");
    assert_eq!(LEGACY.notes_ref, "amont-attest");
    assert_eq!(LEGACY.inputs_ref, "amont-attest-inputs");
    assert_eq!(LEGACY.namespace, "amont-attest");
    assert_eq!(LEGACY.input_domain, "amont-attest-input");
    assert_eq!(LEGACY.canon_domain, "amont-attest-canon");
    assert_eq!(LEGACY.producer, "amont");
}

#[test]
fn each_set_keys_its_lookups_under_its_own_domain() {
    use git_attest::fingerprint::{
        canon_key_preimage, canon_key_preimage_in, key_preimage, key_preimage_in,
    };
    assert_eq!(
        key_preimage_in(&GREEN, "ci-fmt", "abc"),
        "greengate-attest-input ci-fmt abc\n"
    );
    assert_eq!(
        canon_key_preimage_in(&GREEN, "abc"),
        "greengate-attest-canon abc\n"
    );
    // The old signatures keep meaning LEGACY.
    assert_eq!(
        key_preimage("ci-fmt", "abc"),
        key_preimage_in(&LEGACY, "ci-fmt", "abc")
    );
    assert_eq!(
        canon_key_preimage("abc"),
        canon_key_preimage_in(&LEGACY, "abc")
    );
}

#[test]
fn a_greengate_note_is_verified_and_named() {
    let fixture = Fixture::local("green", BOTH);
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    let verdict = fixture.verdict();
    assert_eq!(verdict.gates, gates(&["g-green"]));
    assert_eq!(verdict.verified_under, ["greengate-attest"]);
}

/// A valid signature on a block that covers nothing (another tree) is not
/// counted: the line says a skip was earned under that name.
#[test]
fn a_valid_block_that_covers_nothing_is_not_named() {
    let fixture = Fixture::local("nocover", BOTH);
    let payload = fixture
        .payload(&GREEN, "g")
        .replace(&fixture.tree, &"0".repeat(40));
    let block = fixture.block("greengate-attest", "key", &payload);
    fixture.note(GREEN.notes_ref, &fixture.tree, &block);
    let verdict = fixture.verdict();
    assert!(verdict.gates.is_empty());
    assert!(verdict.verified_under.is_empty());
}

/// A note `notes list` finds but `notes show` cannot read is still a note:
/// the legacy ref is not read for that object, and the trail says why.
#[test]
fn an_unreadable_green_note_does_not_fall_back_to_legacy() {
    let fixture = Fixture::local("unreadable", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    let listing = run(
        &fixture.dir,
        "git",
        &["notes", "--ref", GREEN.notes_ref, "list", &fixture.tree],
    );
    let blob = listing.split_whitespace().next().unwrap().to_string();
    let object = fixture
        .dir
        .join(".git/objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    std::fs::remove_file(&object).unwrap();
    let verdict = fixture.verdict();
    assert!(verdict.gates.is_empty(), "{:?}", verdict.gates);
    assert!(
        verdict
            .trail
            .iter()
            .any(|l| l.starts_with("cannot read the note on ")),
        "{:?}",
        verdict.trail
    );
}

#[test]
fn an_amont_note_is_verified_and_named() {
    let fixture = Fixture::local("legacy", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    let verdict = fixture.verdict();
    assert_eq!(verdict.gates, gates(&["g-legacy"]));
    assert_eq!(verdict.verified_under, ["amont-attest"]);
}

#[test]
fn the_greengate_ref_wins_when_both_exist() {
    let fixture = Fixture::local("both", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    let verdict = fixture.verdict();
    assert_eq!(verdict.gates, gates(&["g-green"]));
    assert_eq!(verdict.verified_under, ["greengate-attest"]);
}

#[test]
fn a_note_that_fails_in_the_green_ref_is_not_rescued_by_the_legacy_ref() {
    let fixture = Fixture::local("norescue", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    // Present in the green ref, signed by a key nobody listed.
    let block = fixture.block(
        "greengate-attest",
        "stranger",
        &fixture.payload(&GREEN, "g-green"),
    );
    fixture.note(GREEN.notes_ref, &fixture.tree, &block);
    assert!(fixture.covered().is_empty());
}

#[test]
fn an_old_header_block_is_refused_under_the_new_namespace() {
    // Old header, signed under the NEW namespace, in either ref.
    for notes_ref in [GREEN.notes_ref, LEGACY.notes_ref] {
        let fixture = Fixture::local("oldhdr-newns", BOTH);
        let block = fixture.block("greengate-attest", "key", &fixture.payload(&LEGACY, "g"));
        fixture.note(notes_ref, &fixture.tree, &block);
        assert!(fixture.covered().is_empty(), "{notes_ref}");
    }
}

#[test]
fn a_new_header_block_is_refused_under_the_old_namespace() {
    for notes_ref in [GREEN.notes_ref, LEGACY.notes_ref] {
        let fixture = Fixture::local("newhdr-oldns", BOTH);
        let block = fixture.block("amont-attest", "key", &fixture.payload(&GREEN, "g"));
        fixture.note(notes_ref, &fixture.tree, &block);
        assert!(fixture.covered().is_empty(), "{notes_ref}");
    }
}

#[test]
fn a_header_of_the_other_set_is_refused_even_when_correctly_signed() {
    // New header, new namespace, but in the LEGACY ref (and the reverse): the
    // ref decides the set, so the block is not read under the other one.
    let fixture = Fixture::local("crossref", BOTH);
    let block = fixture.block("greengate-attest", "key", &fixture.payload(&GREEN, "g"));
    fixture.note(LEGACY.notes_ref, &fixture.tree, &block);
    assert!(fixture.covered().is_empty());
    let fixture = Fixture::local("crossref2", BOTH);
    let block = fixture.block("amont-attest", "key", &fixture.payload(&LEGACY, "g"));
    fixture.note(GREEN.notes_ref, &fixture.tree, &block);
    assert!(fixture.covered().is_empty());
}

#[test]
fn a_signers_line_pinned_to_one_namespace_accepts_only_that_set() {
    let fixture = Fixture::local("pin-old", "amont-attest");
    fixture.attest(&GREEN, "greengate-attest", "g");
    assert!(fixture.covered().is_empty());
    let fixture = Fixture::local("pin-new", "greengate-attest");
    fixture.attest(&LEGACY, "amont-attest", "g");
    assert!(fixture.covered().is_empty());
}

#[test]
fn a_missing_old_ref_on_origin_leaves_the_verdict_unchanged() {
    let fixture = Fixture::with_origin("noold", BOTH);
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    fixture.publish_only(&["greengate-attest"]);
    let verdict = fixture.verdict();
    assert_eq!(verdict.gates, gates(&["g-green"]));
    // Origin answered: the absent set is absent, never "not judged".
    let (m, i) = verdict.legacy_notes.unwrap();
    assert_eq!((m.as_str(), i.as_str()), ("absent", "absent"));
    assert!(
        !verdict
            .trail
            .iter()
            .any(|l| l.contains("running everything")),
        "{:?}",
        verdict.trail
    );
}

#[test]
fn a_missing_new_ref_on_origin_leaves_the_verdict_unchanged() {
    let fixture = Fixture::with_origin("nonew", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    fixture.publish_only(&["amont-attest"]);
    let verdict = fixture.verdict();
    assert_eq!(verdict.gates, gates(&["g-legacy"]));
    let (m, i) = verdict.notes.unwrap();
    assert_eq!((m.as_str(), i.as_str()), ("absent", "absent"));
    assert!(
        !verdict
            .trail
            .iter()
            .any(|l| l.contains("running everything")),
        "{:?}",
        verdict.trail
    );
}

#[test]
fn the_green_ref_wins_on_origin_too() {
    let fixture = Fixture::with_origin("originboth", BOTH);
    fixture.attest(&LEGACY, "amont-attest", "g-legacy");
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    fixture.publish_only(&["amont-attest", "greengate-attest"]);
    assert_eq!(fixture.covered(), gates(&["g-green"]));
}

#[test]
fn a_local_mirror_origin_does_not_have_is_not_judged() {
    let fixture = Fixture::with_origin("stale", BOTH);
    fixture.attest(&GREEN, "greengate-attest", "g-green");
    // Nothing published: origin has neither ref, so the local mirror is deleted.
    assert!(fixture.covered().is_empty());
}
