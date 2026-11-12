//! The two note-name sets, `greengate-attest` and the older `amont-attest`,
//! proven with real `ssh-keygen` keys and a real bare origin through the
//! verifier's entry point (SPEC.md, "Names").

use std::path::{Path, PathBuf};
use std::process::Command;

use git_attest::format::{self, Names, GREEN, LEGACY};
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
    /// A repository whose signers file lists `namespaces`, with an origin when
    /// `with_origin` is set.
    fn new(name: &str, namespaces: &str, with_origin: bool) -> Fixture {
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
        let origin = with_origin.then(|| {
            let o = dir.with_extension("origin.git");
            let _ = std::fs::remove_dir_all(&o); // as above
            run(&dir, "git", &["init", "-q", "--bare", o.to_str().unwrap()]);
            run(
                &dir,
                "git",
                &["remote", "add", "origin", o.to_str().unwrap()],
            );
            o
        });
        Fixture { dir, origin, tree }
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
        if let Some(o) = &self.origin {
            let _ = std::fs::remove_dir_all(o); // as above
        }
    }
}

fn gates(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
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
    let f = Fixture::new("green", BOTH, false);
    f.attest(&GREEN, "greengate-attest", "g-green");
    let v = f.verdict();
    assert_eq!(v.gates, gates(&["g-green"]));
    assert_eq!(v.verified_under, ["greengate-attest"]);
    assert!(v
        .trail
        .iter()
        .any(|l| l == "verified under greengate-attest"));
}

#[test]
fn an_amont_note_is_verified_and_named() {
    let f = Fixture::new("legacy", BOTH, false);
    f.attest(&LEGACY, "amont-attest", "g-legacy");
    let v = f.verdict();
    assert_eq!(v.gates, gates(&["g-legacy"]));
    assert_eq!(v.verified_under, ["amont-attest"]);
}

#[test]
fn the_greengate_ref_wins_when_both_exist() {
    let f = Fixture::new("both", BOTH, false);
    f.attest(&LEGACY, "amont-attest", "g-legacy");
    f.attest(&GREEN, "greengate-attest", "g-green");
    let v = f.verdict();
    assert_eq!(v.gates, gates(&["g-green"]));
    assert_eq!(v.verified_under, ["greengate-attest"]);
}

#[test]
fn a_note_that_fails_in_the_green_ref_is_not_rescued_by_the_legacy_ref() {
    let f = Fixture::new("norescue", BOTH, false);
    f.attest(&LEGACY, "amont-attest", "g-legacy");
    // Present in the green ref, signed by a key nobody listed.
    let block = f.block(
        "greengate-attest",
        "stranger",
        &f.payload(&GREEN, "g-green"),
    );
    f.note(GREEN.notes_ref, &f.tree, &block);
    assert!(f.covered().is_empty());
}

#[test]
fn an_old_header_block_is_refused_under_the_new_namespace() {
    // Old header, signed under the NEW namespace, in either ref.
    for notes_ref in [GREEN.notes_ref, LEGACY.notes_ref] {
        let f = Fixture::new("oldhdr-newns", BOTH, false);
        let block = f.block("greengate-attest", "key", &f.payload(&LEGACY, "g"));
        f.note(notes_ref, &f.tree, &block);
        assert!(f.covered().is_empty(), "{notes_ref}");
    }
}

#[test]
fn a_new_header_block_is_refused_under_the_old_namespace() {
    for notes_ref in [GREEN.notes_ref, LEGACY.notes_ref] {
        let f = Fixture::new("newhdr-oldns", BOTH, false);
        let block = f.block("amont-attest", "key", &f.payload(&GREEN, "g"));
        f.note(notes_ref, &f.tree, &block);
        assert!(f.covered().is_empty(), "{notes_ref}");
    }
}

#[test]
fn a_header_of_the_other_set_is_refused_even_when_correctly_signed() {
    // New header, new namespace, but in the LEGACY ref (and the reverse): the
    // ref decides the set, so the block is not read under the other one.
    let f = Fixture::new("crossref", BOTH, false);
    let block = f.block("greengate-attest", "key", &f.payload(&GREEN, "g"));
    f.note(LEGACY.notes_ref, &f.tree, &block);
    assert!(f.covered().is_empty());
    let f = Fixture::new("crossref2", BOTH, false);
    let block = f.block("amont-attest", "key", &f.payload(&LEGACY, "g"));
    f.note(GREEN.notes_ref, &f.tree, &block);
    assert!(f.covered().is_empty());
}

#[test]
fn a_signers_line_pinned_to_one_namespace_accepts_only_that_set() {
    let f = Fixture::new("pin-old", "amont-attest", false);
    f.attest(&GREEN, "greengate-attest", "g");
    assert!(f.covered().is_empty());
    let f = Fixture::new("pin-new", "greengate-attest", false);
    f.attest(&LEGACY, "amont-attest", "g");
    assert!(f.covered().is_empty());
}

#[test]
fn a_missing_old_ref_on_origin_leaves_the_verdict_unchanged() {
    let f = Fixture::new("noold", BOTH, true);
    f.attest(&GREEN, "greengate-attest", "g-green");
    f.publish_only(&["greengate-attest"]);
    let v = f.verdict();
    assert_eq!(v.gates, gates(&["g-green"]));
    // Origin answered: the absent set is absent, never "not judged".
    let (m, i) = v.legacy_notes.unwrap();
    assert_eq!((m.as_str(), i.as_str()), ("absent", "absent"));
    assert!(
        !v.trail.iter().any(|l| l.contains("running everything")),
        "{:?}",
        v.trail
    );
}

#[test]
fn a_missing_new_ref_on_origin_leaves_the_verdict_unchanged() {
    let f = Fixture::new("nonew", BOTH, true);
    f.attest(&LEGACY, "amont-attest", "g-legacy");
    f.publish_only(&["amont-attest"]);
    let v = f.verdict();
    assert_eq!(v.gates, gates(&["g-legacy"]));
    let (m, i) = v.notes.unwrap();
    assert_eq!((m.as_str(), i.as_str()), ("absent", "absent"));
    assert!(
        !v.trail.iter().any(|l| l.contains("running everything")),
        "{:?}",
        v.trail
    );
}

#[test]
fn the_green_ref_wins_on_origin_too() {
    let f = Fixture::new("originboth", BOTH, true);
    f.attest(&LEGACY, "amont-attest", "g-legacy");
    f.attest(&GREEN, "greengate-attest", "g-green");
    f.publish_only(&["amont-attest", "greengate-attest"]);
    assert_eq!(f.covered(), gates(&["g-green"]));
}

#[test]
fn a_local_mirror_origin_does_not_have_is_not_judged() {
    let f = Fixture::new("stale", BOTH, true);
    f.attest(&GREEN, "greengate-attest", "g-green");
    // Nothing published: origin has neither ref, so the local mirror is deleted.
    assert!(f.covered().is_empty());
}
