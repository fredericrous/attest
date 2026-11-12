//! A platform-bound signer principal may sign only its own platform, proven
//! with real `ssh-keygen` keys through the verifier's entry point.

use std::path::{Path, PathBuf};
use std::process::Command;

use git_attest::verify::evaluate;

fn run(dir: &Path, program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{program} {args:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Fixture {
    dir: PathBuf,
    tree: String,
}

impl Fixture {
    fn new(name: &str, principal: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("attest-bound-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // a leftover from an earlier run; absent is the normal case
        std::fs::create_dir_all(&dir).unwrap();
        run(
            &dir,
            "ssh-keygen",
            &["-q", "-t", "ed25519", "-N", "", "-f", "key"],
        );
        let public = std::fs::read_to_string(dir.join("key.pub")).unwrap();
        std::fs::write(
            dir.join("allowed_signers"),
            format!("{principal} namespaces=\"amont-attest\" {public}"),
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
        Fixture { dir, tree }
    }

    fn attest(&self, platform: &str) {
        self.attest_payload(&format!("platform {platform}\n"));
    }

    fn attest_payload(&self, platform_line: &str) {
        let payload = format!(
            "amont-attest-v2\ntree {}\ngates test lint\n{platform_line}",
            self.tree
        );
        std::fs::write(self.dir.join("payload"), &payload).unwrap();
        run(
            &self.dir,
            "ssh-keygen",
            &["-Y", "sign", "-n", "amont-attest", "-f", "key", "payload"],
        );
        let signature = std::fs::read_to_string(self.dir.join("payload.sig")).unwrap();
        let note = format!("{payload}\n{}", signature.trim_end());
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
                "amont-attest",
                "add",
                "-f",
                "-m",
                &note,
                &self.tree,
            ],
        );
    }

    fn covered(&self, require: Option<&str>, anywhere: &[&str]) -> (Vec<String>, String) {
        self.covered_as(None, require, anywhere)
    }

    fn covered_as(
        &self,
        principal: Option<&str>,
        require: Option<&str>,
        anywhere: &[&str],
    ) -> (Vec<String>, String) {
        let anywhere: Vec<String> = anywhere.iter().map(|g| g.to_string()).collect();
        let verdict = evaluate(
            &self.dir,
            &self.dir.join("allowed_signers"),
            principal,
            require,
            &anywhere,
            true,
        );
        (verdict.gates, verdict.trail.join("\n"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir); // temp dir cleanup; a leftover is harmless
    }
}

const REFUSAL: &str =
    "cluster-signer@x86_64-linux may sign only x86_64-linux blocks; this block is aarch64-macos";

#[test]
fn a_bound_principal_covers_its_own_platform() {
    let f = Fixture::new("own", "cluster-signer@x86_64-linux");
    f.attest("x86_64-linux");
    let (gates, trail) = f.covered(None, &[]);
    assert_eq!(gates, ["test", "lint"], "{trail}");
}

#[test]
fn a_bound_principal_covers_nothing_on_another_platform() {
    let f = Fixture::new("other", "cluster-signer@x86_64-linux");
    f.attest("aarch64-macos");
    let (gates, trail) = f.covered(None, &[]);
    assert!(gates.is_empty(), "{trail}");
    assert!(trail.contains(REFUSAL), "{trail}");
}

#[test]
fn the_anywhere_list_does_not_admit_a_refused_block() {
    let f = Fixture::new("anywhere", "cluster-signer@x86_64-linux");
    f.attest("aarch64-macos");
    let (gates, trail) = f.covered(Some("x86_64-linux"), &["lint"]);
    assert!(gates.is_empty(), "{trail}");
    assert!(trail.contains(REFUSAL), "{trail}");
}

#[test]
fn an_unbound_principal_is_unchanged() {
    let f = Fixture::new("unbound", "dev@example.org");
    f.attest("aarch64-macos");
    let (gates, trail) = f.covered(None, &[]);
    assert_eq!(gates, ["test", "lint"], "{trail}");
}

#[test]
fn a_bound_signer_with_no_platform_line_covers_nothing() {
    let f = Fixture::new("noplatform", "cluster-signer@x86_64-linux");
    f.attest_payload("");
    let (gates, trail) = f.covered(None, &[]);
    assert!(gates.is_empty(), "{trail}");
    assert!(trail.contains("missing a required field"), "{trail}");
}

#[test]
fn the_refusal_for_a_block_with_no_platform_reads_names_no_platform() {
    let refusal = git_attest::sign::Error::PlatformBound {
        signer: "cluster-signer@x86_64-linux".to_string(),
        bound: "x86_64-linux".to_string(),
        platform: None,
    };
    assert_eq!(
        refusal.to_string(),
        "cluster-signer@x86_64-linux may sign only x86_64-linux blocks; this block names no platform"
    );
}

#[test]
fn an_explicit_bound_principal_is_checked() {
    let f = Fixture::new("explicit", "cluster-signer@x86_64-linux");
    f.attest("aarch64-macos");
    let (gates, trail) = f.covered_as(Some("cluster-signer@x86_64-linux"), None, &[]);
    assert!(gates.is_empty(), "{trail}");
    assert!(trail.contains(REFUSAL), "{trail}");
    let matching = Fixture::new("explicit-ok", "cluster-signer@x86_64-linux");
    matching.attest("x86_64-linux");
    let (gates, trail) = matching.covered_as(Some("cluster-signer@x86_64-linux"), None, &[]);
    assert_eq!(gates, ["test", "lint"], "{trail}");
}

#[test]
fn every_principal_of_the_key_is_checked() {
    // One allowed_signers line listing both principals: ssh-keygen answers
    // with each of them, the unbound one first.
    let f = Fixture::new("both", "dev@example.org,cluster-signer@x86_64-linux");
    f.attest("aarch64-macos");
    let (gates, trail) = f.covered(None, &[]);
    assert!(gates.is_empty(), "{trail}");
    assert!(trail.contains(REFUSAL), "{trail}");
}
