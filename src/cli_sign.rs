//! `git-attest sign`: attest, from CI, the gates that just passed on the tree
//! checked out here. The same flags, outputs and exit contract as
//! `sign/sign.sh`, which it replaces; `tests/sign.sh` runs against both.
//!
//! EXIT 0 ALWAYS, whatever happened: no key (a fork PR has no secrets), a
//! push refused, a key that will not load. Signing is an accelerator for the
//! NEXT run and must never fail THIS one. Exit 2 only for a usage error.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use git_attest::format::{block, platform, INPUTS_REF, LOCAL_PREFIX, NAMESPACE, NOTES_REF};
use git_attest::notes::{publish, publish_local, Publish, Published};
use git_attest::produce::{attestation, gate_list};
use git_attest::sign::{public_key, sign, Error as SignError};

pub const USAGE: &str = "\
git-attest sign — attest the gates that just passed on the tree checked out here

  git-attest sign --gates \"NAMES\" [--platform P] [--object REV] [--remote NAME]
                  [--producer NAME] [--attempts N] [--no-push] [--allow-dirty]
                  [--github-output] [--quiet]        < private-key

  Signs an amont-attest-v2 block over HEAD's tree, APPENDS it to the note on
  that tree in refs/notes/amont-attest, and pushes the ref. With --no-push the
  block goes to refs/notes/attest-local/amont-attest instead.

  The private key arrives on STDIN and nowhere else, never argv. ed25519 only.

  Exit 0 always; 2 only for a usage error (an unknown flag, --gates absent, a
  key on a terminal, an --object whose tree is not HEAD's). With
  --github-output, five lines go to stdout:

    status=<token>   pushed local already-present no-key bad-key no-gates
                     dirty sign-failed push-failed error
    signed=<bool>    a new block for this tree exists locally after this run
    pushed=<bool>    the remote holds a block for these gates
    gates=<names>    the normalised list that was (or would have been) signed
    inputs=<p>/<w>   input fingerprints published / declared among the gates

  Refuses to sign a working tree with modified or untracked files
  (--allow-dirty overrides), and an empty gate list.
";

struct Opts {
    gates: String,
    platform: Option<String>,
    object: Option<String>,
    remote: String,
    producer: String,
    attempts: u32,
    push: bool,
    allow_dirty: bool,
    gha: bool,
    quiet: bool,
}

/// The flags, refused rather than skipped when unknown.
fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        gates: String::new(),
        platform: None,
        object: None,
        remote: "origin".into(),
        producer: "attest-sign".into(),
        attempts: 5,
        push: true,
        allow_dirty: false,
        gha: false,
        quiet: false,
    };
    let mut have_gates = false;
    let mut attempts = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a {
            "--gates" => {
                o.gates = value()?;
                have_gates = true;
            }
            "--platform" => o.platform = Some(value()?).filter(|v| !v.is_empty()),
            "--object" => o.object = Some(value()?).filter(|v| !v.is_empty()),
            "--remote" => o.remote = value()?,
            "--producer" => o.producer = value()?,
            "--attempts" => attempts = Some(value()?),
            "--no-push" => o.push = false,
            "--allow-dirty" => o.allow_dirty = true,
            "--github-output" => o.gha = true,
            "--quiet" => o.quiet = true,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    if !have_gates {
        return Err("--gates is required".into());
    }
    if let Some(n) = attempts {
        o.attempts = n
            .parse()
            .ok()
            .filter(|_| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .ok_or("--attempts wants a number")?;
    }
    Ok(o)
}

/// What one run reports.
struct Report<'a> {
    o: &'a Opts,
    gates: String,
    inputs_wanted: usize,
    inputs_published: usize,
}

impl Report<'_> {
    fn say(&self, line: &str) {
        if !self.o.quiet {
            eprintln!("attest-sign: {line}");
        }
    }

    /// The ONE exit for every outcome: the five output lines, then 0.
    fn finish(&self, status: &str, signed: bool, pushed: bool) -> u8 {
        if self.o.gha {
            println!("status={status}");
            println!("signed={signed}");
            println!("pushed={pushed}");
            println!("gates={}", self.gates);
            println!("inputs={}/{}", self.inputs_published, self.inputs_wanted);
        }
        0
    }
}

/// A private directory that goes away on every exit.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Option<Self> {
        let base = std::env::var_os("RUNNER_TEMP")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = base.join(format!("attest-sign-{}-{nonce}", std::process::id()));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&dir).ok()?;
        Some(TempDir(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write the key, as OpenSSH wants it: no CR (a pasted secret routinely
/// carries them), a final newline, mode 0600.
fn write_key(dir: &Path, key: &[u8]) -> Option<PathBuf> {
    let path = dir.join("key");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&path).ok()?;
    let clean: Vec<u8> = key.iter().copied().filter(|&b| b != b'\r').collect();
    f.write_all(&clean).ok()?;
    if !clean.ends_with(b"\n") {
        f.write_all(b"\n").ok()?;
    }
    Some(path)
}

/// The public half, with the one retry Windows needs: OpenSSH there judges a
/// key file by its ACL, which a fresh file in the temp dir may not satisfy.
fn load_public(key: &Path) -> Result<String, SignError> {
    let first = public_key(key);
    #[cfg(windows)]
    if matches!(first, Err(SignError::KeyUnusable)) {
        let user = std::env::var("USERNAME").unwrap_or_default();
        let _ = std::process::Command::new("icacls")
            .arg(key)
            .args(["/inheritance:r", "/grant:r", &format!("{user}:R")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        return public_key(key);
    }
    first
}

fn git_out(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn run(args: &[String]) -> u8 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return 0;
    }
    let o = match parse(args) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("git-attest sign: {m}");
            return 2;
        }
    };
    if std::io::stdin().is_terminal() {
        eprintln!("git-attest sign: the private key is read from stdin, which is a terminal; pipe or redirect it");
        return 2;
    }
    let producer = match gate_list(&o.producer) {
        p if p.is_empty() => "attest-sign".to_string(),
        p => p,
    };
    let mut r = Report {
        o: &o,
        gates: gate_list(&o.gates),
        inputs_wanted: 0,
        inputs_published: 0,
    };

    let Some(tmp) = TempDir::new() else {
        r.say("cannot create a temporary directory");
        return r.finish("error", false, false);
    };
    let mut key = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut key);
    if key.iter().all(|&b| b == b'\r') {
        r.say("no signing key on stdin (a fork PR has no secrets) — nothing signed");
        return r.finish("no-key", false, false);
    }
    let Some(key) = write_key(&tmp.0, &key) else {
        r.say("cannot create a temporary directory");
        return r.finish("error", false, false);
    };
    if let Err(why) = load_public(&key) {
        r.say(&why.to_string());
        return r.finish("bad-key", false, false);
    }

    if r.gates.is_empty() {
        r.say("no gates to sign");
        return r.finish("no-gates", false, false);
    }

    let here = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(root) = git_out(&here, &["rev-parse", "--show-toplevel"]).map(PathBuf::from) else {
        r.say("not a git repository");
        return r.finish("error", false, false);
    };
    let Some(head_tree) = git_out(&root, &["rev-parse", "HEAD^{tree}"]) else {
        r.say("cannot resolve HEAD^{tree}");
        return r.finish("error", false, false);
    };

    // What the note attaches to: HEAD's tree by default, or a REV whose tree
    // IS HEAD's tree. Anything else would sign content the checks never saw.
    let object = o.object.clone().unwrap_or_else(|| head_tree.clone());
    let Some(object_oid) = git_out(&here, &["rev-parse", "--verify", "--quiet", &object]) else {
        eprintln!("git-attest sign: --object {object} does not name an object");
        return 2;
    };
    let Some(object_tree) = git_out(
        &here,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{object}^{{tree}}"),
        ],
    ) else {
        eprintln!("git-attest sign: --object {object} has no tree");
        return 2;
    };
    if object_tree != head_tree {
        eprintln!("git-attest sign: --object {object} has tree {object_tree}, but the checks ran on HEAD^{{tree}} {head_tree}; only that tree may be signed");
        return 2;
    }

    // The honesty guard. Modified OR untracked (non-ignored) files mean the
    // checks ran on something other than HEAD^{tree}; ignored build output
    // does not. A status that FAILS is a tree nobody can vouch for.
    let status = std::process::Command::new("git")
        .current_dir(&root)
        .args([
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    match status {
        Ok(out) if out.status.success() => {
            if !o.allow_dirty && !out.stdout.is_empty() {
                r.say("the working tree has modified or untracked files, so the checks did not run on HEAD^{tree} alone; refusing to sign (--allow-dirty overrides)");
                return r.finish("dirty", false, false);
            }
        }
        _ => {
            r.say("git status failed; cannot tell whether the checks ran on HEAD^{tree}; refusing to sign");
            return r.finish("error", false, false);
        }
    }

    let platform = o.platform.clone().unwrap_or_else(platform);
    let mut log = Vec::new();
    let att = attestation(
        &root,
        &object_tree,
        &r.gates,
        &platform,
        &producer,
        &mut log,
    );
    for line in log.drain(..) {
        r.say(&line);
    }
    r.inputs_wanted = att.inputs.len();

    let Ok(sig) = sign(NAMESPACE, &att.payload, &key) else {
        r.say("ssh-keygen could not sign");
        return r.finish("sign-failed", false, false);
    };
    let body = block(&att.payload, &sig);
    let actor = std::env::var("GITHUB_ACTOR")
        .ok()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "attest-sign".into());
    let email = format!("{actor}@users.noreply.github.com");
    let identity = Some((actor.as_str(), email.as_str()));
    let main_items = vec![(object_oid, body.clone())];
    let input_items: Vec<(String, String)> = att
        .input_keys
        .iter()
        .map(|k| (k.clone(), body.clone()))
        .collect();

    if !o.push {
        let main = publish_local(
            &root,
            identity,
            &format!("{LOCAL_PREFIX}{NOTES_REF}"),
            &main_items,
        );
        if !input_items.is_empty() {
            let inputs = publish_local(
                &root,
                identity,
                &format!("{LOCAL_PREFIX}{INPUTS_REF}"),
                &input_items,
            );
            if inputs != Published::Error {
                r.inputs_published = r.inputs_wanted;
            }
        }
        return match main {
            Published::Error => {
                r.say("cannot write the note");
                r.finish("error", false, false)
            }
            Published::AlreadyPresent => {
                r.say("an identical block is already attached");
                r.finish("already-present", false, false)
            }
            _ => {
                r.say(&format!("signed, not pushed: {} on {platform}", r.gates));
                r.finish("local", true, false)
            }
        };
    }

    let how = Publish {
        remote: &o.remote,
        attempts: o.attempts,
        pause: true,
        identity,
        push_env: &[],
    };
    let main = publish(&root, &how, NOTES_REF, &main_items, &mut log);
    for line in log.drain(..) {
        r.say(&line);
    }
    if !input_items.is_empty() {
        let inputs = publish(&root, &how, INPUTS_REF, &input_items, &mut log);
        for line in log.drain(..) {
            r.say(&line);
        }
        match inputs {
            Published::Pushed | Published::AlreadyPresent => {
                r.inputs_published = r.inputs_wanted;
            }
            _ => r.say("the input fingerprints were not published; the next run will retry"),
        }
    }
    match main {
        Published::Pushed => {
            r.say(&format!("signed and pushed: {} on {platform}", r.gates));
            r.finish("pushed", true, true)
        }
        Published::AlreadyPresent => {
            r.say(&format!("an identical block is already on {}", o.remote));
            r.finish("already-present", false, true)
        }
        Published::PushFailed => r.finish("push-failed", false, false),
        _ => {
            r.say("cannot write the note");
            r.finish("error", false, false)
        }
    }
}
