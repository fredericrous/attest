//! Just enough git to read notes and resolve objects.
//!
//! Subprocesses rather than a git library, for the same reason the signing
//! side shells out to `ssh-keygen`: the answer must be the one the user's own
//! `git` gives, including their config, their `core.notesRef`, and whatever
//! version their runner ships.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Stdout of `git <args>`, trimmed. `None` when git is missing, or exits
/// non-zero, or wrote nothing — three failures with one correct response
/// ("no answer"), which is why they collapse here rather than at each site.
pub fn stdout(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Did `git <args>` exit 0? Output discarded.
pub fn succeeds(args: &[&str]) -> bool {
    exit_code(args) == Some(0)
}

/// The same, run inside `dir`.
pub fn succeeds_in(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The exit code of `git <args>`, output discarded. `None` when git could not
/// be run at all or was killed by a signal.
pub fn exit_code(args: &[&str]) -> Option<i32> {
    Command::new("git")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?
        .code()
}

/// The raw, untrimmed stdout of `git <args>` run inside `dir`. `None` unless
/// git exited 0 — including when it wrote output first and failed after,
/// because a partial `ls-tree` listing must never become a fingerprint.
pub fn stdout_bytes_in(dir: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// `git <args>` inside `dir` with `input` on its stdin; stdout trimmed;
/// `None` unless git exited 0. The input is written whole before the output
/// is read, which is fine for the two callers (`hash-object --stdin` answers
/// after EOF, `cat-file --batch-check` answers a line per name and never has
/// more than a few kilobytes to say).
pub fn stdout_with_input_in(dir: &Path, args: &[&str], input: &[u8]) -> Option<String> {
    let mut child = Command::new("git")
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(input).ok()?;
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `git <args>` against a REMOTE: never a prompt, never an unbounded wait.
///
/// A verifier that asks for a password, or hangs on a host that drops
/// packets, has broken "exit 0, always" as surely as a crash. So: no
/// terminal prompt, stdin closed, ssh in batch mode with a connect timeout
/// unless the user configured their own ssh command, curl's low-speed limit
/// for a stalled https transfer, and a deadline of our own on top, because
/// curl's limit only starts once a connection is up. Returns the exit code
/// and stdout; `None` when git could not run, was killed, or ran out of time.
pub fn remote(args: &[&str]) -> Option<(i32, String)> {
    use std::time::{Duration, Instant};
    let mut cmd = Command::new("git");
    cmd.args(["-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=10"])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let own_ssh = std::env::var_os("GIT_SSH_COMMAND").is_some_and(|v| !v.is_empty())
        || succeeds(&["config", "--get", "core.sshCommand"]);
    if !own_ssh {
        cmd.env(
            "GIT_SSH_COMMAND",
            "ssh -o BatchMode=yes -o ConnectTimeout=10",
        );
    }
    let mut child = cmd.spawn().ok()?;
    // The output is small (an ls-remote of two refs); read it on a thread so
    // a full pipe can never stall the child while we wait on the deadline.
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut out, &mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let stdout = reader.join().ok()?;
    Some((status.code()?, String::from_utf8_lossy(&stdout).to_string()))
}
