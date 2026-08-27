//! Just enough git to read notes and resolve objects.
//!
//! Subprocesses rather than a git library, for the same reason the signing
//! side shells out to `ssh-keygen`: the answer must be the one the user's own
//! `git` gives, including their config, their `core.notesRef`, and whatever
//! version their runner ships.

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
    Command::new("git")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
