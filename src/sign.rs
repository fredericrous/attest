//! `ssh-keygen -Y`: the one place a signature is made or checked. The
//! namespace is a parameter, so a provenance signature and an attestation can
//! never be confused (SPEC.md, "amont-provenance-v1").

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The armored signature as a file, because `ssh-keygen -Y` takes it no other
/// way. Removed on drop, so no early return below can leak it.
struct SigFile(PathBuf);

impl SigFile {
    fn new(sig: &str) -> Option<Self> {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "attest-verify-{}-{:p}.sig",
            std::process::id(),
            &sig
        ));
        // `create_new` refuses an existing path, symlink included, rather than
        // following it — the temp dir is shared with every other process.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .ok()?;
        f.write_all(sig.as_bytes()).ok()?;
        if !sig.ends_with('\n') {
            f.write_all(b"\n").ok()?;
        }
        Some(SigFile(path))
    }
}

impl Drop for SigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// WHO signed, read from the signature and the file rather than guessed.
///
/// `ssh-keygen -Y verify` requires a principal and checks it against the
/// principal column, so a guessed one rejects a perfectly good signature —
/// quietly, since every rejection means "run the tests". The templates this
/// replaced hardcoded `-I you@example.com`; the first release guessed the
/// file's first entry, which silently uncovered every other signer on a team.
/// `find-principals` answers from the key that actually signed.
fn find_principal(sig_file: &Path, allowed_signers: &Path) -> Option<String> {
    let out = Command::new("ssh-keygen")
        .args(["-Y", "find-principals", "-s"])
        .arg(sig_file)
        .arg("-f")
        .arg(allowed_signers)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Why a signature was not accepted. `Display` is the reason the verifier
/// reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The signature could not be handed to `ssh-keygen`.
    TempFile,
    /// No key in the signers file made it.
    UnknownSigner { signers: PathBuf },
    /// `ssh-keygen -Y verify` refused it.
    DoesNotVerify { signer: String, signers: PathBuf },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TempFile => write!(f, "cannot create a temporary file for the signature"),
            Error::UnknownSigner { signers } => write!(
                f,
                "signature was not made by any key in {}",
                signers.display()
            ),
            Error::DoesNotVerify { signer, signers } => write!(
                f,
                "signature does not verify as {signer} against {}",
                signers.display()
            ),
        }
    }
}

impl std::error::Error for Error {}

/// `ssh-keygen -Y verify` over the exact signed bytes, in `namespace`, as
/// `principal` — or, when none is given, as whoever the signature says. `Ok`
/// carries the identity the signature verified as.
pub fn verify(
    namespace: &str,
    payload: &str,
    sig: &str,
    allowed_signers: &Path,
    principal: Option<&str>,
) -> Result<String, Error> {
    use std::io::Write;
    let Some(sig_file) = SigFile::new(sig) else {
        return Err(Error::TempFile);
    };
    let signer = match principal {
        Some(p) => p.to_string(),
        None => {
            find_principal(&sig_file.0, allowed_signers).ok_or_else(|| Error::UnknownSigner {
                signers: allowed_signers.to_path_buf(),
            })?
        }
    };
    let ok = (|| {
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-n", namespace, "-I", &signer, "-f"])
            .arg(allowed_signers)
            .arg("-s")
            .arg(&sig_file.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(payload.as_bytes()).ok()?;
        child.wait().ok().map(|s| s.success())
    })()
    .unwrap_or(false);
    if ok {
        Ok(signer)
    } else {
        Err(Error::DoesNotVerify {
            signer,
            signers: allowed_signers.to_path_buf(),
        })
    }
}
