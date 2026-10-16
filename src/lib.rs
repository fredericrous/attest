//! `git-attest`: the one implementation of the attestation format (SPEC.md,
//! decisions ADR-0037). Producers and verifiers call this library; the
//! `git-attest` binary is a thin command line over it.
//!
//! Each module owns one piece of the format and hides it:
//!
//! - [`format`]: the payload's fields, a note's blocks, the shared names;
//! - [`spec`]: the `attest-inputs` declaration and the canonical opt-out;
//! - [`fingerprint`]: input fingerprints, the canonical tree, their note keys;
//! - [`sign`]: `ssh-keygen -Y`, for any namespace;
//! - [`notes`]: the notes refs as origin's mirror;
//! - [`verify`]: what a valid attestation covers.
//!
//! Every entry point takes the repository it acts on as a path and never
//! reads the process's working directory, and nothing here prints: callers
//! render what the library returns.
//!
//! No dependencies, and that is load-bearing (see Cargo.toml).

pub mod fingerprint;
pub mod format;
pub mod notes;
pub mod sign;
pub mod spec;
pub mod verify;

mod git;

#[cfg(test)]
mod tests;
