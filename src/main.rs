//! `git-attest` — read the attestation covering the tree checked out here.
//!
//! The actions in this repository run `verify.sh`, which needs nothing but
//! `git` and `ssh-keygen`. This binary is the same contract for everywhere
//! else: CI that is neither GitHub nor Forgejo, and a laptop asking why a skip
//! did not happen.

mod attest;
mod git;

use std::path::PathBuf;

const USAGE: &str = "\
git-attest — what a signed attestation covers for the tree checked out here

  git-attest covered [--signers PATH] [--principal ID] [--platform P|any]
                     [--json | --github-output]
  git-attest explain [same flags]

  covered   print the covered gate names, or nothing. Always exits 0: every
            failure means \"run the tests\", which is the caller's default
            anyway, so there is no state a workflow author must remember to
            handle.
  explain   print the same answer with the reasoning that produced it, on
            stderr. Use it when a skip you expected did not happen.

  --signers PATH    default: .forgejo/allowed_signers, then
                    .github/allowed_signers, resolved from the REPOSITORY ROOT
  --principal ID    default: the first principal named in the signers file
  --platform P      default: this machine. `any` accepts an attestation from
                    anywhere, which is a claim that the suite's result does not
                    depend on where it ran.
  --json            print a JSON array instead of a space-separated list
  --github-output   print `covered=` and `gates=` lines ready to append to
                    $GITHUB_OUTPUT
";

fn flag(args: &[String], name: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .filter(|v| !v.starts_with("--"))
            .cloned()
            .map(Some)
            .ok_or_else(|| format!("{name} needs a value")),
    }
}

/// Gate names as a JSON array.
///
/// Hand-rolled, and escaping rather than trusting the input: the names come
/// from a signed document, but "signed" is not "well-formed", and a stray
/// quote reaching a workflow output would be the one way a note could corrupt
/// the YAML that consumes it.
fn as_json(gates: &[String]) -> String {
    let mut out = String::from("[");
    for (i, g) in gates.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        for c in g.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::ExitCode::from(code)
}

fn run(args: &[String]) -> u8 {
    let Some(verb) = args.first() else {
        eprint!("{USAGE}");
        return 2;
    };
    match verb.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return 0;
        }
        "-V" | "--version" | "version" => {
            println!("git-attest {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        "covered" | "explain" => {}
        other => {
            eprintln!("git-attest: unknown subcommand `{other}`");
            eprint!("{USAGE}");
            return 2;
        }
    }
    let explain = verb == "explain";
    let json = args.iter().any(|a| a == "--json");
    let gha = args.iter().any(|a| a == "--github-output");

    let (signers, principal, platform) = match (
        flag(args, "--signers"),
        flag(args, "--principal"),
        flag(args, "--platform"),
    ) {
        (Ok(s), Ok(p), Ok(pl)) => (s, p, pl),
        (Err(m), _, _) | (_, Err(m), _) | (_, _, Err(m)) => {
            eprintln!("git-attest: {m}");
            return 2;
        }
    };

    // Every early return below is "nothing is covered", printed the same way
    // the covered path prints its answer — so a caller that always parses the
    // output never meets a special case.
    let done = |gates: Option<Vec<String>>, trail: Vec<String>| -> u8 {
        if explain {
            for step in &trail {
                eprintln!("  {step}");
            }
        }
        let gates = gates.unwrap_or_default();
        if gha {
            // Both forms. `covered` is the legacy string a downstream
            // `contains()` matches as a SUBSTRING; `gates` is the array form
            // that matches element-wise and is the one to use.
            println!("covered={}", gates.join(" "));
            println!("gates={}", as_json(&gates));
        } else if json {
            println!("{}", as_json(&gates));
        } else if !gates.is_empty() {
            println!("{}", gates.join(" "));
        }
        0
    };

    let Some(signers) = signers.map(PathBuf::from).or_else(attest::default_signers) else {
        return done(
            None,
            vec!["no allowed_signers found (.forgejo/ or .github/) at the repository root".into()],
        );
    };
    let Some(principal) = principal.or_else(|| attest::first_principal(&signers)) else {
        return done(
            None,
            vec![format!("{} names no principal", signers.display())],
        );
    };

    // `any` is the deliberate, committed statement that a suite's result does
    // not depend on where it ran. The default is THIS machine, so a matrix leg
    // skips only work that really ran on its own platform, with no per-leg
    // configuration.
    let want = match platform.as_deref() {
        Some("any") => None,
        Some(explicit) => Some(explicit.to_string()),
        None => Some(attest::platform()),
    };

    let verdict = attest::evaluate(&signers, &principal, want.as_deref());
    done(verdict.gates, verdict.trail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_rather_than_trusts_the_payload() {
        assert_eq!(as_json(&[]), "[]");
        assert_eq!(as_json(&["a".into(), "b".into()]), r#"["a","b"]"#);
        assert_eq!(as_json(&[r#"a"b"#.into()]), r#"["a\"b"]"#);
        assert_eq!(as_json(&["a\\b".into()]), r#"["a\\b"]"#);
        // Control characters are escaped, not passed through: JSON forbids a
        // raw one, and a note is not a trusted source of well-formedness.
        assert_eq!(as_json(&["a\tb".into()]), r#"["a\u0009b"]"#);
    }

    /// The whole point of the array form: a gate name that CONTAINS another
    /// must not be mistaken for it. Substring matching over the joined string
    /// is what made `pre-push-cargo-test-slow` satisfy a check for
    /// `pre-push-cargo-test` and skip the real suite.
    #[test]
    fn a_prefix_colliding_gate_stays_its_own_element() {
        let json = as_json(&["pre-push-cargo-test-slow".into()]);
        assert_eq!(json, r#"["pre-push-cargo-test-slow"]"#);
        assert!(json.contains("pre-push-cargo-test")); // substring: still true
                                                       // element-wise, which is what `contains(fromJSON(...), x)` does:
        assert_ne!(
            vec!["pre-push-cargo-test-slow"],
            vec!["pre-push-cargo-test"]
        );
    }

    #[test]
    fn flags_need_values_and_reject_a_following_flag() {
        let a: Vec<String> = ["covered", "--signers", "p", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(flag(&a, "--signers").unwrap().as_deref(), Some("p"));
        assert_eq!(flag(&a, "--principal").unwrap(), None);
        let b: Vec<String> = ["covered", "--signers", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(flag(&b, "--signers").is_err());
    }

    #[test]
    fn split_note_restores_the_signed_trailing_newline() {
        let body = "amont-attest-v2\ntree abc\n\n-----BEGIN SSH SIGNATURE-----\nx";
        let (payload, sig) = attest::split_note(body).unwrap();
        assert_eq!(payload, "amont-attest-v2\ntree abc\n");
        assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(attest::split_note("no blank line here").is_none());
        assert!(attest::split_note("payload\n\nnot a signature").is_none());
    }
}
