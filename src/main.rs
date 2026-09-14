//! `git-attest` — read the attestation covering the tree checked out here.
//!
//! The actions in this repository run `verify.sh`, which needs nothing but
//! `git` and `ssh-keygen`. This binary is the same contract for everywhere
//! else: CI that is neither GitHub nor Forgejo, and a laptop asking why a skip
//! did not happen.

mod attest;
mod git;

const USAGE: &str = "\
git-attest — what a signed attestation covers for the tree checked out here

  git-attest covered [--signers PATH] [--principal ID] [--platform P|OS|any]
                     [--anywhere \"NAMES\"] [--json | --github-output]
  git-attest explain [same flags]

  covered   print the covered gate names, or nothing. Always exits 0: every
            failure means \"run the tests\", which is the caller's default
            anyway, so there is no state a workflow author must remember to
            handle.
  explain   print the same answer with the reasoning that produced it, on
            stderr. Use it when a skip you expected did not happen.

  --signers PATH    default: .forgejo/allowed_signers, then
                    .github/allowed_signers. A relative PATH is resolved from
                    the REPOSITORY ROOT, not the working directory
  --principal ID    accept only a signature by this identity. Default: whoever
                    the signature says, if that key is in the signers file
  --platform P      default: this machine, as <arch>-<os>. An OS alone (`linux`)
                    accepts any architecture. `any` accepts an attestation from
                    anywhere, which is a claim that the suite's result does not
                    depend on where it ran.
  --anywhere NAMES  gate names whose result cannot depend on where they ran
                    (formatting, shell lint, secret scanning, dependency
                    audit): a verified attestation from any platform covers
                    them. Never a check that compiles or executes the product.
  --json            print a JSON array instead of a space-separated list
  --github-output   print `covered=` and `gates=` lines ready to append to
                    $GITHUB_OUTPUT
";

#[derive(Default, Debug, PartialEq)]
struct Opts {
    signers: Option<String>,
    principal: Option<String>,
    platform: Option<String>,
    anywhere: Vec<String>,
    json: bool,
    gha: bool,
}

/// The flags after the verb. An unknown one is an ERROR, not something to
/// skip: `--platfrom any` that silently fell back to this machine's platform
/// would never cover anything and never say why, which is the exact shape of
/// silence this tool exists to remove. `verify.sh` refuses the same way.
fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => o.json = true,
            "--github-output" => o.gha = true,
            name @ ("--signers" | "--principal" | "--platform" | "--anywhere") => {
                let value = args
                    .get(i + 1)
                    .filter(|v| !v.starts_with("--"))
                    .cloned()
                    .ok_or_else(|| format!("{name} needs a value"))?;
                match name {
                    "--signers" => o.signers = Some(value),
                    "--principal" => o.principal = Some(value),
                    "--anywhere" => o
                        .anywhere
                        .extend(value.split_whitespace().map(String::from)),
                    _ => o.platform = Some(value),
                }
                i += 1;
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(o)
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
    let Opts {
        signers,
        principal,
        platform,
        anywhere,
        json,
        gha,
    } = match parse(&args[1..]) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("git-attest: {m}");
            eprint!("{USAGE}");
            return 2;
        }
    };

    // Every early return below is "nothing is covered", printed the same way
    // the covered path prints its answer — so a caller that always parses the
    // output never meets a special case.
    let done = |gates: Vec<String>, trail: Vec<String>| -> u8 {
        if explain {
            for step in &trail {
                eprintln!("  {step}");
            }
        }
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

    let Some(signers) = signers
        .as_deref()
        .map(attest::resolve_signers)
        .or_else(attest::default_signers)
    else {
        return done(
            Vec::new(),
            vec!["no allowed_signers found (.forgejo/ or .github/) at the repository root".into()],
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

    let verdict = attest::evaluate(&signers, principal.as_deref(), want.as_deref(), &anywhere);
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

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_need_values_and_reject_a_following_flag() {
        let o = parse(&argv(&["--signers", "p", "--json"])).unwrap();
        assert_eq!(o.signers.as_deref(), Some("p"));
        assert_eq!(o.principal, None);
        assert!(o.json && !o.gha);
        assert!(parse(&argv(&["--signers", "--json"])).is_err());
    }

    #[test]
    fn anywhere_accumulates_whitespace_separated_names() {
        let o = parse(&argv(&[
            "--anywhere",
            " ci-fmt\tci-shellcheck ",
            "--anywhere",
            "x",
        ]))
        .unwrap();
        assert_eq!(o.anywhere, ["ci-fmt", "ci-shellcheck", "x"]);
        assert!(parse(&argv(&["--anywhere"])).is_err());
    }

    /// A typo must be refused, not skipped: `--platfrom any` that fell back to
    /// this machine's platform would silently never cover anything.
    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        assert_eq!(
            parse(&argv(&["--platfrom", "any"])),
            Err("unknown argument --platfrom".into())
        );
        assert_eq!(
            parse(&argv(&["--quiet"])),
            Err("unknown argument --quiet".into())
        );
        assert_eq!(parse(&[]), Ok(Opts::default()));
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
