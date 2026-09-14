@echo off
rem Windows shim: `Command::new("git")` in the Rust binary will not run an
rem extension-less script, so PATH lookup finds this and it forwards to the
rem bash wrapper beside it. bash is Git Bash's, which every runner has.
bash "%~dp0git" %*
