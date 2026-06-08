# Deep demo — validating and self-testing real Sigma rules

This scenario shows SIGMACHECK doing the full pySigma-style workflow on two
non-trivial detection rules (`rules.yml`):

1. **Suspicious Service Installation Via sc.exe** — Windows persistence
   (T1543.003). Exercises `endswith`, `contains|all` (AND-of-substrings),
   list-OR selections, and a 3-clause condition with `not`.
2. **Kubernetes Privileged Pod Exec** — container escape (T1609). Exercises
   the `1 of selection*` quantifier and the `|re` regex modifier.

## Validate + run the embedded unit tests

    python -m sigmacheck check demos/02-deep/rules.yml

Each rule carries inline `tests:` with positive (should match) and negative
(should NOT match) sample events. SIGMACHECK compiles the `detection` block
into a real matcher and reports pass/fail per test. Exit code is non-zero if
any rule is invalid or any unit test fails.

JSON output for CI:

    python -m sigmacheck --format json check demos/02-deep/rules.yml

## Match a rule against live events

`events.jsonl` is a stream of process-creation events. Match the first rule
against them:

    python -m sigmacheck match demos/02-deep/rules.yml demos/02-deep/events.jsonl

Events 0 and 2 (service install from `\Users\Public\` and `\Temp\`) MATCH;
the `sc query` and `net start` events do not. A match yields exit code 1
(useful as a "did this telemetry trip the rule?" gate).

## Try the bundled library

    python -m sigmacheck demo
    python -m sigmacheck list
