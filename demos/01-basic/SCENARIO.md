# Demo 01 - Basic: detecting suspicious PowerShell encoded commands

This demo shows SIGMACHECK linting a real Sigma rule and unit-testing its
detection logic against sample Windows process-creation events.

## Files

- `encoded_powershell.yml` - a Sigma rule that flags `powershell.exe` invoked
  with an encoded-command flag (`-enc`, `-EncodedCommand`, etc.). This is a
  classic obfuscation/defense-evasion technique (MITRE ATT&CK T1059.001 /
  T1027).
- `cases.json` - unit-test cases: malicious events that SHOULD match and
  benign events that should NOT match (true/false positive coverage).

## Run it

Lint the rule (structure + best-practice checks):

```
python -m sigmacheck lint demos/01-basic/encoded_powershell.yml
```

Unit-test the detection logic against the sample events:

```
python -m sigmacheck test demos/01-basic/encoded_powershell.yml \
    --cases demos/01-basic/cases.json --format json
```

Evaluate a single ad-hoc event:

```
python -m sigmacheck match demos/01-basic/encoded_powershell.yml \
    --event some_event.json
```

## What to expect

- `lint` returns exit 0 (clean) for this well-formed rule.
- `test` returns exit 0 when every case matches its `expect_match`, and
  exit 1 if the detection logic regresses (e.g. a malicious sample stops
  matching or a benign sample starts matching).

This is the core defensive workflow: prove your detections *work* and keep
them working as you edit them.
