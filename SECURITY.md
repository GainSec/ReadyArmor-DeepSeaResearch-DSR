# Security

## Intended use

Deep Sea Research is security research tooling. It is meant for finding vulnerabilities in
software and devices that you own or are explicitly authorised to test, so that they can be
reported and fixed.

- Do not point it at systems or products you have no authorisation to assess.
- Findings produced by a hunt are unverified leads. Confirm them before acting on them or
  reporting them.
- When a finding is confirmed, disclose it to the affected vendor or maintainer and give them
  reasonable time to fix it before publishing details.

## What a hunt does on your machine

A live hunt starts a coding agent (OpenCode) with reverse-engineering tools and lets a language
model drive them against the target directory. Keep that in mind when you choose where to run it:

- Run hunts in a directory, account or machine that holds nothing you would mind the agent
  reading. The agent works inside the directory given as `DSR_ROOT`.
- The campaign database named by `DSR_DB` is deleted and recreated on every run of
  `scripts/hunt_generic.py`.
- Targets are untrusted input. Text inside a target (strings, comments, file contents) reaches the
  model and may try to steer it. The engine's gates limit what a steered model can get recorded
  or promoted, but they do not sandbox the agent.
- The CVE prior-art check sends a file's SHA-256 and component and version strings to public
  services (CIRCL hashlookup and the NVD API). Do not call it for targets whose identity is
  confidential.

## Telemetry and redaction

Telemetry is written locally as JSONL. Request and response bodies are logged by default; set
`FIRMWARE_SPIDER_LOG_BODIES=0` to keep only hashes and lengths. Redaction of secrets is
pattern-based and is not a guarantee. See `docs/REDACTION-POLICY.md` before sharing logs.

The test suite contains a deliberately fake, AWS-format access key used as a redaction canary. It
is not a real credential. `.gitleaksignore` lists its locations so secret scanners pass.

## Reporting a vulnerability in DSR itself

If you find a security problem in this code, please report it privately to the maintainers
through the repository's private reporting channel, or by opening an issue that says only that
you have a security report and how to reach you. Please do not put exploit details in a public
issue.
