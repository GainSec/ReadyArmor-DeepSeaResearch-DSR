# Redaction policy (Firmware Spider telemetry)

Redaction runs centrally in the emitter **before anything reaches disk**: event `data` and `message`,
artifact bodies (model requests/responses, tool arguments/results, stdout/stderr, CLI inputs, job packets),
argv, environment summaries, exception messages and stack traces, and dead-letter records. The Python
and Node emitters load the same `fwspider_telemetry/redaction-rules.json`.

Every redaction replaces the value with `[REDACTED]` and is recorded: events carry
`redaction: {count, rules, paths}`; artifact envelopes carry `redaction.count/rules/paths`.

## Rules

String rules (regex, applied to every string value):

| Rule | Covers |
|---|---|
| `private_key_block` | PEM private-key blocks, including unterminated/truncated ones |
| `aws_access_key_id` | AWS access key IDs (AKIA/ASIA prefixes) |
| `vendor_token_format` | GitHub, OpenAI/Anthropic-style `sk-`, Slack, Hugging Face, Google API, GitLab token formats |
| `jwt` | three-part base64url JSON Web Tokens |
| `authorization_header` / `bearer_token` | `Authorization` / `Proxy-Authorization` header values, bare `Bearer <token>` |
| `cookie_header` | `Cookie` / `Set-Cookie` values |
| `url_userinfo_password` | `scheme://user:<password>@host` (connection strings) |
| `cli_secret_flag` | `--password X`, `--token=X`, `--api-key X`, ... inside command strings |
| `secret_key_value` | `password=`, `secret:`, `api_key=`, `token=`, `session_id=`, `otp=`, `verification_code=`, `cvv=`, `pin=` ... in text, query strings and embedded JSON |
| `payment_card_number` | 13-19 digit card numbers that pass the Luhn check |
| `custom_N` | patterns from `FIRMWARE_SPIDER_REDACT_PATTERNS` or `extra_redact_patterns` |

Key rule (`sensitive_key`): any mapping key whose normalized name ends in a sensitive term (password,
passwd, passphrase, pwd, secret, client_secret, api_key, access_key, secret_key, *_token / token,
authorization, cookie, set_cookie, session_id, private_key, credential(s), otp, verification_code,
mfa_code, cvv, cvc, card_number, connection_string, dsn, signature) has its whole value replaced,
including nested objects. Token-count keys (`prompt_tokens`, `total_tokens`, `max_tokens`, ...) and the
`PWD`/`OLDPWD` environment names are explicitly exempt. `claim_token` (REFALL lease capability) is redacted.

argv: values following a sensitive flag and `--flag=value` forms are redacted, then string rules apply.

## Never logged

- Complete environments: only an allowlist (paths, locale, shell, `FIRMWARE_SPIDER_*` control variables,
  `REFALL_LITE_DB`) with values redacted, plus a SHA-256 digest over all names and value hashes and the count.
- Raw firmware / binary content: path, size, sha256/sha1/md5, sniffed type, offset/length and a bounded
  64-byte hex preview only. Binary stdout is described, never stored.
- Raw password, card or verification-code values (rules above), PoW challenge tokens (downloader logs only
  `token_present`).

## Bounding

Bodies are bounded (`FIRMWARE_SPIDER_MAX_ARTIFACT_BYTES`); envelopes always state `original_length`,
`stored_length`, `sha256` (full redacted content), `stored_sha256` and an explicit `truncated` flag.
Hashes are computed over **redacted** content so they never fingerprint a secret.

## Debug mode

`FIRMWARE_SPIDER_DEBUG=1` adds events (reads, nested operations, per-file results, artifact writes, an
env-name digest); it does not change any rule. The canary tests run in both modes.

## Guarantees and limits

- Tested: canaries planted in prompts, model responses, tool arguments/results, command argv, child
  environment, stdout/stderr, HTTP headers and URLs, config, exception messages + cause chains, nested JSON,
  JSON-in-strings, REFALL submissions and ledger payloads never appear in any log, human log, artifact,
  manifest or dead-letter file (Python and Node; normal and debug mode).
- Not guaranteed: a bare high-entropy secret with no recognizable context (no sensitive key, flag, header,
  URL userinfo or known token format) cannot be distinguished from ordinary data. Callers must not place
  secrets in free-form positional data; use a sensitive key name or `FIRMWARE_SPIDER_REDACT_PATTERNS`.
- Canonical ArcticBase redaction (`refall_lite.arcticbase.contracts.redact`) is unchanged and independent.
- Files are 0600 and directories 0700 under the operator account; logs remain sensitive internal data.
