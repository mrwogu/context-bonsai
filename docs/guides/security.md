---
title: Log Sanitization and Security
description: How LogStrip sanitizes UUIDs, timestamps, hashes, and IPs before logs reach AI agents. Not a secret scanner - recommended security posture for CI workflows.
---
# Security

LogStrip is designed to reduce accidental data exposure before logs are passed to an LLM. The same sanitization rules apply whether the parser is invoked through the CLI, the library, or the GitHub Action wrapper.

## Sanitized values

The parser replaces common high-cardinality identifiers:

- UUIDs become `[ID]`;
- ISO and UTC timestamps become `[TIME]`;
- long hexadecimal or alphanumeric hashes become `[HASH]`;
- IPv4 addresses become `[IP]`;
- IPv6 addresses become `[IPV6]`;
- email addresses become `[EMAIL]`.

This lowers token cost and removes identifiers that rarely help root-cause analysis.

## Secret and credential coverage

LogStrip detects and redacts known credential patterns:

| Pattern | Replacement | Example |
|---|---|---|
| GitHub tokens (`ghp_`, `gho_`, etc.) | `[REDACTED]` | `ghp_abc123...` |
| JWT tokens | `[JWT]` | `eyJ...` |
| Slack tokens (`xoxb-`, `xoxp-`, etc.) | `[REDACTED]` | `xoxb-1234567890-...` |
| Stripe API keys (`sk_live_`, `pk_test_`, etc.) | `[REDACTED]` | `sk_live_51ABC...` |
| npm access tokens (`npm_`) | `[REDACTED]` | `npm_ABCDEF...` |
| Google API keys (`AIza`) | `[REDACTED]` | `AIzaSyB9abc...` |
| Twilio keys (`SK`, `AC`) | `[REDACTED]` | `SKabcdef12...` |
| SendGrid keys (`SG.`) | `[REDACTED]` | `SG.Abcd...XyZ` |
| Connection strings with credentials | `[REDACTED]` (password) | `postgres://user:pwd@host` |
| Authorization headers | `Authorization: [REDACTED]` | `Authorization: Bearer xyz` |
| Secret field values | key=`[REDACTED]` | `password=hunter2` |
| AWS access keys (`AKIA`, `ABIA`, `ASIA`) | `[REDACTED]` | `AKIAIOSFODNN7...` |
| AWS ARN account IDs | `[ACCOUNT]` | `arn:aws:s3:::123456789012:...` |
| PEM private key blocks | `[PEM PRIVATE KEY REDACTED]` | `-----BEGIN RSA PRIVATE KEY-----` |
| High-entropy tokens (fallback) | `[REDACTED]` | `3kF9mQ2xY7LpR4wZ8tN1...` |

Multi-line PEM private key blocks are collapsed to a single `[PEM PRIVATE KEY REDACTED]` marker, with the key body fully removed.

After the vendor-specific patterns run, an entropy-based fallback masks any
remaining random-looking token of 20+ characters (Shannon entropy ≥ 4.2
bits/char with both letters and digits, plus mixed case or base64
punctuation). This catches credentials in formats LogStrip has no dedicated
pattern for, while leaving file paths, kebab-case identifiers and pod names
untouched.

## What is not guaranteed

LogStrip is not a secret scanner. It does not guarantee removal of:

- passwords in non-standard formats;
- customer data;
- arbitrary access tokens not matching known patterns.

Run a dedicated secret scanner before sending logs to third-party systems if your logs may contain sensitive content.

## Recommended workflow posture

When using the GitHub Action wrapper, use minimum permissions for the
compression step:

```yaml
permissions:
  contents: read
```

When using the CLI directly, run it as the same user / service account that
already has read access to the log; no extra privileges are required.

Only upload or forward the compressed artifact if your downstream AI system is
approved for the data class in your organization.

## Raw log retention

Avoid long artifact retention for raw logs. If a raw log is needed for debugging, configure short retention:

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: raw-logs
    path: raw_logs.txt
    retention-days: 1
```

Compressed logs are safer to share than raw logs, but they should still be treated as build data.
