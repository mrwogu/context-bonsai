---
title: Log Compression CLI Reference
description: Complete CLI reference for LogStrip - flags, exit codes, I/O contract, stats, JSON output, multiline joining, severity filtering, include/exclude, timeout, progress. Extend with .logstrip.yml.
---
# CLI Reference

The CLI is the primary distribution channel for LogStrip. It is published
to npm as `logstrip` and exposes one binary:

| Binary | Purpose |
| :--- | :--- |
| `logstrip` | Log compression CLI - the sole entry point. |

The binary points at the compiled entry: `dist/cli/index.js`.

## Synopsis

```text
logstrip [INPUT] [options]
```

### Arguments

| Argument | Description |
| :--- | :--- |
| `INPUT` | Path to a raw log file. When omitted, the CLI reads from `stdin`. |

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-o`, `--output <path>` | Write the compressed log to `<path>`. When omitted, the compressed log is written to `stdout`. | _(stdout)_ |
| `-a`, `--aggressiveness <level>` | Compression preset: `low`, `medium`, `high`, `aggressive`, `auto`. | `auto` |
| `-m`, `--multiline <mode>` | Multiline log joining: `auto`, `python`, `node`, `java`, `go`, `rust`, `off`. Joins continuation lines (indented tracebacks, stack frames) with their parent into a single logical line before processing. | `off` |
| `--severity <level>` | Minimum severity to keep: `fatal`, `error`, `warn`, `info`, `debug`, `trace`. Lines below the given level are dropped. | _(off)_ |
| `--include <regex>` | Keep only lines matching this regex. All non-matching lines are dropped. | _(off)_ |
| `--exclude <regex>` | Drop lines matching this regex. Useful for suppressing known noise patterns like `Downloading\|Extracting`. | _(off)_ |
| `--sample <N>` | Limit output to the first _N_ kept lines. Useful for previewing large logs. | _(off)_ |
| `--max-tokens <N>` | Trim the compressed output to at most _N_ tokens, keeping the highest-scoring lines first (LLM context-budget mode). Survivors stay in original order. | _(off)_ |
| `--dedupe-window <N>` | Collapse non-adjacent duplicate lines seen within the last _N_ distinct lines into a single `[xN]` group. `1` keeps adjacent-only deduplication. | `1` |
| `--format-sample <N>` | Majority-vote format-detection window: the number of leading non-blank lines sampled before the first-line format guess may be corrected. Robust to mixed-format logs (e.g. JSON interleaved with plaintext). | `50` |
| `--collapse-blocks <N>` | Collapse consecutive repeats of a multi-line block (up to _N_ lines) into a single copy followed by a `[block xM]` marker. Complements single-line `[xN]` deduplication. | _(off)_ |
| `--no-collapse-stacks` | Disable the automatic collapsing of repeated stack-trace windows that differ only in memory addresses, Go offsets or goroutine ids. | _(auto on)_ |
| `--no-root-cause` | Disable the automatic pruning of downstream cascade restatements (e.g. `aborting due to previous errors`, `skipped because the upstream job failed`). | _(auto on)_ |
| `--no-multilingual` | Disable the automatic detection of non-English error/failure/exception keywords (e.g. `erreur`, `Fehler`, `fallo`, `ошибка`, `错误`). | _(auto on)_ |
| `--no-adaptive-context` | Disable the auto-mode adaptive context window. By default `auto` widens the after-error context around isolated errors and tightens it around clustered, self-contextualizing ones. | _(auto on)_ |
| `--max-stack-frames <N>` | Keep at most _N_ consecutive application stack frames per trace; the rest collapse into a single `[... K more application stack frames ...]` marker. `0` keeps every frame. Internal library frames are still hidden separately. | `10` |
| `--no-template-mining` | Disable template mining: by default near-identical lines that differ only in a number after a generic word label (e.g. `Retrying job 17` / `Retrying job 18`) fold into one `[xN]` group with a delta list. Numbers after diagnostic labels (`code`, `status`, `exit`, `signal`, `line`, `version`, `errno`, `error`) never merge. | _(auto on)_ |
| `--no-json-report` | Disable structured JSON document detection. By default an input that is a whole JSON document (test-runner report, scanner export) is compressed semantically instead of line-by-line: string values are sanitized, empty fields pruned, a field repeating an earlier sibling becomes a `[logstrip:= field]` reference, and array entries identical except for unique identifier fields collapse into one entry with a `[logstrip:group]` header listing each grouped entry's identifiers. The output stays valid JSON. Inputs larger than 8 MiB, JSONL streams (pino/bunyan) and lone JSON log lines with a `level` field keep using the line pipeline. | _(auto on)_ |
| `--preserve-id-suffix <N>` | Keep the last _N_ characters of redacted UUIDs and hashes (e.g. `[ID:174000]`, `[HASH:0a1b2c]`) instead of fully masking them to `[ID]` / `[HASH]`. Useful when trailing identifier digits help correlate events across lines. Range `0`–`16`; `0` masks fully. | `0` |
| `--max-line-length <n>` | Truncate lines longer than _n_ characters. Very long lines (e.g. minified bundles) are replaced with `[TRUNCATED]`. | `100000` |
| `--timeout <s>` | Stop processing after _s_ seconds. The output is flushed and `timedOut: true` is set in the result. | _(off)_ |
| `--progress` | Show a progress bar on stderr (file input only, requires `--output`). | off |
| `-s`, `--stats` | Print compression statistics to `stderr` after the log has been processed. | off |
| `-j`, `--json` | Print the `LogStripResult` as JSON to `stdout`. Requires `--output` so the compressed log does not collide with the report. | off |
| `-h`, `--help` | Print the help text and exit. | - |
| `-v`, `--version` | Print the CLI version and exit. | - |
| `--config <path>` | Path to a `.logstrip.yml` custom config file. When omitted, the CLI auto-detects `.logstrip.yml` in the current working directory. | _(auto)_ |
| `--telemetry` | Print cumulative telemetry summary to `stderr` and exit. No compression is performed. | off |

## I/O contract

- The compressed log goes to `--output` when set, otherwise to `stdout`.
- Stats (`--stats`) always go to `stderr` so they never collide with the
  compressed log on `stdout`.
- The JSON report (`--json`) always goes to `stdout`. To prevent
  contamination, `--json` requires `--output`.
- When `INPUT` is omitted and `stdin` is a terminal (TTY), the CLI exits with
  code `2` rather than waiting forever for input.

## Exit codes

| Code | Meaning |
| :--: | :--- |
| `0` | Success. |
| `1` | Runtime failure (file not found, stream error, internal exception). |
| `2` | Usage error (unknown flag, unsupported aggressiveness, `--json` without `--output`, stdin is a TTY). |

## Recipes

### File in, file out

```bash
logstrip raw.log -o clean.log
```

### Stdin in, stdout out

```bash
cat raw.log | logstrip > clean.log
```

PowerShell:

```powershell
Get-Content raw.log | logstrip > clean.log
```

### Stats alongside content

```bash
logstrip raw.log --stats > clean.log
# compressed log -> clean.log
# stats          -> stderr (visible in the terminal or CI summary)
```

### Machine-readable report

```bash
logstrip raw.log -o clean.log --json
```

`stdout` will contain a `LogStripResult` object:

```json
{
  "stats": {
    "inputLines": 4128,
    "outputLines": 312,
    "inputWords": 21450,
    "outputWords": 4138,
    "inputBytes": 412800,
    "outputBytes": 31200,
    "droppedLines": 3640,
    "duplicateLines": 87,
    "hiddenInternalStackLines": 89,
    "truncatedLines": 3
  },
  "inputTokens": 27885,
  "outputTokens": 5379,
  "savedTokens": 22506,
  "savingsPercent": 80.71,
  "detectedSources": ["webpack", "npm", "kubernetes"],
  "detectedFormat": "node",
  "timedOut": false,
  "outputPath": "clean.log"
}
```

`detectedSources` is ranked by lightweight source fingerprints gathered during
streaming. It is informational and does not change the compressed log output.
`detectedFormat` indicates the inferred log format (e.g. `node`, `python`,
`java`, `go`). `timedOut` is `true` when `--timeout` was reached before the
full stream was processed.

### Multiline traceback joining

Python tracebacks and Node.js stack traces span multiple indented lines.
Use `-m` to join continuation lines with their parent into a single logical
line before scoring and deduplication:

```bash
logstrip traceback.log -m python -o clean.log
logstrip crash.log -m node -o clean.log
logstrip mixed.log -m auto -o clean.log
```

Supported modes:

| Mode | Continuation detection |
| :--- | :--- |
| `python` | Indented lines (e.g. `  File "app.py", line 42`) |
| `node` | Indented lines (e.g. `    at app (/src/app.ts:10:5)`) |
| `java` | Indented lines + `Caused by:` headers |
| `go` | Tab-indented lines + `goroutine N [status]:` headers |
| `rust` | Indented lines |
| `auto` | Combines all of the above; best for mixed-language logs |
| `off` | No joining (default) |

Groups are bounded at 200 lines / 200 KB to prevent unbounded memory growth
from pathological input.

### Severity filtering

Keep only lines at or above a given severity level:

```bash
logstrip raw.log --severity error -o clean.log   # errors + fatals only
logstrip raw.log --severity warn -o clean.log     # warnings + errors + fatals
```

| Level | What passes |
| :--- | :--- |
| `fatal` | `FATAL`, `CRITICAL`, `EMERG`, `ALERT` |
| `error` | Above + `ERROR`, `ERR`, `SEV2` |
| `warn` | Above + `WARN`, `WARNING` |
| `info` | Above + `INFO` |
| `debug` | Above + `DEBUG` |
| `trace` | All levels pass |

Severity is inferred from log-level tags, JSON `level` fields, and common
abbreviations. Lines with no detectable severity always pass the filter.

### Include / exclude patterns

```bash
# Keep only lines mentioning "timeout" or "refused"
logstrip raw.log --include 'timeout|refused' -o clean.log

# Drop download/extract progress noise
logstrip build.log --exclude 'Downloading|Extracting|Progress' -o clean.log
```

Both flags accept JavaScript-compatible regex patterns. When `--include` is
set, any line that does not match is dropped. When `--exclude` is set, any
line that matches is dropped. They can be combined.

### Sampling and timeouts

```bash
# Preview the first 50 significant lines of a huge log
logstrip huge.log --sample 50 -o preview.log

# Stop processing after 30 seconds (CI time budgets)
logstrip raw.log --timeout 30 -o clean.log
```

When `--timeout` fires, the output is flushed and the result includes
`timedOut: true`. The compressed output is still valid and usable.

### Progress bar

```bash
logstrip huge.log --progress -o clean.log
```

Shows a live progress bar on stderr (file input only, requires `--output`).
Useful when compressing multi-gigabyte logs locally.

## Aggressiveness and context retention

`--aggressiveness` controls how much context survives around high-signal lines.
The parser uses a hybrid scoring model instead of a single binary filter:

- hard signals (`[ERROR]`, JSON `"level":"error"`, scanner findings, container
  failures, npm/yarn errors, stack frames) are emitted immediately;
- nearby soft lines are kept through a small before/after context window;
- repeated sanitized lines are dampened so spam eventually falls below the keep
  threshold;
- adjacent diagnostic variants with the same stable shape are folded as delta
  summaries, so repeated lines like `amount=99.99`, `amount=49.50`, and
  `amount=12.00` render as `[x3] ... amount=[99.99 | 49.50 | 12.00]`;
- `aggressive` still drops pure warning noise, but preserves warning lines with
  diagnostic keywords such as `failed`, `timeout`, `refused`, `crashed`,
  `killed`, `terminated`, `unauthorized`, and `unavailable`.

### Static levels

| Level | Behavior |
| :--- | :--- |
| `low` | Keeps most lines including `[INFO]` and `[DEBUG]`. Minimal compression. |
| `medium` | Drops noise tags (`[INFO]`, `[DEBUG]`, `[TRACE]`) but keeps `[WARN]`. |
| `high` | Drops noise and pure warnings; keeps only diagnostic signals + context window. |
| `aggressive` | Drops everything except errors, fatals, stack frames, and explicit diagnostic keywords. Maximum compression. |

### `auto` mode (default)

`auto` starts at the `high` static level and then **adjusts dynamically** based
on what the parser sees in the stream:

- The parser tracks a sliding window of the last 8 line decisions (kept vs
  dropped).
- When the window contains mostly hard-keep signals (3+ errors/diagnostics),
  the effective level **decreases** toward `medium` - more context is preserved
  because the log is signal-rich.
- When the window shows many drops and repeated lines (6+ drops + repeats),
  the effective level **increases** toward `aggressive` - the log is mostly
  noise, so stricter filtering recovers more tokens.

This means `auto` is safe to use as the default: it preserves context in
error-heavy logs and maximizes compression in noisy build output, without
requiring the user to guess the right level up front.

To pin a specific static level and disable dynamic adjustment, pass it
explicitly:

```bash
logstrip raw.log -a high -o clean.log
```

### Use inside a shell script

```bash
#!/usr/bin/env bash
set -euo pipefail

logstrip raw.log -o clean.log --json | jq '.savingsPercent'
```

## Stats block format

When `--stats` is enabled the CLI writes a fixed-shape block to `stderr`:

```text
LogStrip compression report
  input lines     : <int>
  output lines    : <int>
  dropped lines   : <int>
  duplicate lines : <int>
  hidden internal : <int>
  input tokens    : <int>
  output tokens   : <int>
  saved tokens    : <int>
  savings         : <float>%
  output path     : <path>   # only when --output was set
```

This format is stable across patch releases. If you need to parse it from
shell, prefer `--json` instead.

## Telemetry

LogStrip automatically records cumulative token-savings telemetry after
every successful run. The data is stored locally in
`~/.logstrip/telemetry.json` and never sent anywhere. To override the
storage directory, set the `LOGSTRIP_TELEMETRY_DIR` environment variable.

### View the summary

```bash
logstrip --telemetry
```

Output (written to `stderr`):

```text
LogStrip Telemetry
  total runs       : 42
  input tokens     : 2,145,000
  output tokens    : 413,800
  saved tokens     : 1,731,200
  average savings  : 80.71%
  last run         : 2026-05-21T14:30:00.000Z

  Last 5 runs:
    2026-05-21T14:30:00  saved=52,000  (80.0%)
    2026-05-21T14:15:00  saved=48,000  (78.5%)
    ...
```

The store keeps at most 1,000 entries; older entries are pruned
automatically.

## Update notifications

When `stderr` is attached to a terminal, `logstrip` checks the npm
registry once every 24 hours and prints a single line to `stderr` if a
newer release is available:

```text
logstrip: update available 1.8.0 → 1.9.0 (npm i -g logstrip)
```

The check is best-effort and never affects the exit code, stdout output
or your pipeline. It is skipped automatically in the following cases:

- when `stderr` is redirected (CI logs, files, pipes),
- when `--json` is used (machine-readable mode stays clean),
- when the `LOGSTRIP_NO_UPDATE_CHECK` environment variable is set to any
  non-empty value.

The last-known latest version is cached at
`~/.logstrip/.cache/version.json` for 24 hours. Override the cache
directory with the `LOGSTRIP_CACHE_DIR` environment variable.

## Embedding in Node

If you'd rather call the CLI from JavaScript without spawning a subprocess,
import the helper directly:

```ts
import { runCli } from 'logstrip/cli';

const exitCode = await runCli(['raw.log', '-o', 'clean.log', '--json'], {
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  stdinIsTTY: Boolean(process.stdin.isTTY),
  stderrIsTTY: Boolean(process.stderr.isTTY),
});
```

For library-style integration that returns a `LogStripResult` directly, use
[`processLogFile` / `processLogStream`](core.md) instead.

## Custom configuration (.logstrip.yml)

Corporations and teams running internal tools can extend LogStrip
without modifying the source code. Create a `.logstrip.yml` file in the
repository root (or pass `--config path/to/config.yml`) to define custom
log sources, diagnostic patterns, ignore rules, sanitization rules, and
internal stack patterns that merge with the built-in set at runtime.

### File format

```yaml
# Custom log sources - markers are case-insensitive substrings
# matched against every line. If a source name matches a built-in
# source, the markers are merged (deduplicated).
sources:
  - name: acme-gateway
    markers:
      - acme-gateway
      - "[ACME-GW]"
  - name: acme-auth
    markers: [acme-auth-service, "[ACME-AUTH]"]

# Lines matching any of these regexes receive a +50 relevance boost,
# same as built-in DIAGNOSTIC_PATTERN.
diagnosticPatterns:
  - "ACME_ERROR_\\d+"
  - "\\bACME-FATAL\\b"

# Lines matching any of these regexes are dropped early (before
# sanitization and scoring), similar to built-in IGNORED_LOG_TAG_PATTERN.
ignorePatterns:
  - "\\bACME-HEARTBEAT\\b"
  - "\\bacme-metrics\\b"

# Each rule applies a regex replacement to every line after built-in
# sanitization. Use "flags" to control regex flags (default: "gu").
sanitizePatterns:
  - pattern: "\\bACME-USER-\\d+\\b"
    replacement: "[ACME-USER]"
  - pattern: "acme-tenant/[a-z0-9-]+"
    replacement: "acme-tenant/[ID]"
    flags: "gi"

# Lines matching any of these regexes are collapsed behind the
# [internal-stack] marker, same as built-in INTERNAL_STACK patterns.
internalStackPatterns:
  - "/opt/acme/lib/"
```

### How it works

1. **Auto-detection** - When `--config` is not provided, the CLI looks
   for `.logstrip.yml` in the current working directory. If the file does
   not exist, processing continues with built-in patterns only.
2. **Merging** - Custom sources with a name that already exists in the
   built-in set (e.g. `docker`) have their markers **merged** with the
   built-in markers. New source names are appended.
3. **Order of application** - Custom ignore patterns are checked
   **before** built-in noise-tag filtering. Custom sanitize rules run
   **after** built-in sanitization. Custom diagnostic patterns add
   +50 to the relevance score (same weight as built-in diagnostics).
   Custom internal-stack patterns are checked alongside built-in ones.
4. **Zero runtime dependencies** - The YAML subset parser is built into
   `logstrip-config.ts` and handles the constructs shown above (mappings,
   sequences, inline arrays, quoted and unquoted strings, comments).
   It does not require `js-yaml` or any external package.

### Example: internal CI platform

```yaml
# .logstrip.yml - Acme Corp CI extension
sources:
  - name: acme-ci
    markers: [acme-ci-runner, "[ACME-CI]"]

diagnosticPatterns:
  - "ACME_BUILD_FAILED"
  - "ACME_TEST_TIMEOUT"

ignorePatterns:
  - "\\bacme-ci heartbeat\\b"
  - "\\bacme-ci version check\\b"

sanitizePatterns:
  - pattern: "ACME-EMP-\\d{6}"
    replacement: "[ACME-EMP]"

internalStackPatterns:
  - "/opt/acme/ci-runner/"
```

Then simply run:

```bash
logstrip ci-output.log -o clean.log
# .logstrip.yml is auto-detected from the current directory
```

Or explicitly:

```bash
logstrip ci-output.log -o clean.log --config /etc/logstrip/acme.yml
```
