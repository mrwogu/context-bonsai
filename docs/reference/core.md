---
title: Core TypeScript API Reference
description: Process logs in Node.js with processLogStream and processLogFile. Stream-based, deterministic, zero external dependencies. Sanitization, scoring, dedup, multiline joining, severity filtering, format detection, and timeout API.
---
# Core API Reference

The core parser lives in `src/core/logstrip-parser.ts`. It is intentionally independent from GitHub Actions and does not import `@actions/*`.

## `processLogStream`

```ts
import { createReadStream, createWriteStream } from 'node:fs';
import { processLogStream } from 'logstrip';

const input = createReadStream('raw.log', { encoding: 'utf8' });
const output = createWriteStream('raw.logstrip.log', { encoding: 'utf8' });

const result = await processLogStream(input, output, {
  aggressiveness: 'auto',
});
```

Returns:

```ts
interface LogStripResult {
  stats: LogStripStats;
  inputTokens: number;
  outputTokens: number;
  savedTokens: number;
  savingsPercent: number;
  detectedSources?: readonly string[];
  detectedFormat?: string;
  timedOut?: boolean;
  outputPath?: string;
}

interface LogStripStats {
  inputLines: number;
  outputLines: number;
  inputWords: number;
  outputWords: number;
  inputBytes: number;
  outputBytes: number;
  droppedLines: number;
  duplicateLines: number;
  hiddenInternalStackLines: number;
  truncatedLines?: number;
}
```

The stream parser is deterministic and allocation-conscious: it reads line by
line, sanitizes before deduplication, and writes directly to the supplied output
stream. When adjacent diagnostic lines share the same stable shape, the parser
folds them into a single `[xN]` line and generalizes volatile fields such as
`amount=99.99`, `amount=49.50`, and `amount=12.00` to
`amount=[99.99 | 49.50 | 12.00]`.

`detectedFormat` is set whenever the parser can infer a log format (e.g. `node`,
`python`, `java`, `go`). The detection is hybrid and always-on: the parser locks
onto the first recognizable line for speed, then self-corrects via a majority
vote over the first `formatDetectionSampleSize` (default 50) non-blank lines, so
mixed-format streams resolve to their dominant format. `timedOut` is `true` when
`processLogStreamWithTimeout` was used and the deadline was reached.
`truncatedLines` counts lines that exceeded `maxLineLength` and were replaced
with `[TRUNCATED]`.

## Aggressiveness

The `aggressiveness` option in `LogStripOptions` accepts five values:

| Value | Behavior |
| :--- | :--- |
| `low` | Keeps most lines including `[INFO]` and `[DEBUG]`. Minimal compression. |
| `medium` | Drops noise tags (`[INFO]`, `[DEBUG]`, `[TRACE]`) but keeps `[WARN]`. |
| `high` | Drops noise and pure warnings; keeps only diagnostic signals + context window. |
| `aggressive` | Drops everything except errors, fatals, stack frames, and explicit diagnostic keywords. |
| `auto` | Starts at `high` and adjusts dynamically (default when `aggressiveness` is omitted). |

### Dynamic aggressiveness (`auto`)

When `aggressiveness` is `'auto'`, the parser creates a `DynamicAggressivenessState`
that tracks a sliding window of the last 8 line decisions:

- **Decrease** (toward `medium`): when 3+ of the last 8 decisions were hard
  keeps (errors, stack frames, diagnostic keywords), the effective level drops
  to preserve more context in signal-rich logs.
- **Increase** (toward `aggressive`): when 6+ of the last 8 decisions were drops
  or repeated lines, the effective level rises to filter more aggressively in
  noisy output.
- **Stable**: otherwise the effective level stays at `high`.

The transitions use hysteresis - the effective level only changes when the
window consistently supports the shift, so brief fluctuations do not cause
oscillation.

```ts
import { createDynamicAggressivenessState } from 'logstrip';

const state = createDynamicAggressivenessState('auto');
console.log(state.effective); // 'high'

// After processing lines, the state may shift
state.recordDecision('keep-hard');
state.recordDecision('keep-hard');
state.recordDecision('keep-hard');
// ... over an 8-line window, effective may shift to 'medium'
```

## Hybrid detection engine

LogStrip no longer treats every line as a simple keep/drop decision. The
core parser combines four signals:

| Layer | Behavior | Why it matters |
| :--- | :--- | :--- |
| Scoring | `scoreLineRelevance()` gives points for errors, JSON severity, scanner findings, container failures, npm/yarn errors, diagnostic keywords, and stack frames. | Keeps real failure context even when the source format varies. |
| Context before | Up to `CONTEXT_WINDOW_BEFORE` soft-scored lines are buffered and retroactively emitted when a high-score line appears. | Preserves setup lines like "connecting database" before the error. |
| Context after | `CONTEXT_WINDOW_AFTER` lines after a high-score event are emitted as trailing context. | Keeps the first useful follow-up lines without retaining the whole log. |
| TF-IDF dampening | Repeated sanitized lines lose score after `TFIDF_REPEAT_THRESHOLD`; the per-stream map is bounded by `TFIDF_MAP_LIMIT`. | Reduces repeated spam while keeping early examples. |
| Repeat signatures | `createRepeatSignature()` groups lines by stable `key=value` shape, then the stream deduplicator lists only differing values. | Collapses repeated incident variants while preserving one-off values. |

Current exported thresholds:

| Constant | Value | Meaning |
| :--- | :---: | :--- |
| `CONTEXT_WINDOW_BEFORE` | `3` | Soft lines retained before a triggering diagnostic line. |
| `CONTEXT_WINDOW_AFTER` | `2` | Lines retained after a triggering diagnostic line. |
| `SCORE_KEEP_THRESHOLD` | `40` | Minimum score for immediate emission. |
| `TFIDF_REPEAT_THRESHOLD` | `3` | Repeat count where dampening begins. |
| `TFIDF_PENALTY` | `8` | Score penalty applied per repeat beyond the threshold. |
| `TFIDF_MAP_LIMIT` | `50_000` | Maximum unique sanitized lines tracked before the frequency map is reset. |

Example scoring outcomes:

```ts
scoreLineRelevance('[ERROR] database timeout', 'high');      // >= 40
scoreLineRelevance('[WARN] connection timeout', 'aggressive'); // >= 40
scoreLineRelevance('containerd v1.7.0 started', 'high');       // 0
scoreLineRelevance('containerd failed to create task', 'high'); // >= 40
```

## Multiline log joining

Many log formats span multiple lines - Python tracebacks, Node.js stack traces,
Java `Caused by:` chains, Go goroutine dumps. By default (`multiline: 'off'`)
each physical line is processed independently. Enable multiline mode to join
continuation lines with their parent into a single logical line before scoring:

```ts
import { processLogStream } from 'logstrip';

const result = await processLogStream(input, output, {
  multiline: 'python',  // 'auto' | 'python' | 'node' | 'java' | 'go' | 'rust' | 'off'
});
```

Groups are bounded at 200 lines / 200 KB to prevent unbounded memory growth.

The `MultilineMode` type and `isContinuationLine` helper are exported:

```ts
import { isContinuationLine, createContinuationContext, type MultilineMode } from 'logstrip';

const ctx = createContinuationContext('python');
isContinuationLine('    File "app.py", line 42', ctx); // true
```

## Severity filtering

```ts
import { processLogStream, parseSeverityLevel, type SeverityLevel } from 'logstrip';

const result = await processLogStream(input, output, {
  severity: 'error',  // keep only error + fatal lines
});
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
abbreviations. Lines with no detectable severity always pass.

`inferSeverity` and `passesSeverityFilter` are also exported for direct use:

```ts
import { inferSeverity, passesSeverityFilter } from 'logstrip';

inferSeverity('[ERROR] timeout');       // 'error'
passesSeverityFilter('[WARN] slow', 'error');  // false
passesSeverityFilter('[ERROR] fail', 'error');  // true
```

## Log format detection

The parser can infer the dominant log format from stream markers:

```ts
import { detectFormat } from 'logstrip';

detectFormat('npm ERR! code ERESOLVE\n    at module (app.js:1:1)');
// 'node'
```

`processLogStream` always attempts format detection and sets `detectedFormat`
on the result when a format is recognized (independent of the `multiline`
setting). The `detectFormat` function checks for Python (`Traceback`), Node.js
(`at ` stack frames), Java (`Exception in thread`), Go (`goroutine`), and other
format markers. For the streaming parser the first-line guess is refined by a
majority vote over the first `formatDetectionSampleSize` non-blank lines, which
keeps detection robust on logs that interleave formats (e.g. JSON lines mixed
with plaintext). Source-marker matching itself runs through a single-pass
Aho-Corasick automaton built from all 705+ ecosystem signatures - same results
as the previous per-marker scan, just faster on the hot path.

## HTTP status code grouping

The sanitizer groups HTTP status codes into classes:

```ts
import { sanitizeLine } from 'logstrip';

sanitizeLine('GET /api 503 Service Unavailable');
// 'GET /api [5xx] Service Unavailable'

sanitizeLine('responded 200 OK');
// 'responded [2xx] OK'
```

This prevents status code variations from breaking deduplication.

## Timeout wrapper

For CI time budgets, use `processLogStreamWithTimeout`:

```ts
import { processLogStreamWithTimeout } from 'logstrip';

const result = await processLogStreamWithTimeout(input, output, { aggressiveness: 'auto' }, 30_000);
if (result.timedOut) {
  console.warn('Processing timed out after 30s; output may be partial');
}
```

The function flushes the output and returns a valid `LogStripResult` with
`timedOut: true` when the deadline is reached.

## Include / exclude / sample

These options provide fine-grained filtering at the library level:

```ts
const result = await processLogStream(input, output, {
  include: /timeout|refused/,   // keep only matching lines
  exclude: /Downloading/,       // drop matching lines
  sampleSize: 50,              // limit to first 50 kept lines
  maxLineLength: 10_000,       // truncate very long lines
});
```

`include` and `exclude` accept `RegExp` objects. `sampleSize` caps the total
kept lines. `maxLineLength` replaces lines exceeding the limit with
`[TRUNCATED]` and increments `stats.truncatedLines`.

## Automatic boosters and budget options

In the default `auto` mode LogStrip enables a set of detection and compression
boosters automatically. They are exposed as tri-state options on
`LogStripOptions`: leave them `undefined` to keep the auto-on default, or set
them to `false` to opt out (the CLI surfaces the opt-outs as `--no-*` flags).

```ts
const result = await processLogStream(input, output, {
  // Tri-state boosters (default-on in auto; set false to disable):
  collapseRepeatedStacks: true, // fold repeated multi-line stack windows that
                                //   differ only in addresses/offsets/goroutine ids
  rootCause: true,              // prune downstream cascade restatements
  multilingual: true,           // detect non-English / CJK error keywords
  adaptiveContext: true,        // size the after-error context by error density
  templateMining: true,         // fold near-identical lines differing only in a
                                //   number after a generic word label

  // Numeric tuning / budget options:
  maxTokens: 8_000,             // trim to the highest-scoring lines within a
                                //   token budget (original order preserved)
  dedupeWindow: 200,            // collapse non-adjacent duplicates within the
                                //   last N distinct lines (1 = adjacent only)
  collapseBlocks: 20,           // collapse consecutive repeats of a multi-line
                                //   block (up to N lines) into one + [block xM]
  formatDetectionSampleSize: 50,// majority-vote window for format detection
  maxStackFrames: 10,           // cap consecutive app stack frames per trace
                                //   (0 keeps every frame)
});
```

| Option | Type | Default | Behavior |
| :--- | :--- | :--- | :--- |
| `collapseRepeatedStacks` | `boolean` | auto-on | Folds repeated stack-trace windows differing only in volatile frame data into a single `[xN]` group. |
| `rootCause` | `boolean` | auto-on | Drops downstream cascade restatements (`aborting due to previous errors`, `could not compile … due to previous error`, `skipped because the upstream job failed`). Conservative - genuine first errors are kept. |
| `multilingual` | `boolean` | auto-on | Boosts the score of error/failure/exception keywords in 8+ languages plus CJK (`erreur`, `Fehler`, `fallo`, `ошибка`, `错误`, …). |
| `adaptiveContext` | `boolean` | auto-on | Sizes the after-error context window by error density: wider for isolated errors, tighter for clustered, self-contextualizing ones. Disabled automatically when `contextBefore`/`contextAfter` are set explicitly. |
| `maxTokens` | `number` | _(off)_ | LLM context-budget mode: keeps the highest-scoring lines until the token budget is reached, preserving original order. |
| `dedupeWindow` | `number` | `1` | Collapses non-adjacent duplicate lines seen within the last _N_ distinct lines. `1` keeps adjacent-only deduplication. |
| `collapseBlocks` | `number` | _(off)_ | Collapses consecutive repeats of a multi-line block (up to _N_ lines) into one copy plus a `[block xM]` marker. |
| `formatDetectionSampleSize` | `number` | `50` | Number of leading non-blank lines sampled before the first-line format guess may be corrected by majority vote. After the vote locks, a sustained run of differently-formatted lines (20 consecutive) re-elects the format, so mixed streams that switch format mid-file stay correctly classified. |
| `templateMining` | `boolean` | auto-on | Folds near-identical lines whose only difference is a number after a generic word label (`Retrying upload 17` / `… 18` → `[x2] Retrying upload [17 \| 18] …`). Numbers after diagnostic labels (`code`, `status`, `exit`, `signal`, `line`, `version`, `errno`, `error`) never merge. |
| `maxStackFrames` | `number` | `10` | Keeps at most _N_ consecutive application stack frames per trace; the remainder collapses into a `[... K more application stack frames ...]` marker. `0` keeps every frame. Internal library frames are hidden separately by the internal-stack collapser. |

```ts
import { processLogFile } from 'logstrip';

const result = await processLogFile('raw.log', 'raw.logstrip.log', {
  aggressiveness: 'auto',
});
```

This helper creates Node.js file streams and returns the same `LogStripResult`.

## Context, dedupe and sanitization options

These library-level options are not surfaced as dedicated CLI flags but are
available on `LogStripOptions`:

| Option | Type | Default | Behavior |
| :--- | :--- | :--- | :--- |
| `contextBefore` | `number` | `3` | Lines kept before each retained error (the "before" half of the context window). Setting it (or `contextAfter`) disables the auto-mode adaptive window. |
| `contextAfter` | `number` | `2` | Lines kept after each retained error (the "after" half of the context window). Setting it (or `contextBefore`) disables the auto-mode adaptive window. |
| `dedupe` | `boolean` | `true` | Collapses repeated lines into `[xN]` groups. Set `false` for a raw pass. Forced off for `outputFormat: 'jsonl-preserve'`. |
| `preserveIdSuffix` | `number` | `0` | Keeps the last _N_ (`0`–`16`) characters of redacted UUIDs/hashes (`[ID:174000]`) instead of fully masking. Mirrors `--preserve-id-suffix`. |
| `outputFormat` | `'text' \| 'jsonl-preserve'` | `'text'` | `'jsonl-preserve'` keeps the original JSONL structure of each line (no folding/dedupe) while still scoring and dropping noise. |
| `config` | `LogStripCustomConfig` | _(none)_ | Inline custom config (ignore/sanitize/keep patterns). Equivalent to a parsed `.logstrip.yml`. |
| `configPath` | `string` | _(auto)_ | Path to a `.logstrip.yml` file to load. When omitted, `.logstrip.yml` is auto-detected from the cwd. |

### Programmatic-only hooks

| Option | Type | Behavior |
| :--- | :--- | :--- |
| `signal` | `AbortSignal` | Aborts processing cooperatively; the partial output is flushed and an `ABORTED` error is raised. |
| `onDecision` | `(decision: LogStripLineDecision) => void` | Per-line callback exposing the keep/drop decision, reason, and score - useful for debugging or building custom reports. |
| `tokenEstimator` | `(line: string) => number` | Overrides the built-in token estimate used for `maxTokens` budgeting and the `inputTokens` / `outputTokens` totals. |
| `timeoutMs` | `number` | Hard deadline in milliseconds; on expiry the output is flushed and `result.timedOut` is set. `processLogStreamWithTimeout` is the convenience wrapper. |

## `detectLogSources`

```ts
import { detectLogSources } from 'logstrip';

const detected = detectLogSources(`
npm ERR! code ERESOLVE
running with gitlab-runner 17.4.0
Warning BackOff restarting failed container
`);

console.log(detected);
// ['npm', 'gitlab-ci', 'kubernetes', ...]
```

Returns ranked source candidates based on lightweight fingerprint matching.

## `KNOWN_LOG_SOURCES`

```ts
import { KNOWN_LOG_SOURCES, LOG_SOURCE_SIGNATURES } from 'logstrip';

console.log(KNOWN_LOG_SOURCES.length); // 700+
console.log(LOG_SOURCE_SIGNATURES[0]); // ['vitest', ['vitest']]
```

`KNOWN_LOG_SOURCES` lists all built-in source names. `LOG_SOURCE_SIGNATURES`
lists the source-to-marker table used by `detectLogSources` and
`processLogStream`; each source must have a matching fixture under
`tests/fixtures/sources/<source>.log`.

## `sanitizeLine`

```ts
import { sanitizeLine } from 'logstrip';

sanitizeLine('[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed');
// [ERROR] request [ID] failed
```

The sanitizer replaces:

| Pattern | Replacement |
| :--- | :--- |
| UUID | `[ID]` |
| ISO and UTC timestamps | `[TIME]` |
| IPv4 addresses | `[IP]` |
| IPv4 address + port | `[IP]:[PORT]` |
| GitHub tokens (`ghp_`, `gho_`, `ghu_`, etc.) | `[REDACTED]` |
| JWT tokens (`eyJ...`) | `[JWT]` |
| Slack tokens (`xoxb-...`, `xoxp-...`) | `[REDACTED]` |
| Connection strings (`postgres://user:pass@`) | password → `[REDACTED]` |
| `Authorization:` headers | `Authorization: [REDACTED]` |
| Secret field values (`password=`, `token=`, `api_key=`, etc.) | value → `[REDACTED]` |
| AWS access keys (`AKIA...`) | `[REDACTED]` |
| AWS ARN account IDs | `[ACCOUNT]` |
| long hexadecimal or alphanumeric hashes | `[HASH]` |
| HTTP status codes | `[2xx]`, `[4xx]`, `[5xx]`, etc. |
| ANSI color escapes | removed |

Pass a second argument to keep a trailing slice of redacted UUIDs and hashes
instead of fully masking them - the same behavior the CLI exposes as
`--preserve-id-suffix`:

```ts
sanitizeLine('request 123e4567-e89b-12d3-a456-426614174000 failed', 6);
// request [ID:174000] failed
```

`preserveIdSuffix` accepts `0`–`16`; `0` (the default) masks the value entirely
to `[ID]` / `[HASH]`.

## `createRepeatSignature`

```ts
import { createRepeatSignature } from 'logstrip';

createRepeatSignature(
  '[ERROR] charge failed requestId=[ID] amount=99.99 failures=3/5',
);
// '[ERROR] charge failed requestId=[VALUE] amount=[VALUE] failures=[VALUE]'
```

This helper is used by the stream deduplicator to detect same-shape structured
events. Single lines still keep their sanitized values; differing field values
are listed only when adjacent diagnostics fold into an `[xN]` summary.

## `shouldKeepLine`

```ts
import { shouldKeepLine } from 'logstrip';

shouldKeepLine('[INFO] boot ok'); // false
shouldKeepLine('[ERROR] failure'); // true
```

The filter removes low-value log tags and keeps errors, warnings, fatal lines,
critical lines, and diagnostic stack trace lines. The full streaming parser uses
the hybrid scoring engine above, so direct `shouldKeepLine()` calls are best
treated as a lightweight helper rather than a complete compression pass.

## Tested log sources and tools

The parser detects **705+ log ecosystems** across 30+ categories.
See the [Supported Sources](sources.md) page for the full catalogue.

Fixture files live in `tests/fixtures/*.log` and deterministic outputs in
`tests/fixtures/__snapshots__/*.logstrip.snap`.

## Telemetry

The library exports a local telemetry store that records cumulative
token savings across runs. Data is stored in `~/.logstrip/telemetry.json`
(or the directory specified by `LOGSTRIP_TELEMETRY_DIR`). Nothing is sent
to any server.

### `recordTelemetry`

```ts
import { recordTelemetry, type LogStripResult } from 'logstrip';

const result: LogStripResult = await processLogFile('raw.log', 'clean.log');
recordTelemetry(result); // appends entry, updates totals
```

### `loadTelemetry` / `saveTelemetry`

```ts
import { loadTelemetry, saveTelemetry, type TelemetryStore } from 'logstrip';

const store: TelemetryStore = loadTelemetry();
console.log(store.totalSavedTokens);
```

### `formatTelemetrySummary`

```ts
import { formatTelemetrySummary } from 'logstrip';

const text = formatTelemetrySummary(loadTelemetry());
process.stderr.write(text);
```

The store keeps at most 1,000 entries; older entries are pruned
automatically by `recordTelemetry`.
