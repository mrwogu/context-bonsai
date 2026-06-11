#!/usr/bin/env node
import { createReadStream, createWriteStream, statSync } from 'node:fs';
import { Readable, Writable } from 'node:stream';
import { parseArgs } from 'node:util';
import {
  parseAggressiveness,
  parseSeverityLevel,
  pathsReferToSameFile,
  processLogStreamWithTimeout,
  type Aggressiveness,
  type LogStripOptions,
  type LogStripResult,
  type MultilineMode,
  type SeverityLevel,
} from '../core/logstrip-parser';
import {
  formatTelemetrySummary,
  loadTelemetry,
  recordTelemetry,
} from '../core/telemetry/telemetry-store';
import { runHookCommand } from './hook-runner';
import { checkForUpdates, formatUpdateNotification } from './version-check';

export const CLI_VERSION = '1.11.0'; // x-release-please-version

export const HOOK_SUBCOMMAND = 'hook';

export const HELP_TEXT = `Usage: logstrip [INPUT] [options]
       logstrip hook

Stream-based log compression that trims noisy server logs, build
pipelines, vulnerability scanners, and container workloads down to the
diagnostic context an LLM actually needs.

Arguments:
  INPUT                    Path to the raw log. When omitted, reads from stdin.

Subcommands:
  hook                     Run as an AI assistant plugin hook. Reads a JSON event
                           from stdin (PreToolUse or UserPromptSubmit) and emits
                           the matching hookSpecificOutput JSON to stdout. Used
                           by the bundled Droid, Claude, Codex, Copilot, and
                           Cursor plugin manifests.

Options:
  -o, --output <path>      Write the compressed log to <path>. Defaults to stdout.
  -a, --aggressiveness <l> Compression preset: low | medium | high | aggressive | auto.
                           Default: auto.
  -s, --stats              Print compression statistics to stderr.
  -j, --json               Print LogStripResult JSON to stdout. Requires --output.
  -m, --multiline <mode>   Multiline handling: auto | python | node | java | go | rust | off.
                           Default: off.
      --severity <level>   Minimum severity: fatal | error | warn | info | debug | trace.
      --include <regex>    Keep only lines matching this regex.
      --exclude <regex>    Drop lines matching this regex.
      --sample <N>         Limit output to first N kept lines.
      --max-tokens <N>     Trim output to at most N tokens, keeping the
                           highest-scoring lines (LLM context-budget mode).
      --dedupe-window <N>  Collapse non-adjacent duplicate lines seen within
                           the last N distinct lines. Default: 1 (adjacent only).
      --format-sample <N>  Majority-vote format detection window over the first
                           N non-blank lines. Default: 50.
      --collapse-blocks <N> Collapse consecutive repeats of a block of up to N
                           lines into one copy plus a [block xM] marker.
      --no-collapse-stacks Disable auto-collapsing of repeated stack-trace
                           windows that differ only in addresses/offsets.
      --no-root-cause      Disable auto-pruning of downstream cascade
                           restatements (e.g. "aborting due to previous errors").
      --no-multilingual    Disable auto-detection of non-English error/failure
                           keywords (e.g. "erreur", "Fehler", "错误").
      --no-adaptive-context Disable auto-mode adaptive context windows that
                           widen around isolated errors and tighten around
                           clustered ones.
      --max-stack-frames <N> Keep at most N consecutive application stack
                           frames per trace; the rest collapse into a
                           [... K more application stack frames ...] marker.
                           0 keeps every frame. Default: 10.
      --no-template-mining Disable folding of near-identical lines that
                           differ only in a number after a generic word
                           label (e.g. "Retrying job 17" / "Retrying job 18").
      --no-json-report     Disable auto-detection of structured JSON documents
                           (test reports, scanner exports). Detected documents
                           are compressed semantically - repeated entries
                           grouped, duplicate fields referenced, empty fields
                           pruned - and stay valid JSON.
      --preserve-id-suffix <N> Keep the last N chars of redacted UUIDs/hashes
                           (e.g. [ID:74000]) instead of fully masking. 0-16,
                           0 masks fully. Default: 0.
      --max-line-length <n> Truncate lines longer than n chars. Default: 100000.
      --timeout <s>        Stop processing after s seconds.
      --progress           Show progress bar (file input only, requires --output).
      --config <path>      Path to .logstrip.yml config file. Auto-detects from cwd.
      --telemetry          Show cumulative telemetry summary on stderr and exit.
  -h, --help               Show this help text and exit.
  -v, --version            Print the CLI version and exit.

Examples:
  logstrip raw.log -o clean.log
  cat raw.log | logstrip > clean.log
  logstrip raw.log --stats > clean.log
  logstrip raw.log -o clean.log --json
  logstrip traceback.log -m python -o clean.log
  logstrip build.log --exclude 'Downloading|Extracting' -o clean.log
  logstrip huge.log --progress --timeout 30 -o clean.log
`;

const VALID_MULTILINE_MODES: readonly string[] = [
  'auto', 'python', 'node', 'java', 'go', 'rust', 'off',
];

export interface CliOptions {
  input?: string;
  output?: string;
  aggressiveness: Aggressiveness;
  stats: boolean;
  json: boolean;
  multiline: MultilineMode;
  severity?: SeverityLevel;
  include?: RegExp;
  exclude?: RegExp;
  sample?: number;
  maxLineLength?: number;
  timeout?: number;
  progress: boolean;
  config?: string;
  preserveIdSuffix?: number;
  maxTokens?: number;
  collapseRepeatedStacks: boolean;
  dedupeWindow?: number;
  rootCause: boolean;
  formatSample?: number;
  multilingual: boolean;
  collapseBlocks?: number;
  adaptiveContext: boolean;
  maxStackFrames?: number;
  templateMining: boolean;
  jsonReport: boolean;
  telemetry: boolean;
  help: boolean;
  version: boolean;
}

export interface CliIo {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  stdinIsTTY: boolean;
  stderrIsTTY?: boolean;
}

export class CliError extends Error {
  public readonly exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
  }
}

export function parseMultilineMode(value: string): MultilineMode {
  const normalized = value.toLowerCase();
  if (VALID_MULTILINE_MODES.includes(normalized)) {
    return normalized as MultilineMode;
  }
  throw new CliError(
    `Unsupported multiline mode: ${value}. Valid values: ${VALID_MULTILINE_MODES.join(', ')}`,
    2,
  );
}

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function parseCliOptions(argv: readonly string[]): CliOptions {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv as string[],
      allowPositionals: true,
      strict: true,
      options: {
        output: { type: 'string', short: 'o' },
        aggressiveness: { type: 'string', short: 'a' },
        stats: { type: 'boolean', short: 's', default: false },
        json: { type: 'boolean', short: 'j', default: false },
        multiline: { type: 'string', short: 'm' },
        'preserve-id-suffix': { type: 'string' },
        severity: { type: 'string' },
        include: { type: 'string' },
        exclude: { type: 'string' },
        sample: { type: 'string' },
        'max-tokens': { type: 'string' },
        'dedupe-window': { type: 'string' },
        'format-sample': { type: 'string' },
        'collapse-blocks': { type: 'string' },
        'no-collapse-stacks': { type: 'boolean', default: false },
        'no-root-cause': { type: 'boolean', default: false },
        'no-multilingual': { type: 'boolean', default: false },
        'no-adaptive-context': { type: 'boolean', default: false },
        'max-stack-frames': { type: 'string' },
        'no-template-mining': { type: 'boolean', default: false },
        'no-json-report': { type: 'boolean', default: false },
        'max-line-length': { type: 'string' },
        timeout: { type: 'string' },
        progress: { type: 'boolean', default: false },
        config: { type: 'string' },
        telemetry: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });
  } catch (error) {
    throw new CliError(messageOf(error), 2);
  }

  if (parsed.positionals.length > 1) {
    throw new CliError(
      `Unexpected positional argument: ${parsed.positionals[1]}`,
      2,
    );
  }

  const aggressivenessInput =
    typeof parsed.values.aggressiveness === 'string'
      ? parsed.values.aggressiveness
      : 'auto';

  let aggressiveness: Aggressiveness;
  try {
    aggressiveness = parseAggressiveness(aggressivenessInput);
  } catch (error) {
    throw new CliError(messageOf(error), 2);
  }

  const multilineInput =
    typeof parsed.values.multiline === 'string'
      ? parsed.values.multiline
      : 'off';

  let multiline: MultilineMode;
  try {
    multiline = parseMultilineMode(multilineInput);
  } catch (error) {
    throw new CliError(messageOf(error), 2);
  }

  let severity: SeverityLevel | undefined;
  if (typeof parsed.values.severity === 'string') {
    try {
      severity = parseSeverityLevel(parsed.values.severity);
    } catch (error) {
      throw new CliError(messageOf(error), 2);
    }
  }

  let include: RegExp | undefined;
  if (typeof parsed.values.include === 'string') {
    try { include = new RegExp(parsed.values.include, 'u'); }
    catch { throw new CliError(`Invalid --include regex: ${parsed.values.include}`, 2); }
  }

  let exclude: RegExp | undefined;
  if (typeof parsed.values.exclude === 'string') {
    try { exclude = new RegExp(parsed.values.exclude, 'u'); }
    catch { throw new CliError(`Invalid --exclude regex: ${parsed.values.exclude}`, 2); }
  }

  let sample: number | undefined;
  if (typeof parsed.values.sample === 'string') {
    if (!/^\d+$/u.test(parsed.values.sample)) throw new CliError(`Invalid --sample: ${parsed.values.sample}. Must be a positive integer.`, 2);
    sample = Number(parsed.values.sample);
    if (sample < 1) throw new CliError(`Invalid --sample: ${parsed.values.sample}. Must be a positive integer.`, 2);
  }

  let maxTokens: number | undefined;
  if (typeof parsed.values['max-tokens'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['max-tokens'])) {
      throw new CliError(`Invalid --max-tokens: ${parsed.values['max-tokens']}. Must be a positive integer.`, 2);
    }
    maxTokens = Number(parsed.values['max-tokens']);
    if (maxTokens < 1) {
      throw new CliError(`Invalid --max-tokens: ${parsed.values['max-tokens']}. Must be a positive integer.`, 2);
    }
  }

  let dedupeWindow: number | undefined;
  if (typeof parsed.values['dedupe-window'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['dedupe-window'])) {
      throw new CliError(`Invalid --dedupe-window: ${parsed.values['dedupe-window']}. Must be a positive integer.`, 2);
    }
    dedupeWindow = Number(parsed.values['dedupe-window']);
    if (dedupeWindow < 1) {
      throw new CliError(`Invalid --dedupe-window: ${parsed.values['dedupe-window']}. Must be a positive integer.`, 2);
    }
  }

  let formatSample: number | undefined;
  if (typeof parsed.values['format-sample'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['format-sample'])) {
      throw new CliError(`Invalid --format-sample: ${parsed.values['format-sample']}. Must be a positive integer.`, 2);
    }
    formatSample = Number(parsed.values['format-sample']);
    if (formatSample < 1) {
      throw new CliError(`Invalid --format-sample: ${parsed.values['format-sample']}. Must be a positive integer.`, 2);
    }
  }

  let collapseBlocks: number | undefined;
  if (typeof parsed.values['collapse-blocks'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['collapse-blocks'])) {
      throw new CliError(`Invalid --collapse-blocks: ${parsed.values['collapse-blocks']}. Must be an integer >= 2.`, 2);
    }
    collapseBlocks = Number(parsed.values['collapse-blocks']);
    if (collapseBlocks < 2) {
      throw new CliError(`Invalid --collapse-blocks: ${parsed.values['collapse-blocks']}. Must be an integer >= 2.`, 2);
    }
  }

  let maxStackFrames: number | undefined;
  if (typeof parsed.values['max-stack-frames'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['max-stack-frames'])) {
      throw new CliError(`Invalid --max-stack-frames: ${parsed.values['max-stack-frames']}. Must be an integer >= 0 (0 keeps every frame).`, 2);
    }
    maxStackFrames = Number(parsed.values['max-stack-frames']);
  }

  let maxLineLength: number | undefined;
  if (typeof parsed.values['max-line-length'] === 'string') {
    if (!/^\d+$/u.test(parsed.values['max-line-length'])) throw new CliError(`Invalid --max-line-length. Must be >= 100.`, 2);
    maxLineLength = Number(parsed.values['max-line-length']);
    if (maxLineLength < 100) throw new CliError(`Invalid --max-line-length. Must be >= 100.`, 2);
  }

  let timeout: number | undefined;
  if (typeof parsed.values.timeout === 'string') {
    if (!/^(?:\d+|\d*\.\d+)$/u.test(parsed.values.timeout)) throw new CliError(`Invalid --timeout. Must be a positive number.`, 2);
    timeout = Number(parsed.values.timeout);
    if (timeout < 0.1) throw new CliError(`Invalid --timeout. Must be a positive number.`, 2);
    timeout = Math.round(timeout * 1000);
  }

  const progress = parsed.values.progress === true;

  let preserveIdSuffix: number | undefined;
  if (typeof parsed.values['preserve-id-suffix'] === 'string') {
    const suffix = Number.parseInt(parsed.values['preserve-id-suffix'], 10);
    if (!Number.isFinite(suffix) || suffix < 0 || suffix > 16) {
      throw new CliError('--preserve-id-suffix must be a number between 0 and 16', 2);
    }
    preserveIdSuffix = suffix;
  }

  return {
    input: parsed.positionals[0],
    output:
      typeof parsed.values.output === 'string' ? parsed.values.output : undefined,
    aggressiveness,
    stats: parsed.values.stats === true,
    json: parsed.values.json === true,
    multiline,
    severity,
    include,
    exclude,
    sample,
    maxLineLength,
    timeout,
    progress,
    config:
      typeof parsed.values.config === 'string'
        ? parsed.values.config
        : undefined,
    preserveIdSuffix,
    maxTokens,
    collapseRepeatedStacks: parsed.values['no-collapse-stacks'] !== true,
    dedupeWindow,
    rootCause: parsed.values['no-root-cause'] !== true,
    formatSample,
    multilingual: parsed.values['no-multilingual'] !== true,
    collapseBlocks,
    adaptiveContext: parsed.values['no-adaptive-context'] !== true,
    maxStackFrames,
    templateMining: parsed.values['no-template-mining'] !== true,
    jsonReport: parsed.values['no-json-report'] !== true,
    telemetry: parsed.values.telemetry === true,
    help: parsed.values.help === true,
    version: parsed.values.version === true,
  };
}

export function formatStats(result: LogStripResult): string {
  const lines = [
    'LogStrip compression report',
    `  input lines     : ${result.stats.inputLines}`,
    `  output lines    : ${result.stats.outputLines}`,
    `  dropped lines   : ${result.stats.droppedLines}`,
    `  duplicate lines : ${result.stats.duplicateLines}`,
    `  hidden internal : ${result.stats.hiddenInternalStackLines}`,
    `  truncated lines : ${result.stats.truncatedLines ?? 0}`,
    `  input tokens    : ${result.inputTokens}`,
    `  output tokens   : ${result.outputTokens}`,
    `  saved tokens    : ${result.savedTokens}`,
    `  savings         : ${result.savingsPercent.toFixed(2)}%`,
  ];

  if (result.outputPath !== undefined) {
    lines.push(`  output path     : ${result.outputPath}`);
  }

  return `${lines.join('\n')}\n`;
}

export function writeAll(
  stream: NodeJS.WritableStream,
  chunk: string,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stream.write(chunk, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

export function endStream(stream: Writable): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stream.end((error?: Error | null) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

export function attachProgress(
  input: Readable,
  stderr: NodeJS.WritableStream,
  totalBytes: number,
): () => Promise<void> {
  let seenBytes = 0;
  const width = 20;
  const render = (): void => {
    const ratio =
      totalBytes === 0 ? 1 : Math.min(1, seenBytes / totalBytes);
    const complete = Math.round(ratio * width);
    const bar = `${'#'.repeat(complete)}${'-'.repeat(width - complete)}`;
    stderr.write(`\rlogstrip: [${bar}] ${Math.round(ratio * 100)}%`);
  };
  const onData = (chunk: Buffer | string): void => {
    seenBytes += Buffer.byteLength(chunk);
    render();
  };

  input.on('data', onData);
  render();

  return async () => {
    input.off('data', onData);
    seenBytes = totalBytes;
    render();
    await writeAll(stderr, '\n');
  };
}

export async function runCli(
  argv: readonly string[],
  io: CliIo,
): Promise<number> {
  if (argv[0] === HOOK_SUBCOMMAND) {
    return runHookCommand(io);
  }

  let options: CliOptions;
  try {
    options = parseCliOptions(argv);
  } catch (error) {
    const cliError = error as CliError;
    await writeAll(io.stderr, `logstrip: ${cliError.message}\n`);
    return cliError.exitCode;
  }

  if (options.help) {
    await writeAll(io.stdout, HELP_TEXT);
    return 0;
  }

  if (options.version) {
    await writeAll(io.stdout, `${CLI_VERSION}\n`);
    return 0;
  }

  if (options.telemetry) {
    const store = loadTelemetry();
    await writeAll(io.stderr, formatTelemetrySummary(store));
    return 0;
  }

  if (options.json && options.output === undefined) {
    await writeAll(
      io.stderr,
      'logstrip: --json requires --output so the compressed log does not collide with the JSON report on stdout\n',
    );
    return 2;
  }

  if (options.progress && options.input === undefined) {
    await writeAll(io.stderr, 'logstrip: --progress requires a file input (not stdin)\n');
    return 2;
  }

  if (options.progress && options.output === undefined) {
    await writeAll(io.stderr, 'logstrip: --progress requires --output so progress does not collide with stdout\n');
    return 2;
  }

  if (options.input === undefined && io.stdinIsTTY) {
    await writeAll(
      io.stderr,
      'logstrip: no INPUT given and stdin is a terminal. Pass a file path or pipe a log.\n',
    );
    return 2;
  }

  if (
    options.input !== undefined &&
    options.output !== undefined &&
    pathsReferToSameFile(options.input, options.output)
  ) {
    await writeAll(
      io.stderr,
      'logstrip: INPUT and --output must be different paths; refusing to overwrite the input log\n',
    );
    return 2;
  }

  const input =
    options.input !== undefined
      ? createReadStream(options.input, { encoding: 'utf8' })
      : (io.stdin as NodeJS.ReadableStream);

  const output =
    options.output !== undefined
      ? createWriteStream(options.output, { encoding: 'utf8' })
      : (io.stdout as NodeJS.WritableStream);

  let result: LogStripResult;
  let finishProgress: (() => Promise<void>) | undefined;
  try {
    finishProgress =
      options.progress && options.input !== undefined
        ? attachProgress(input as Readable, io.stderr, statSync(options.input).size)
        : undefined;
    const logStripOptions: LogStripOptions = {
      aggressiveness: options.aggressiveness,
      configPath: options.config,
      multiline: options.multiline,
      severity: options.severity,
      include: options.include,
      exclude: options.exclude,
      sampleSize: options.sample,
      maxLineLength: options.maxLineLength,
      preserveIdSuffix: options.preserveIdSuffix,
      maxTokens: options.maxTokens,
      collapseRepeatedStacks: options.collapseRepeatedStacks,
      dedupeWindow: options.dedupeWindow,
      rootCause: options.rootCause,
      formatDetectionSampleSize: options.formatSample,
      multilingual: options.multilingual,
      collapseBlocks: options.collapseBlocks,
      adaptiveContext: options.adaptiveContext ? undefined : false,
      maxStackFrames: options.maxStackFrames,
      templateMining: options.templateMining,
      jsonReport: options.jsonReport,
    };
    result = await processLogStreamWithTimeout(
      input,
      output as Writable,
      logStripOptions,
      options.timeout,
    );
  } catch (error) {
    if (options.input !== undefined) {
      (input as Readable).destroy();
    }
    if (options.output !== undefined) {
      (output as Writable).destroy();
    }
    await writeAll(io.stderr, `logstrip: ${messageOf(error)}\n`);
    return 1;
  }

  if (finishProgress !== undefined) {
    await finishProgress();
  }

  if (options.output !== undefined) {
    result = { ...result, outputPath: options.output };
    await endStream(output as Writable);
  }

  try { recordTelemetry(result); } catch { /* non-critical, ignore write failures */ }

  if (options.json) {
    await writeAll(io.stdout, `${JSON.stringify(result, null, 2)}\n`);
  }
  if (options.stats) {
    await writeAll(io.stderr, formatStats(result));
  }

  if (result.timedOut === true) {
    await writeAll(io.stderr, 'logstrip: processing timed out\n');
    return 1;
  }

  await maybeNotifyUpdate(io, options);

  return 0;
}

async function maybeNotifyUpdate(
  io: CliIo,
  options: CliOptions,
): Promise<void> {
  // Only nudge interactive users. Skip JSON output mode so machine-readable
  // runs stay clean, and skip when stderr is redirected (CI logs).
  if (options.json || io.stderrIsTTY !== true) {
    return;
  }
  try {
    const info = await checkForUpdates(CLI_VERSION);
    if (info) {
      await writeAll(io.stderr, formatUpdateNotification(info));
    }
  } catch {
    /* update check is best-effort; never fail the run because of it */
  }
}

/* v8 ignore start */
if (require.main === module) {
  runCli(process.argv.slice(2), {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    stdinIsTTY: Boolean(process.stdin.isTTY),
    stderrIsTTY: Boolean(process.stderr.isTTY),
  })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(
        `logstrip: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`,
      );
      process.exitCode = 1;
    });
}
/* v8 ignore stop */
