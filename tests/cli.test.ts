import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough, Readable, Writable } from 'node:stream';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CLI_VERSION,
  CliError,
  attachProgress,
  endStream,
  formatStats,
  HELP_TEXT,
  messageOf,
  parseCliOptions,
  runCli,
  writeAll,
  type CliIo,
} from '../src/cli/index';

function bufferWritable(): Writable & { value: () => string } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk, _encoding, cb) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      cb();
    },
  }) as Writable & { value: () => string };

  stream.value = () => Buffer.concat(chunks).toString('utf8');
  return stream;
}

function bufferReadable(content: string): Readable {
  return Readable.from([content]);
}

function makeIo(
  input: Readable,
  options: { stdinIsTTY?: boolean } = {},
): { io: CliIo; stdout: ReturnType<typeof bufferWritable>; stderr: ReturnType<typeof bufferWritable> } {
  const stdout = bufferWritable();
  const stderr = bufferWritable();
  return {
    io: {
      stdin: input,
      stdout,
      stderr,
      stdinIsTTY: options.stdinIsTTY ?? false,
    },
    stdout,
    stderr,
  };
}

let workDir: string;
const telemetryDir = vi.hoisted(() => {
  const { join: pJoin } = require('node:path');
  const { tmpdir } = require('node:os');
  const dir = pJoin(tmpdir(), 'logstrip-cli-telemetry');
  process.env.LOGSTRIP_TELEMETRY_DIR = dir;
  // Disable the npm update-check ping for the entire CLI test file; the
  // dedicated tests/version-check.test.ts covers that path explicitly.
  process.env.LOGSTRIP_NO_UPDATE_CHECK = '1';
  return dir;
});

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'logstrip-cli-'));
});

afterAll(async () => {
  await rm(workDir, { force: true, recursive: true });
  try { await rm(telemetryDir, { force: true, recursive: true }); } catch {}
});

describe('parseCliOptions', () => {
  it('returns defaults when only an input is given', () => {
    const opts = parseCliOptions(['raw.log']);

    expect(opts.input).toBe('raw.log');
    expect(opts.output).toBeUndefined();
    expect(opts.aggressiveness).toBe('auto');
    expect(opts.stats).toBe(false);
    expect(opts.json).toBe(false);
    expect(opts.config).toBeUndefined();
    expect(opts.help).toBe(false);
    expect(opts.version).toBe(false);
  });

  it('parses --config flag', () => {
    const opts = parseCliOptions(['raw.log', '--config', '.logstrip.yml']);

    expect(opts.input).toBe('raw.log');
    expect(opts.config).toBe('.logstrip.yml');
  });

  it('parses --telemetry flag', () => {
    const opts = parseCliOptions(['--telemetry']);

    expect(opts.telemetry).toBe(true);
  });

  it('defaults telemetry to false', () => {
    const opts = parseCliOptions(['raw.log']);

    expect(opts.telemetry).toBe(false);
  });

  it('parses every short flag', () => {
    const opts = parseCliOptions([
      'raw.log',
      '-o',
      'out.log',
      '-a',
      'low',
      '-s',
      '-j',
    ]);

    expect(opts).toMatchObject({
      input: 'raw.log',
      output: 'out.log',
      aggressiveness: 'low',
      stats: true,
      json: true,
    });
  });

  it('parses every long flag', () => {
    const opts = parseCliOptions([
      '--output',
      'out.log',
      '--aggressiveness',
      'aggressive',
      '--stats',
      '--json',
      '--help',
      '--version',
    ]);

    expect(opts).toMatchObject({
      output: 'out.log',
      aggressiveness: 'aggressive',
      stats: true,
      json: true,
      help: true,
      version: true,
    });
  });

  it('parses auto aggressiveness', () => {
    const opts = parseCliOptions(['raw.log', '--aggressiveness', 'auto']);

    expect(opts.aggressiveness).toBe('auto');
  });

  it('rejects unknown flags via CliError(exitCode=2)', () => {
    const error = (() => {
      try {
        parseCliOptions(['--nope']);
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();

    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
  });

  it('rejects extra positionals via CliError(exitCode=2)', () => {
    const error = (() => {
      try {
        parseCliOptions(['raw.log', 'extra.log']);
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();

    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Unexpected positional');
  });

  it('rejects unsupported aggressiveness as CliError(exitCode=2)', () => {
    const error = (() => {
      try {
        parseCliOptions(['-a', 'extreme', 'raw.log']);
        return undefined;
      } catch (caught) {
        return caught;
      }
    })();

    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Unsupported aggressiveness');
  });
});

describe('writeAll', () => {
  it('rejects when the stream callback signals an error', async () => {
    const broken = new Writable({
      write(_chunk, _encoding, cb) {
        cb(new Error('write broken'));
      },
    });
    broken.on('error', () => undefined);

    await expect(writeAll(broken, 'data')).rejects.toThrow('write broken');
  });

  it('resolves on normal writes', async () => {
    const sink = bufferWritable();

    await expect(writeAll(sink, 'ok')).resolves.toBeUndefined();
    expect(sink.value()).toBe('ok');
  });
});

describe('endStream', () => {
  it('rejects when the end callback signals an error', async () => {
    const broken = new Writable({
      write(_chunk, _encoding, cb) {
        cb();
      },
      final(cb) {
        cb(new Error('end broken'));
      },
    });
    broken.on('error', () => undefined);

    await expect(endStream(broken)).rejects.toThrow('end broken');
  });

  it('resolves on graceful end', async () => {
    const sink = new PassThrough();

    await expect(endStream(sink)).resolves.toBeUndefined();
  });
});

describe('attachProgress', () => {
  it('renders completion for empty inputs', async () => {
    const stderr = bufferWritable();
    const finish = attachProgress(new PassThrough(), stderr, 0);

    await finish();

    expect(stderr.value()).toContain('100%');
  });
});

describe('messageOf', () => {
  it('returns the error message for Error instances', () => {
    expect(messageOf(new Error('boom'))).toBe('boom');
  });

  it('coerces non-Error values to string', () => {
    expect(messageOf('plain')).toBe('plain');
    expect(messageOf(42)).toBe('42');
  });
});

describe('formatStats', () => {
  it('renders compact stats with the output path when present', () => {
    const text = formatStats({
      inputTokens: 100,
      outputTokens: 25,
      savedTokens: 75,
      savingsPercent: 75,
      outputPath: '/tmp/out.log',
      stats: {
        droppedLines: 3,
        duplicateLines: 2,
        hiddenInternalStackLines: 1,
        inputBytes: 1000,
        inputLines: 10,
        inputWords: 77,
        outputBytes: 250,
        outputLines: 4,
        outputWords: 19,
      },
    });

    expect(text).toContain('input lines     : 10');
    expect(text).toContain('savings         : 75.00%');
    expect(text).toContain('output path     : /tmp/out.log');
  });

  it('omits output path when missing', () => {
    const text = formatStats({
      inputTokens: 0,
      outputTokens: 0,
      savedTokens: 0,
      savingsPercent: 0,
      stats: {
        droppedLines: 0,
        duplicateLines: 0,
        hiddenInternalStackLines: 0,
        inputBytes: 0,
        inputLines: 0,
        inputWords: 0,
        outputBytes: 0,
        outputLines: 0,
        outputWords: 0,
      },
    });

    expect(text).not.toContain('output path');
  });
});

describe('runCli', () => {
  let counter = 0;
  let inputPath: string;

  beforeEach(async () => {
    counter += 1;
    inputPath = join(workDir, `raw-${counter}.log`);
    await writeFile(
      inputPath,
      [
        '[INFO] boot ok',
        '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed',
        '[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed',
        '',
      ].join('\n'),
      'utf8',
    );
  });

  it('compresses stdin to stdout when no paths are given', async () => {
    const { io, stdout, stderr } = makeIo(
      bufferReadable(
        [
          '[INFO] boot',
          '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed',
          '[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed',
          '',
        ].join('\n'),
      ),
    );

    const code = await runCli([], io);

    expect(code).toBe(0);
    expect(stdout.value()).toContain('[x2] [ERROR] request [ID] failed');
    expect(stderr.value()).toBe('');
  });

  it('compresses a file to a file and stays silent without --stats', async () => {
    const outputPath = join(workDir, `out-${counter}.log`);
    const { io, stdout, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', outputPath], io);

    expect(code).toBe(0);
    expect(stdout.value()).toBe('');
    expect(stderr.value()).toBe('');
    expect(await readFile(outputPath, 'utf8')).toContain(
      '[x2] [ERROR] request [ID] failed',
    );
  });

  it('disables the adaptive context window via --no-adaptive-context', async () => {
    const outputPath = join(workDir, `out-${counter}.log`);
    const { io } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', outputPath, '--no-adaptive-context'], io);

    expect(code).toBe(0);
    expect(await readFile(outputPath, 'utf8')).toContain(
      '[x2] [ERROR] request [ID] failed',
    );
  });

  it('rejects identical input and output paths before truncating the log', async () => {
    const original = await readFile(inputPath, 'utf8');
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', inputPath], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('must be different paths');
    expect(await readFile(inputPath, 'utf8')).toBe(original);
  });

  it('rejects case-only input and output path variants', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', inputPath.toUpperCase()], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('must be different paths');
  });

  it('writes stats to stderr when --stats is set with --output', async () => {
    const outputPath = join(workDir, `out-${counter}.log`);
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', outputPath, '--stats'], io);

    expect(code).toBe(0);
    expect(stderr.value()).toContain('LogStrip compression report');
    expect(stderr.value()).toContain('savings');
  });

  it('writes JSON to stdout when --json is set with --output', async () => {
    const outputPath = join(workDir, `out-${counter}.log`);
    const { io, stdout } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', outputPath, '--json'], io);

    expect(code).toBe(0);
    const report = JSON.parse(stdout.value()) as { savingsPercent: number };
    expect(report.savingsPercent).toBeGreaterThan(0);
  });

  it('writes JSON to stdout and stats to stderr together', async () => {
    const outputPath = join(workDir, `json-stats-${counter}.log`);
    const { io, stdout, stderr } = makeIo(new PassThrough());

    const code = await runCli(
      [inputPath, '-o', outputPath, '--json', '--stats'],
      io,
    );

    expect(code).toBe(0);
    expect(JSON.parse(stdout.value())).toMatchObject({
      outputPath,
    });
    expect(stderr.value()).toContain('LogStrip compression report');
  });

  it('applies include, exclude and max line length options', async () => {
    const { io, stdout } = makeIo(
      bufferReadable(
        [
          '[ERROR] keep this failure',
          '[WARN] skip by include',
          '[ERROR] hide this failure',
          `[ERROR] ${'x'.repeat(160)}`,
        ].join('\n'),
      ),
    );

    const code = await runCli([
      '--include',
      'ERROR',
      '--exclude',
      'hide',
      '--max-line-length',
      '100',
    ], io);

    expect(code).toBe(0);
    expect(stdout.value()).toContain('[ERROR] keep this failure');
    expect(stdout.value()).not.toContain('skip by include');
    expect(stdout.value()).not.toContain('hide this failure');
    expect(stdout.value()).toContain('… [truncated]');
  });

  it('applies sample and timeout options', async () => {
    const { io, stdout } = makeIo(
      bufferReadable('[ERROR] one\n[ERROR] two\n[ERROR] three\n'),
    );

    const code = await runCli(['--sample', '2', '--timeout', '1'], io);

    expect(code).toBe(0);
    expect(stdout.value().match(/\[ERROR\]/gu)).toHaveLength(2);
  });

  it('returns a runtime failure when timeout is reached', async () => {
    const stdin = new Readable({
      read() {
        // Keep stream open until timeout.
      },
    });
    const { io, stderr } = makeIo(stdin);

    const code = await runCli(['--timeout', '0.1'], io);

    expect(code).toBe(1);
    expect(stderr.value()).toContain('processing timed out');
  });

  it('renders progress for file input with output', async () => {
    const outputPath = join(workDir, `progress-${counter}.log`);
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-o', outputPath, '--progress'], io);

    expect(code).toBe(0);
    expect(stderr.value()).toContain('logstrip: [');
    expect(stderr.value()).toContain('100%');
    expect(await readFile(outputPath, 'utf8')).toContain('[ERROR]');
  });

  it('rejects --json without --output as usage error', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '--json'], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('--json requires --output');
  });

  it('rejects --progress without --output', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '--progress'], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('--progress requires --output');
  });

  it('refuses to read stdin when it is a TTY', async () => {
    const { io, stderr } = makeIo(new PassThrough(), { stdinIsTTY: true });

    const code = await runCli([], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('stdin is a terminal');
  });

  it('reports flag errors with friendly stderr', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli(['--unknown'], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('logstrip:');
  });

  it('reports unsupported aggressiveness as exit 2', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath, '-a', 'extreme'], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('Unsupported aggressiveness');
  });

  it('handles runtime errors from processLogFile as exit 1', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli(
      [join(workDir, 'missing.log'), '-o', join(workDir, 'never.log')],
      io,
    );

    expect(code).toBe(1);
    expect(stderr.value()).toContain('logstrip:');
  });

  it('reports stdin/stdout pipeline errors as exit 1', async () => {
    const stdin = new Readable({
      read() {
        this.destroy(new Error('stdin pipe broken'));
      },
    });
    const { io, stderr } = makeIo(stdin);

    const code = await runCli([], io);

    expect(code).toBe(1);
    expect(stderr.value()).toContain('stdin pipe broken');
  });

  it('prints help when --help is set', async () => {
    const { io, stdout } = makeIo(new PassThrough());

    const code = await runCli(['--help'], io);

    expect(code).toBe(0);
    expect(stdout.value()).toBe(HELP_TEXT);
  });

  it('prints version when --version is set', async () => {
    const { io, stdout } = makeIo(new PassThrough());

    const code = await runCli(['--version'], io);

    expect(code).toBe(0);
    expect(stdout.value()).toBe(`${CLI_VERSION}\n`);
  });

  it('parses --multiline flag', () => {
    const opts = parseCliOptions(['raw.log', '--multiline', 'python']);
    expect(opts.multiline).toBe('python');
  });

  it('parses --severity flag', () => {
    const opts = parseCliOptions(['raw.log', '--severity', 'error']);
    expect(opts.severity).toBe('error');
  });

  it('parses --include flag', () => {
    const opts = parseCliOptions(['raw.log', '--include', 'ERROR|WARN']);
    expect(opts.include).toBeInstanceOf(RegExp);
    expect(opts.include?.source).toBe('ERROR|WARN');
  });

  it('parses --exclude flag', () => {
    const opts = parseCliOptions(['raw.log', '--exclude', 'DEBUG|TRACE']);
    expect(opts.exclude).toBeInstanceOf(RegExp);
    expect(opts.exclude?.source).toBe('DEBUG|TRACE');
  });

  it('parses --sample flag', () => {
    const opts = parseCliOptions(['raw.log', '--sample', '10']);
    expect(opts.sample).toBe(10);
  });

  it('parses --max-line-length flag', () => {
    const opts = parseCliOptions(['raw.log', '--max-line-length', '500']);
    expect(opts.maxLineLength).toBe(500);
  });

  it('parses --timeout flag', () => {
    const opts = parseCliOptions(['raw.log', '--timeout', '30']);
    expect(opts.timeout).toBe(30000);
  });

  it('parses --max-tokens flag', () => {
    const opts = parseCliOptions(['raw.log', '--max-tokens', '5000']);
    expect(opts.maxTokens).toBe(5000);

    const opts2 = parseCliOptions(['raw.log']);
    expect(opts2.maxTokens).toBeUndefined();
  });

  it('rejects invalid --max-tokens values', () => {
    const check = (val: string) => {
      try { parseCliOptions(['raw.log', '--max-tokens', val]); return undefined; }
      catch (e) { return e; }
    };

    expect(check('0')).toBeInstanceOf(CliError);
    expect(check('-5')).toBeInstanceOf(CliError);
    expect(check('abc')).toBeInstanceOf(CliError);
    expect((check('0') as CliError).exitCode).toBe(2);
  });

  it('enables collapse-stacks by default and disables it via --no-collapse-stacks', () => {
    const opts = parseCliOptions(['raw.log']);
    expect(opts.collapseRepeatedStacks).toBe(true);

    const opts2 = parseCliOptions(['raw.log', '--no-collapse-stacks']);
    expect(opts2.collapseRepeatedStacks).toBe(false);
  });

  it('parses --dedupe-window flag', () => {
    const opts = parseCliOptions(['raw.log', '--dedupe-window', '50']);
    expect(opts.dedupeWindow).toBe(50);

    const opts2 = parseCliOptions(['raw.log']);
    expect(opts2.dedupeWindow).toBeUndefined();
  });

  it('rejects invalid --dedupe-window values', () => {
    const check = (val: string) => {
      try { parseCliOptions(['raw.log', '--dedupe-window', val]); return undefined; }
      catch (e) { return e; }
    };

    expect(check('0')).toBeInstanceOf(CliError);
    expect(check('-3')).toBeInstanceOf(CliError);
    expect(check('xyz')).toBeInstanceOf(CliError);
    expect((check('0') as CliError).exitCode).toBe(2);
  });

  it('enables root-cause by default and disables it via --no-root-cause', () => {
    const opts = parseCliOptions(['raw.log']);
    expect(opts.rootCause).toBe(true);

    const opts2 = parseCliOptions(['raw.log', '--no-root-cause']);
    expect(opts2.rootCause).toBe(false);
  });

  it('parses --format-sample flag', () => {
    const opts = parseCliOptions(['raw.log', '--format-sample', '20']);
    expect(opts.formatSample).toBe(20);

    const opts2 = parseCliOptions(['raw.log']);
    expect(opts2.formatSample).toBeUndefined();
  });

  it('rejects invalid --format-sample values', () => {
    const check = (val: string) => {
      try { parseCliOptions(['raw.log', '--format-sample', val]); return undefined; }
      catch (e) { return e; }
    };

    expect(check('0')).toBeInstanceOf(CliError);
    expect(check('-1')).toBeInstanceOf(CliError);
    expect(check('nan')).toBeInstanceOf(CliError);
    expect((check('0') as CliError).exitCode).toBe(2);
  });

  it('enables multilingual by default and disables it via --no-multilingual', () => {
    const opts = parseCliOptions(['raw.log']);
    expect(opts.multilingual).toBe(true);

    const opts2 = parseCliOptions(['raw.log', '--no-multilingual']);
    expect(opts2.multilingual).toBe(false);
  });

  it('enables adaptive context by default and disables it via --no-adaptive-context', () => {
    const opts = parseCliOptions(['raw.log']);
    expect(opts.adaptiveContext).toBe(true);

    const opts2 = parseCliOptions(['raw.log', '--no-adaptive-context']);
    expect(opts2.adaptiveContext).toBe(false);
  });

  it('enables template mining by default and disables it via --no-template-mining', () => {
    const opts = parseCliOptions(['raw.log']);
    expect(opts.templateMining).toBe(true);

    const opts2 = parseCliOptions(['raw.log', '--no-template-mining']);
    expect(opts2.templateMining).toBe(false);
  });

  it('parses --max-stack-frames including the 0 = unlimited sentinel', () => {
    const opts = parseCliOptions(['raw.log', '--max-stack-frames', '5']);
    expect(opts.maxStackFrames).toBe(5);

    const unlimited = parseCliOptions(['raw.log', '--max-stack-frames', '0']);
    expect(unlimited.maxStackFrames).toBe(0);

    const unset = parseCliOptions(['raw.log']);
    expect(unset.maxStackFrames).toBeUndefined();
  });

  it('rejects a non-numeric --max-stack-frames with exit code 2', () => {
    let caught: unknown;
    try {
      parseCliOptions(['raw.log', '--max-stack-frames', 'many']);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CliError);
    expect((caught as CliError).exitCode).toBe(2);
  });

  it('parses --collapse-blocks flag', () => {
    const opts = parseCliOptions(['raw.log', '--collapse-blocks', '10']);
    expect(opts.collapseBlocks).toBe(10);

    const opts2 = parseCliOptions(['raw.log']);
    expect(opts2.collapseBlocks).toBeUndefined();
  });

  it('rejects invalid --collapse-blocks values', () => {
    const check = (val: string) => {
      try { parseCliOptions(['raw.log', '--collapse-blocks', val]); return undefined; }
      catch (e) { return e; }
    };

    expect(check('1')).toBeInstanceOf(CliError);
    expect(check('-2')).toBeInstanceOf(CliError);
    expect(check('two')).toBeInstanceOf(CliError);
    expect((check('1') as CliError).exitCode).toBe(2);
  });

  it('parses --progress flag', () => {
    const opts = parseCliOptions(['raw.log', '--progress', '-o', 'out.log']);
    expect(opts.progress).toBe(true);
  });

  it('rejects invalid --multiline mode', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--multiline', 'badmode']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Unsupported multiline mode');
  });

  it('parses --preserve-id-suffix flag', () => {
    const opts = parseCliOptions(['raw.log', '--preserve-id-suffix', '8']);
    expect(opts.preserveIdSuffix).toBe(8);

    const opts2 = parseCliOptions(['raw.log', '--preserve-id-suffix', '0']);
    expect(opts2.preserveIdSuffix).toBe(0);

    const opts3 = parseCliOptions(['raw.log']);
    expect(opts3.preserveIdSuffix).toBeUndefined();
  });

  it('rejects invalid --preserve-id-suffix values', () => {
    const check = (val: string) => {
      try { parseCliOptions(['raw.log', '--preserve-id-suffix', val]); return undefined; }
      catch (e) { return e; }
    };

    expect(check('-1')).toBeInstanceOf(CliError);
    expect(check('17')).toBeInstanceOf(CliError);
    expect(check('abc')).toBeInstanceOf(CliError);
  });

  it('rejects invalid --severity level', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--severity', 'verbose']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Unsupported severity level');
  });

  it('rejects invalid --include regex', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--include', '[invalid']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Invalid --include regex');
  });

  it('rejects invalid --exclude regex', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--exclude', '[invalid']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Invalid --exclude regex');
  });

  it('rejects invalid --sample value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--sample', 'abc']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Invalid --sample');
  });

  it('rejects negative --sample value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--sample', '0']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
  });

  it('rejects invalid --max-line-length value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--max-line-length', '50']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Invalid --max-line-length');
  });

  it('rejects malformed --max-line-length value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--max-line-length', '100x']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
  });

  it('rejects invalid --timeout value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--timeout', '0']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
    expect((error as CliError).message).toContain('Invalid --timeout');
  });

  it('rejects malformed --timeout value', () => {
    const error = (() => {
      try { parseCliOptions(['raw.log', '--timeout', '1s']); return undefined; }
      catch (e) { return e; }
    })();
    expect(error).toBeInstanceOf(CliError);
    expect((error as CliError).exitCode).toBe(2);
  });

  it('rejects --progress without a file input', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli(['--progress'], io);

    expect(code).toBe(2);
    expect(stderr.value()).toContain('--progress requires a file input');
  });

  it('shows telemetry summary with --telemetry and exits', async () => {
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli(['--telemetry'], io);

    expect(code).toBe(0);
    expect(stderr.value()).toContain('LogStrip Telemetry');
  });

  it('records telemetry after a successful run', async () => {
    const { io, stdout } = makeIo(new PassThrough());

    const code = await runCli([inputPath], io);

    expect(code).toBe(0);
    expect(stdout.value()).toContain('[ERROR]');

    const { loadTelemetry: load } = await import('../src/core/telemetry/telemetry-store.js');
    const store = load();
    expect(store.totalRuns).toBeGreaterThanOrEqual(1);
    expect(store.totalSavedTokens).toBeGreaterThan(0);
  });
});

describe('runCli update notification', () => {
  const ORIGINAL_FETCH = globalThis.fetch;
  let cacheDir: string;
  let inputPath: string;

  beforeAll(async () => {
    cacheDir = await mkdtemp(join(tmpdir(), 'logstrip-cli-update-'));
    process.env.LOGSTRIP_CACHE_DIR = cacheDir;
  });

  afterAll(async () => {
    await rm(cacheDir, { force: true, recursive: true });
    delete process.env.LOGSTRIP_CACHE_DIR;
    process.env.LOGSTRIP_NO_UPDATE_CHECK = '1';
    globalThis.fetch = ORIGINAL_FETCH;
  });

  beforeEach(async () => {
    delete process.env.LOGSTRIP_NO_UPDATE_CHECK;
    await rm(cacheDir, { force: true, recursive: true });
    inputPath = join(workDir, `update-raw-${Date.now()}.log`);
    await writeFile(inputPath, '[INFO] boot ok\n[ERROR] x\n', 'utf8');
  });

  afterEach(() => {
    // Restore guard for any tests that come after in other describes.
    process.env.LOGSTRIP_NO_UPDATE_CHECK = '1';
    globalThis.fetch = ORIGINAL_FETCH;
  });

  function mockFetch(body: unknown): void {
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => body,
    } as unknown as Response)) as unknown as typeof globalThis.fetch;
  }

  it('prints notification on stderr when stderrIsTTY and a newer version exists', async () => {
    mockFetch({ version: '999.0.0' });
    const { io, stderr } = makeIo(new PassThrough());
    io.stderrIsTTY = true;

    const code = await runCli([inputPath], io);

    expect(code).toBe(0);
    expect(stderr.value()).toContain('update available');
    expect(stderr.value()).toContain('999.0.0');
  });

  it('does not print when stderr is not a TTY', async () => {
    mockFetch({ version: '999.0.0' });
    const { io, stderr } = makeIo(new PassThrough());

    const code = await runCli([inputPath], io);

    expect(code).toBe(0);
    expect(stderr.value()).not.toContain('update available');
  });

  it('does not print when --json is set, even on a TTY', async () => {
    mockFetch({ version: '999.0.0' });
    const outputPath = join(workDir, `update-out-${Date.now()}.log`);
    const { io, stderr } = makeIo(new PassThrough());
    io.stderrIsTTY = true;

    const code = await runCli([inputPath, '-o', outputPath, '--json'], io);

    expect(code).toBe(0);
    expect(stderr.value()).not.toContain('update available');
  });

  it('swallows unexpected errors from the update check', async () => {
    // fetch returns a malformed response whose .json() throws.
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error('bad json');
      },
    } as unknown as Response)) as unknown as typeof globalThis.fetch;

    const { io, stderr } = makeIo(new PassThrough());
    io.stderrIsTTY = true;

    const code = await runCli([inputPath], io);

    expect(code).toBe(0);
    expect(stderr.value()).not.toContain('update available');
  });
});
