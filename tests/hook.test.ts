import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable, Writable } from 'node:stream';

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

import { runCli, type CliIo } from '../src/cli/index';

import * as parser from '../src/core/logstrip-parser';

const TEMP_ENV_KEYS = ['TMPDIR', 'TMP', 'TEMP'] as const;

function extractLogPath(reason: string): string | null {
  const match = reason.match(/(\S+logstrip-[0-9a-f]+\.logstrip\.log)/u);
  return match ? match[1] : null;
}

const HOOKS_JSON = resolve(__dirname, '../plugins/logstrip/hooks/hooks.json');
const CURSOR_HOOKS_JSON = resolve(
  __dirname,
  '../plugins/logstrip/hooks/cursor-hooks.json',
);
const FACTORY_PLUGIN_JSON = resolve(
  __dirname,
  '../plugins/logstrip/.factory-plugin/plugin.json',
);
const PLUGIN_MANIFEST_PATHS: readonly string[] = [
  '.factory-plugin/plugin.json',
  '.claude-plugin/plugin.json',
  '.github/plugin.json',
  '.codex-plugin/plugin.json',
];

const HOOK_COMMAND = 'logstrip hook';

// ── helpers ──────────────────────────────────────────────────────────

interface HookResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
}

function bufferWritable(): Writable & { value(): string } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk, _encoding, cb) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      cb();
    },
  }) as Writable & { value(): string };

  stream.value = () => Buffer.concat(chunks).toString('utf8');
  return stream;
}

function makeIo(stdinPayload: string): {
  io: CliIo;
  stdout: ReturnType<typeof bufferWritable>;
  stderr: ReturnType<typeof bufferWritable>;
} {
  const stdout = bufferWritable();
  const stderr = bufferWritable();
  return {
    io: {
      stdin: Readable.from([stdinPayload]),
      stdout,
      stderr,
      stdinIsTTY: false,
    },
    stdout,
    stderr,
  };
}

async function runHookRaw(stdinPayload: string): Promise<HookResult> {
  const start = performance.now();
  const { io, stdout, stderr } = makeIo(stdinPayload);
  const exitCode = await runCli(['hook'], io);
  const durationMs = performance.now() - start;
  return {
    stdout: stdout.value(),
    stderr: stderr.value(),
    exitCode,
    durationMs,
  };
}

function runHook(input: unknown): Promise<HookResult> {
  return runHookRaw(JSON.stringify(input));
}

function parseJson<T>(raw: string): T | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return null;
  }
}

function makePreToolUseInput(
  filePath: string,
  toolName = 'Read',
): object {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: toolName,
    tool_input: { file_path: filePath },
    session_id: 'test-session',
  };
}

function makeUserPromptSubmitInput(prompt: unknown): object {
  return {
    hook_event_name: 'UserPromptSubmit',
    prompt,
    session_id: 'test-session',
  };
}

// ── fixtures ──────────────────────────────────────────────────────────

const CI_LOG_PASTE = [
  '2024-01-15 10:23:45.123 [ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed',
  '2024-01-15 10:23:46.456 [ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed',
  '2024-01-15 10:23:47.789 [WARN]  retrying connection',
  '2024-01-15 10:23:48.012 [INFO]  boot ok',
  '2024-01-15 10:23:49.345 [ERROR] connection lost',
  '2024-01-15 10:23:50.678 [DEBUG] at com.example.Service.handle(Service.java:42)',
].join('\n');

const JAVA_STACK_PASTE = [
  'java.lang.NullPointerException',
  '    at com.example.checkout.CartService.calculateTotal(CartService.java:42)',
  '    at com.example.checkout.OrderService.processOrder(OrderService.java:118)',
  '    at com.example.api.CheckoutController.postOrder(CheckoutController.java:67)',
  '    at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)',
  '2024-03-12T14:32:01.456 [ERROR] Unhandled exception in checkout flow',
].join('\n');

const NPM_BUILD_PASTE = [
  'npm ERR! code ELIFECYCLE',
  'npm ERR! errno 1',
  'npm ERR! build-server@1.0.0 build: `tsc -p tsconfig.json`',
  'npm ERR! Exit status 1',
  'npm ERR! Failed at the build-server@1.0.0 build script.',
  'npm ERR! This is probably not a problem with npm.',
].join('\n');

const MIXED_CI_PASTE = [
  'FAIL  tests/integration/users.test.ts',
  'PASS  tests/unit/auth.test.ts',
  'SKIP  tests/e2e/deploy.test.ts',
  'RUN   tests/integration/orders.test.ts',
  'FAIL  tests/integration/orders.test.ts (2 failed)',
  '  ● Order Service › should create order',
].join('\n');

const SHORT_NON_LOG = 'Hello, how are you today?';

const CODE_DISCUSSION = [
  'I think we should refactor the authentication module.',
  'The current implementation uses callback-based patterns,',
  'but we could switch to async/await which is cleaner.',
  'What do you think about this approach?',
  'Let me know your thoughts.',
].join('\n');

const SINGLE_HEURISTIC = [
  '2024-01-15 10:23:45.123 something happened',
  '2024-01-15 10:23:46.456 something else happened',
  'This is just a regular message with timestamps',
  'But no log levels or CI markers anywhere',
  'So it should not trigger auto-detection',
].join('\n');

let workDir: string;
const savedTempEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'logstrip-hook-'));
  for (const key of TEMP_ENV_KEYS) {
    savedTempEnv[key] = process.env[key];
    process.env[key] = workDir;
  }
});

afterAll(async () => {
  for (const key of TEMP_ENV_KEYS) {
    const previous = savedTempEnv[key];
    if (previous === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = previous;
    }
  }
  await rm(workDir, { force: true, recursive: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - file extension matching
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - extension matching', () => {
  const logExtensions = ['.log', '.out', '.txt', '.trace', '.err'];

  it.each(logExtensions)('denies Read on %s file and redirects', async (ext) => {
    const filePath = join(workDir, `test${ext}`);
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      hookSpecificOutput: {
        hookEventName: string;
        permissionDecision: string;
        permissionDecisionReason: string;
      };
      permission: string;
      permissionDecision: string;
      permissionDecisionReason: string;
      user_message: string;
      agent_message: string;
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(json!.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(json!.hookSpecificOutput.permissionDecisionReason).toContain(
      '.logstrip.log',
    );
    expect(json!.hookSpecificOutput.permissionDecisionReason).toContain(
      filePath,
    );
    expect(json!.permission).toBe('deny');
    expect(json!.permissionDecision).toBe('deny');
    expect(json!.permissionDecisionReason).toContain(filePath);
    expect(json!.user_message).toContain(filePath);
    expect(json!.agent_message).toContain(filePath);
  });

  const skipExtensions = ['.ts', '.js', '.json', '.yml', '.md', '.css', '.py'];

  it.each(skipExtensions)('skips Read on %s file', async (ext) => {
    const filePath = join(workDir, `test${ext}`);
    await writeFile(filePath, 'some content');

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - skip already-compressed files
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - skip already-compressed files', () => {
  it('skips .logstrip.log files', async () => {
    const filePath = join(workDir, 'already.logstrip.log');
    await writeFile(filePath, 'compressed content');

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips .logstrip.txt files', async () => {
    const filePath = join(workDir, 'already.logstrip.txt');
    await writeFile(filePath, 'compressed content');

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - non-existent files
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - non-existent files', () => {
  it('skips non-existent .log file', async () => {
    const filePath = join(workDir, 'nonexistent.log');

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - non-Read tools
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - non-Read tools', () => {
  it('skips Write tool even on .log file', async () => {
    const filePath = join(workDir, 'target.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath, 'Write'));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips Edit tool even on .log file', async () => {
    const filePath = join(workDir, 'target.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath, 'Edit'));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips Bash tool', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'cat /tmp/test.log' },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - missing/invalid file_path
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - missing file_path', () => {
  it('skips when tool_input has no file_path', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: {},
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips when file_path is an empty string', async () => {
    const result = await runHook(makePreToolUseInput(''));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips when file_path is not a string', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: 123 },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips when tool_input itself is null', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Read',
      tool_input: null,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips when tool_name field is entirely absent', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_input: { file_path: '/tmp/some.log' },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - compression output
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - compression output', () => {
  it('creates .logstrip.log output file on disk', async () => {
    const filePath = join(workDir, 'compress-me.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);

    const compressed = await readFile(
      `${filePath}.logstrip.log`,
      'utf8',
    );
    expect(compressed.length).toBeGreaterThan(0);
    expect(compressed).toContain('[ERROR]');
  });

  it('deny reason includes original and output paths', async () => {
    const filePath = join(workDir, 'path-test.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath));
    const json = parseJson<{
      hookSpecificOutput: { permissionDecisionReason: string };
    }>(result.stdout);

    expect(json!.hookSpecificOutput.permissionDecisionReason).toContain(
      filePath,
    );
    expect(json!.hookSpecificOutput.permissionDecisionReason).toContain(
      `${filePath}.logstrip.log`,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════
// PreToolUse - compression failure path
// ═══════════════════════════════════════════════════════════════════════

describe('PreToolUse - compression failure', () => {
  it('emits additionalContext when processLogFile throws', async () => {
    const filePath = join(workDir, 'fails-to-compress.log');
    await writeFile(filePath, CI_LOG_PASTE);

    vi.spyOn(parser, 'processLogFile').mockRejectedValueOnce(
      new Error('simulated compression failure'),
    );

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      hookSpecificOutput: {
        hookEventName: string;
        additionalContext: string;
      };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(json!.hookSpecificOutput.additionalContext).toContain(
      'compression failed',
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════
// UserPromptSubmit - log detection
// ═══════════════════════════════════════════════════════════════════════

describe('UserPromptSubmit - positive detection', () => {
  it('detects CI log paste (timestamps + log levels)', async () => {
    const result = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ decision: string; reason: string }>(
      result.stdout,
    );
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
    expect(json!.reason).toContain('LogStrip blocked');
    expect(json!.reason).toContain('tokens saved');
  });

  it('detects Java stack trace paste (log levels + stacks)', async () => {
    const result = await runHook(makeUserPromptSubmitInput(JAVA_STACK_PASTE));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ decision: string; reason: string }>(
      result.stdout,
    );
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
  });

  it('detects npm build error paste (CI markers)', async () => {
    const result = await runHook(makeUserPromptSubmitInput(NPM_BUILD_PASTE));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ decision: string; reason: string }>(
      result.stdout,
    );
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
  });

  it('detects vitest/jest result paste (FAIL + PASS + SKIP)', async () => {
    const result = await runHook(makeUserPromptSubmitInput(MIXED_CI_PASTE));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ decision: string }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// UserPromptSubmit - blocking + temp file
// ═══════════════════════════════════════════════════════════════════════

describe('UserPromptSubmit - blocking + temp file', () => {
  it('blocks the paste and writes a compressed temp file', async () => {
    const result = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ decision: string; reason: string }>(
      result.stdout,
    );
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');

    const path = extractLogPath(json!.reason);
    expect(path).not.toBeNull();
    expect(path!.endsWith('.logstrip.log')).toBe(true);

    const compressed = await readFile(path!, 'utf8');
    expect(compressed).toContain('[ERROR]');
    expect(compressed.length).toBeLessThan(CI_LOG_PASTE.length);
  });

  it('reuses the same temp path for an identical paste (content-hashed)', async () => {
    const first = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));
    const second = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));

    const firstPath = extractLogPath(
      parseJson<{ reason: string }>(first.stdout)!.reason,
    );
    const secondPath = extractLogPath(
      parseJson<{ reason: string }>(second.stdout)!.reason,
    );
    expect(firstPath).not.toBeNull();
    expect(firstPath).toBe(secondPath);
  });

  it('fails open (no block) when processLogString throws', async () => {
    vi.spyOn(parser, 'processLogString').mockRejectedValueOnce(
      new Error('simulated compression failure'),
    );

    const result = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('blocks with manual instructions when the temp dir is not writable', async () => {
    const blocker = join(workDir, 'not-a-writable-dir');
    await writeFile(blocker, 'x');

    const saved = TEMP_ENV_KEYS.map((key) => process.env[key]);
    for (const key of TEMP_ENV_KEYS) {
      process.env[key] = blocker;
    }

    try {
      const result = await runHook(makeUserPromptSubmitInput(CI_LOG_PASTE));
      expect(result.exitCode).toBe(0);

      const json = parseJson<{ decision: string; reason: string }>(
        result.stdout,
      );
      expect(json).not.toBeNull();
      expect(json!.decision).toBe('block');
      expect(json!.reason).toContain('logstrip <file>');
      expect(extractLogPath(json!.reason)).toBeNull();
    } finally {
      TEMP_ENV_KEYS.forEach((key, index) => {
        const previous = saved[index];
        if (previous === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = previous;
        }
      });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// UserPromptSubmit - negative cases
// ═══════════════════════════════════════════════════════════════════════

describe('UserPromptSubmit - negative cases', () => {
  it('skips short messages (< 5 lines)', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(SHORT_NON_LOG),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips normal code discussion', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(CODE_DISCUSSION),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips empty prompt', async () => {
    const result = await runHook(makeUserPromptSubmitInput(''));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips content with only one heuristic match', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(SINGLE_HEURISTIC),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips prompt with null value', async () => {
    const result = await runHook({
      hook_event_name: 'UserPromptSubmit',
      prompt: null,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('skips prompt with missing prompt field', async () => {
    const result = await runHook({
      hook_event_name: 'UserPromptSubmit',
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// UserPromptSubmit - boundary conditions
// ═══════════════════════════════════════════════════════════════════════

describe('UserPromptSubmit - boundary conditions', () => {
  const boundaryLogLines = [
    '2024-01-15 10:23:45 [ERROR] line 1',
    '2024-01-15 10:23:46 [ERROR] line 2',
    '2024-01-15 10:23:47 [WARN]  line 3',
    '2024-01-15 10:23:48 [INFO]  line 4',
    '2024-01-15 10:23:49 [ERROR] line 5',
  ].join('\n');

  it('triggers on exactly 5 lines with 2+ heuristic matches', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(boundaryLogLines),
    );
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
  });

  const fourLineLog = [
    '2024-01-15 10:23:45 [ERROR] line 1',
    '2024-01-15 10:23:46 [ERROR] line 2',
    '2024-01-15 10:23:47 [WARN]  line 3',
    '2024-01-15 10:23:48 [INFO]  line 4',
  ].join('\n');

  it('skips exactly 4 lines even with 2+ heuristic matches', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(fourLineLog),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('triggers on exactly score=2 (timestamps + levels only)', async () => {
    const twoHeuristicPaste = [
      '2024-01-15 10:23:45 [ERROR] something',
      '2024-01-15 10:23:46 [ERROR] something',
      '2024-01-15 10:23:47 [WARN]  something',
      '2024-01-15 10:23:48 [INFO]  something',
      '2024-01-15 10:23:49 [ERROR] something',
    ].join('\n');

    const result = await runHook(
      makeUserPromptSubmitInput(twoHeuristicPaste),
    );
    const json = parseJson<{
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
  });

  it('awards the deep stack-trace bonus when 3+ stack lines are present', async () => {
    const deepStackPaste = [
      'java.lang.NullPointerException',
      '    at com.example.A.run(A.java:1)',
      '    at com.example.B.run(B.java:2)',
      '    at com.example.C.run(C.java:3)',
      '    at com.example.D.run(D.java:4)',
    ].join('\n');

    const result = await runHook(
      makeUserPromptSubmitInput(deepStackPaste),
    );
    const json = parseJson<{
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Cross-host compatibility (Cursor / Copilot / camelCase aliases)
// ═══════════════════════════════════════════════════════════════════════

describe('Cross-host compatibility', () => {
  it('PreToolUse: camelCase hook_event_name triggers deny (Cursor native)', async () => {
    const filePath = join(workDir, 'cursor-camel.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook({
      hook_event_name: 'preToolUse',
      tool_name: 'Read',
      tool_input: { file_path: filePath },
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      permission: string;
      hookSpecificOutput: { permissionDecision: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.permission).toBe('deny');
    expect(json!.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('PreToolUse: hookEventName camelCase top-level key is accepted', async () => {
    const filePath = join(workDir, 'camel-top-level.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook({
      hookEventName: 'PreToolUse',
      tool_name: 'Read',
      tool_input: { file_path: filePath },
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ permission: string }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.permission).toBe('deny');
  });

  it('PreToolUse: Copilot CLI "view" tool name triggers deny on log file', async () => {
    const filePath = join(workDir, 'copilot-view.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'view',
      tool_input: { file_path: filePath },
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ permission: string }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.permission).toBe('deny');
  });

  it('PreToolUse: camelCase toolName + toolInput.filePath work together', async () => {
    const filePath = join(workDir, 'copilot-camel.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook({
      hook_event_name: 'PreToolUse',
      toolName: 'Read',
      toolInput: { filePath },
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{ permission: string }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.permission).toBe('deny');
  });

  it('PreToolUse: unknown tool name (Copilot Bash) skips silently', async () => {
    const result = await runHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'bash',
      tool_input: { command: 'cat /tmp/foo.log' },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('UserPromptSubmit: camelCase event "userPromptSubmit" triggers block', async () => {
    const result = await runHook({
      hook_event_name: 'userPromptSubmit',
      prompt: CI_LOG_PASTE,
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      decision: string;
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
    expect(json!.hookSpecificOutput.additionalContext).toContain(
      'LogStrip blocked',
    );
  });

  it('UserPromptSubmit: Copilot CLI "userPromptSubmitted" event triggers block', async () => {
    const result = await runHook({
      hook_event_name: 'userPromptSubmitted',
      prompt: CI_LOG_PASTE,
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      decision: string;
      reason: string;
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.decision).toBe('block');
    expect(json!.reason).toContain('LogStrip blocked');
    expect(json!.hookSpecificOutput.additionalContext).toContain(
      'LogStrip blocked',
    );
  });

  it('Cursor beforeSubmitPrompt: blocks with continue=false + user_message', async () => {
    const result = await runHook({
      hook_event_name: 'beforeSubmitPrompt',
      prompt: CI_LOG_PASTE,
    });
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      continue: boolean;
      user_message: string;
      decision?: string;
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.continue).toBe(false);
    expect(json!.user_message).toContain('LogStrip blocked');
    // Must NOT emit Claude-style `decision: 'block'` for Cursor; the
    // Claude-only `continue: false` semantics would otherwise abort the
    // entire Claude session in a multi-host setup.
    expect(json!.decision).toBeUndefined();
  });

  it('Cursor beforeSubmitPrompt: short prompt is silently allowed', async () => {
    const result = await runHook({
      hook_event_name: 'beforeSubmitPrompt',
      prompt: SHORT_NON_LOG,
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Unknown events
// ═══════════════════════════════════════════════════════════════════════

describe('Unknown events', () => {
  it('silently skips PostToolUse event', async () => {
    const result = await runHook({
      hook_event_name: 'PostToolUse',
      tool_name: 'Read',
      tool_input: { file_path: '/tmp/test.log' },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('silently skips Stop event', async () => {
    const result = await runHook({ hook_event_name: 'Stop' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('silently skips empty event', async () => {
    const result = await runHook({});
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('silently skips malformed JSON gracefully', async () => {
    const start = performance.now();
    const result = await runHookRaw('{not valid json');
    const elapsed = performance.now() - start;
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
    expect(elapsed).toBeLessThan(3_000);
  });

  it('silently skips empty stdin', async () => {
    const result = await runHookRaw('');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });

  it('silently skips JSON that is not an object', async () => {
    const result = await runHookRaw('"plain string"');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// stdin chunking
// ═══════════════════════════════════════════════════════════════════════

describe('stdin chunking', () => {
  it('decodes Buffer chunks delivered without an explicit utf-8 encoding', async () => {
    const payload = JSON.stringify(makePreToolUseInput('/tmp/none.log'));
    const stdin = Readable.from(
      (async function* generate() {
        for (const part of [payload.slice(0, 5), payload.slice(5)]) {
          yield Buffer.from(part, 'utf8');
        }
      })(),
    );

    const stdout = bufferWritable();
    const stderr = bufferWritable();
    const exitCode = await runCli(['hook'], {
      stdin,
      stdout,
      stderr,
      stdinIsTTY: false,
    });

    expect(exitCode).toBe(0);
    expect(stdout.value().trim()).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// stdout error propagation
// ═══════════════════════════════════════════════════════════════════════

describe('stdout error propagation', () => {
  it('propagates errors from the stdout write callback', async () => {
    const filePath = join(workDir, 'broken-stdout.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const brokenStdout = new Writable({
      write(_chunk, _encoding, cb) {
        cb(new Error('stdout write broken'));
      },
    });
    brokenStdout.on('error', () => undefined);

    await expect(
      runCli(['hook'], {
        stdin: Readable.from([
          JSON.stringify(makePreToolUseInput(filePath)),
        ]),
        stdout: brokenStdout,
        stderr: bufferWritable(),
        stdinIsTTY: false,
      }),
    ).rejects.toThrow('stdout write broken');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Hook config validation
// ═══════════════════════════════════════════════════════════════════════

describe('hook config files', () => {
  it('hooks.json is valid JSON with expected structure', async () => {
    const raw = await readFile(HOOKS_JSON, 'utf8');
    const config = JSON.parse(raw);

    expect(config.hooks).toBeDefined();
    expect(config.hooks.PreToolUse).toBeDefined();
    expect(config.hooks.UserPromptSubmit).toBeDefined();
    expect(config.hooks.PreToolUse).toBeInstanceOf(Array);
    expect(config.hooks.UserPromptSubmit).toBeInstanceOf(Array);

    const preToolUse = config.hooks.PreToolUse[0];
    expect(preToolUse.matcher).toBe('Read');
    expect(preToolUse.hooks[0].type).toBe('command');
    expect(preToolUse.hooks[0].command).toBe(HOOK_COMMAND);
    expect(preToolUse.hooks[0].timeout).toBeTypeOf('number');

    const userPrompt = config.hooks.UserPromptSubmit[0];
    expect(userPrompt.hooks[0].type).toBe('command');
    expect(userPrompt.hooks[0].command).toBe(HOOK_COMMAND);
  });

  it('cursor-hooks.json is valid JSON with Cursor format', async () => {
    const raw = await readFile(CURSOR_HOOKS_JSON, 'utf8');
    const config = JSON.parse(raw);

    expect(config.version).toBe(1);
    expect(config.hooks).toBeDefined();
    expect(config.hooks.preToolUse).toBeDefined();
    expect(config.hooks.preToolUse).toBeInstanceOf(Array);

    const preToolUse = config.hooks.preToolUse[0];
    expect(preToolUse.matcher).toBe('Read');
    expect(preToolUse.command).toBe(HOOK_COMMAND);
    expect(preToolUse.timeout).toBeTypeOf('number');

    expect(config.hooks.beforeSubmitPrompt).toBeDefined();
    expect(config.hooks.beforeSubmitPrompt).toBeInstanceOf(Array);
    const beforeSubmitPrompt = config.hooks.beforeSubmitPrompt[0];
    expect(beforeSubmitPrompt.matcher).toBe('UserPromptSubmit');
    expect(beforeSubmitPrompt.command).toBe(HOOK_COMMAND);
    expect(beforeSubmitPrompt.timeout).toBeTypeOf('number');
  });

  it('factory plugin manifest explicitly wires the shared hooks file', async () => {
    const raw = await readFile(FACTORY_PLUGIN_JSON, 'utf8');
    const config = JSON.parse(raw);

    expect(config.hooks).toBe('./hooks/hooks.json');
  });

  it.each(PLUGIN_MANIFEST_PATHS)(
    '%s wires shared hooks via ./hooks/hooks.json',
    async (relPath) => {
      const raw = await readFile(
        resolve(__dirname, '../plugins/logstrip', relPath),
        'utf8',
      );
      const config = JSON.parse(raw);
      expect(config.hooks).toBe('./hooks/hooks.json');
    },
  );

  it('cursor plugin manifest wires the cursor hooks file', async () => {
    const raw = await readFile(
      resolve(__dirname, '../plugins/logstrip/.cursor-plugin/plugin.json'),
      'utf8',
    );
    const config = JSON.parse(raw);
    expect(config.hooks).toBe('./hooks/cursor-hooks.json');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Performance - latency budgets
// ═══════════════════════════════════════════════════════════════════════

describe('performance - latency budgets', () => {
  it('negative path (non-log .ts file) completes under 100ms', async () => {
    const filePath = join(workDir, 'perf-skip.ts');
    await writeFile(filePath, 'const x = 1;');

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');
    expect(result.durationMs).toBeLessThan(100);
  });

  it('UserPromptSubmit short message completes under 100ms', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(SHORT_NON_LOG),
    );
    expect(result.exitCode).toBe(0);
    expect(result.durationMs).toBeLessThan(100);
  });

  it('UserPromptSubmit positive detection completes under 500ms', async () => {
    const result = await runHook(
      makeUserPromptSubmitInput(CI_LOG_PASTE),
    );
    expect(result.exitCode).toBe(0);
    expect(result.durationMs).toBeLessThan(500);
  });

  it('PreToolUse compression of a small log completes under 2s', async () => {
    const filePath = join(workDir, 'perf-small.log');
    await writeFile(filePath, CI_LOG_PASTE);

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.durationMs).toBeLessThan(2_000);
  });

  it('handles a 1000-line log paste under 1s', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 1000; i++) {
      const level = i % 3 === 0 ? 'ERROR' : i % 3 === 1 ? 'WARN' : 'INFO';
      lines.push(
        `2024-01-15 10:23:${String(i % 60).padStart(2, '0')}.${String(i).padStart(3, '0')} [${level}] event ${i}`,
      );
    }
    const bigPaste = lines.join('\n');

    const result = await runHook(makeUserPromptSubmitInput(bigPaste));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(result.durationMs).toBeLessThan(1_000);
  });

  it('handles a 10_000-line log file under 5s', async () => {
    const filePath = join(workDir, 'perf-large.log');
    const lines: string[] = [];
    for (let i = 0; i < 10_000; i++) {
      const level = i % 4 === 0 ? 'ERROR' : i % 4 === 1 ? 'WARN' : i % 4 === 2 ? 'INFO' : 'DEBUG';
      lines.push(
        `2024-01-15 10:${String(i % 60).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}.${String(i % 1000).padStart(3, '0')} [${level}] repeated event ${i}`,
      );
    }
    await writeFile(filePath, lines.join('\n'));

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);
    expect(result.durationMs).toBeLessThan(5_000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Performance - throughput (sequential)
// ═══════════════════════════════════════════════════════════════════════

describe('performance - sequential throughput', () => {
  it('processes 100 negative UserPromptSubmit calls under 10s', async () => {
    const start = performance.now();
    for (let i = 0; i < 100; i++) {
      const result = await runHook(
        makeUserPromptSubmitInput('Just a regular chat message'),
      );
      expect(result.exitCode).toBe(0);
    }
    const total = performance.now() - start;
    expect(total).toBeLessThan(10_000);
  });

  it('processes 50 positive UserPromptSubmit calls under 15s', async () => {
    const start = performance.now();
    for (let i = 0; i < 50; i++) {
      const result = await runHook(
        makeUserPromptSubmitInput(CI_LOG_PASTE),
      );
      expect(result.exitCode).toBe(0);
    }
    const total = performance.now() - start;
    expect(total).toBeLessThan(15_000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Integration - end-to-end flow
// ═══════════════════════════════════════════════════════════════════════

describe('integration - end-to-end compression flow', () => {
  it('compressed file contains diagnostic signal from original', async () => {
    const filePath = join(workDir, 'e2e-signal.log');
    await writeFile(filePath, CI_LOG_PASTE);

    await runHook(makePreToolUseInput(filePath));

    const compressed = await readFile(
      `${filePath}.logstrip.log`,
      'utf8',
    );
    expect(compressed).toContain('[ERROR]');
  });

  it('compressed file is smaller than original', async () => {
    const filePath = join(workDir, 'e2e-smaller.log');
    const original = CI_LOG_PASTE.repeat(10);
    await writeFile(filePath, original);

    await runHook(makePreToolUseInput(filePath));

    const compressed = await readFile(
      `${filePath}.logstrip.log`,
      'utf8',
    );
    expect(compressed.length).toBeLessThan(original.length);
  });

  it('second Read on the .logstrip.log file is not re-compressed', async () => {
    const filePath = join(workDir, 'e2e-no-recompress.log');
    await writeFile(filePath, CI_LOG_PASTE);

    await runHook(makePreToolUseInput(filePath));
    const compressed = await readFile(
      `${filePath}.logstrip.log`,
      'utf8',
    );

    const result = await runHook(
      makePreToolUseInput(`${filePath}.logstrip.log`),
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('');

    const rechecked = await readFile(
      `${filePath}.logstrip.log`,
      'utf8',
    );
    expect(rechecked).toBe(compressed);
  });

  it('refuses to read a directory disguised as a .log file (catch path)', async () => {
    const filePath = join(workDir, 'dir.log');
    await mkdir(filePath, { recursive: true });

    const result = await runHook(makePreToolUseInput(filePath));
    expect(result.exitCode).toBe(0);

    const json = parseJson<{
      hookSpecificOutput: { additionalContext: string };
    }>(result.stdout);
    expect(json).not.toBeNull();
    expect(json!.hookSpecificOutput.additionalContext).toContain(
      'compression failed',
    );
  });
});
