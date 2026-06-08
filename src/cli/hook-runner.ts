import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { processLogFile, processLogString } from '../core/logstrip-parser';
import type { LogStripStringResult } from '../core/logstrip-parser';
import type { CliIo } from './index';

const LOG_FILE_EXTENSIONS: readonly string[] = [
  '.log',
  '.out',
  '.txt',
  '.trace',
  '.err',
];

const HOOK_LOG_DETECTION_MIN_LINES = 5;
const HOOK_LOG_DETECTION_MIN_SCORE = 2;
const HOOK_STACK_TRACE_BONUS_THRESHOLD = 3;

const TIMESTAMP_PATTERN =
  /([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}|[0-9]{2}:[0-9]{2}:[0-9]{2}[.,][0-9]{3})/u;
const LOG_LEVEL_PATTERN =
  /\[(INFO|ERROR|WARN|DEBUG|TRACE|FATAL|WARNING)\]|(^|\s)(ERROR|WARNING|FATAL|INFO):|npm (ERR|WARN)!/iu;
const STACK_TRACE_PATTERN = /at [a-zA-Z][a-zA-Z0-9_$]+\.[a-zA-Z]/u;
const CI_MARKER_PATTERN =
  /(FAIL|PASS|SKIP|RUN)\b|npm ERR!|cargo (error|warning)|make\[|pytest|jest|mocha/iu;
const LINE_PREFIX_PATTERN =
  /^\s*(npm ERR|npm WARN|yarn error|FAIL|PASS|SKIP|RUN|OK|ERR!|WARN!|\[ERROR\]|\[INFO\]|\[WARN\]|\[DEBUG\]|\[FATAL\]|\[TRACE\]|FATAL:|ERROR:|WARNING:)/iu;

const COMPRESSION_FAILED_HINT =
  'LogStrip: compression failed. Analysing raw content.';

const PRE_TOOL_USE_EVENT_ALIASES: ReadonlySet<string> = new Set([
  'pretooluse',
]);
const CLAUDE_USER_PROMPT_SUBMIT_ALIASES: ReadonlySet<string> = new Set([
  'userpromptsubmit',
  'userpromptsubmitted',
]);
const CURSOR_USER_PROMPT_SUBMIT_ALIASES: ReadonlySet<string> = new Set([
  'beforesubmitprompt',
]);
const READ_TOOL_ALIASES: ReadonlySet<string> = new Set([
  'read',
  'view',
]);

interface HookEnvelope {
  hook_event_name?: unknown;
  hookEventName?: unknown;
}

interface PreToolUseEvent extends HookEnvelope {
  tool_name?: unknown;
  toolName?: unknown;
  tool_input?: { file_path?: unknown; filePath?: unknown } | null;
  toolInput?: { file_path?: unknown; filePath?: unknown } | null;
}

interface UserPromptSubmitEvent extends HookEnvelope {
  prompt?: unknown;
}

function normalizeEventName(value: unknown): string {
  return typeof value === 'string' ? value.toLowerCase() : '';
}

function isAlreadyCompressed(filePath: string): boolean {
  return filePath.endsWith('.logstrip.log') || filePath.includes('.logstrip.');
}

function isSupportedLogFile(filePath: string): boolean {
  return LOG_FILE_EXTENSIONS.some((extension) => filePath.endsWith(extension));
}

function buildTempLogPath(prompt: string): string {
  const hash = createHash('sha1').update(prompt).digest('hex').slice(0, 12);
  return join(tmpdir(), `logstrip-${hash}.logstrip.log`);
}

function buildBlockReason(
  result: LogStripStringResult,
  outputPath: string | null,
): string {
  const savings =
    `${result.savingsPercent.toFixed(0)}% smaller, ` +
    `~${result.savedTokens} tokens saved`;

  if (outputPath !== null) {
    return (
      `LogStrip blocked a raw log paste (~${result.stats.inputLines} lines). ` +
      `Pasting raw logs wastes tokens, so the prompt was not sent. ` +
      `A compressed copy (${savings}) was written to ${outputPath}. ` +
      `Re-send your request pointing the agent at that file, ` +
      `or paste its contents instead of the raw logs.`
    );
  }

  return (
    `LogStrip blocked a raw log paste (~${result.stats.inputLines} lines, ` +
    `compresses to ${savings}). Pasting raw logs wastes tokens, so the prompt ` +
    `was not sent. Save the logs to a file and run ` +
    '`logstrip <file> -o <file>.logstrip.log`, then re-send referencing the ' +
    'compressed file or paste its contents.'
  );
}

function countMatchingLines(text: string, pattern: RegExp): number {
  let count = 0;
  for (const line of text.split(/\r?\n/u)) {
    if (pattern.test(line)) {
      count += 1;
    }
  }
  return count;
}

function emit(stream: NodeJS.WritableStream, payload: unknown): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    stream.write(JSON.stringify(payload), (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

async function readStdinJson(stdin: NodeJS.ReadableStream): Promise<unknown> {
  let buffer = '';
  for await (const chunk of stdin) {
    buffer += typeof chunk === 'string' ? chunk : (chunk as Buffer).toString('utf8');
  }

  const trimmed = buffer.trim();
  if (trimmed.length === 0) {
    return null;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function extractToolName(event: PreToolUseEvent): string | null {
  if (typeof event.tool_name === 'string') return event.tool_name;
  if (typeof event.toolName === 'string') return event.toolName;
  return null;
}

function extractFilePath(event: PreToolUseEvent): string | null {
  const candidates = [event.tool_input, event.toolInput];
  for (const input of candidates) {
    if (input == null) continue;
    if (typeof input.file_path === 'string' && input.file_path.length > 0) {
      return input.file_path;
    }
    if (typeof input.filePath === 'string' && input.filePath.length > 0) {
      return input.filePath;
    }
  }
  return null;
}

function buildDenyPayload(reason: string): Record<string, unknown> {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
    permission: 'deny',
    permissionDecision: 'deny',
    permissionDecisionReason: reason,
    user_message: reason,
    agent_message: reason,
  };
}

type UserPromptDialect = 'claude' | 'cursor';

function buildBlockPayload(
  reason: string,
  dialect: UserPromptDialect,
): Record<string, unknown> {
  if (dialect === 'cursor') {
    // Cursor's beforeSubmitPrompt blocks with `continue: false`; emitting
    // Claude's `continue` flag elsewhere would stop the whole session, so we
    // branch on the originating event name.
    return {
      continue: false,
      user_message: reason,
    };
  }
  return {
    decision: 'block',
    reason,
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: reason,
    },
  };
}

async function handlePreToolUse(
  event: PreToolUseEvent,
  stdout: NodeJS.WritableStream,
): Promise<void> {
  const toolName = extractToolName(event);
  if (toolName === null || !READ_TOOL_ALIASES.has(toolName.toLowerCase())) {
    return;
  }

  const filePath = extractFilePath(event);
  if (filePath === null) {
    return;
  }

  if (isAlreadyCompressed(filePath)) {
    return;
  }
  if (!isSupportedLogFile(filePath)) {
    return;
  }
  if (!existsSync(filePath)) {
    return;
  }

  const outputFile = `${filePath}.logstrip.log`;
  try {
    await processLogFile(filePath, outputFile);
  } catch {
    await emit(stdout, {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext: COMPRESSION_FAILED_HINT,
      },
    });
    return;
  }

  const reason =
    `LogStrip: auto-compressed ${filePath} -> ${outputFile}. ` +
    'Read the compressed .logstrip.log file instead.';
  await emit(stdout, buildDenyPayload(reason));
}

async function handleUserPromptSubmit(
  event: UserPromptSubmitEvent,
  stdout: NodeJS.WritableStream,
  dialect: UserPromptDialect,
): Promise<void> {
  const prompt = event.prompt;
  if (typeof prompt !== 'string' || prompt.length === 0) {
    return;
  }

  const lineCount = prompt.split(/\r?\n/u).length;
  if (lineCount < HOOK_LOG_DETECTION_MIN_LINES) {
    return;
  }

  let score = 0;
  if (countMatchingLines(prompt, TIMESTAMP_PATTERN) >= 2) {
    score += 1;
  }
  if (countMatchingLines(prompt, LOG_LEVEL_PATTERN) >= 2) {
    score += 1;
  }

  const stackTraceLines = countMatchingLines(prompt, STACK_TRACE_PATTERN);
  if (stackTraceLines >= 1) {
    score += 1;
  }
  if (stackTraceLines >= HOOK_STACK_TRACE_BONUS_THRESHOLD) {
    score += 1;
  }

  if (countMatchingLines(prompt, CI_MARKER_PATTERN) >= 2) {
    score += 1;
  }
  if (countMatchingLines(prompt, LINE_PREFIX_PATTERN) >= 2) {
    score += 1;
  }

  if (score < HOOK_LOG_DETECTION_MIN_SCORE) {
    return;
  }

  let compressed: LogStripStringResult;
  try {
    compressed = await processLogString(prompt);
  } catch {
    return;
  }

  let outputPath: string | null = buildTempLogPath(prompt);
  try {
    await writeFile(outputPath, compressed.output, 'utf8');
  } catch {
    outputPath = null;
  }

  await emit(
    stdout,
    buildBlockPayload(buildBlockReason(compressed, outputPath), dialect),
  );
}

function resolveEventName(envelope: HookEnvelope): string {
  const explicit = normalizeEventName(envelope.hook_event_name);
  if (explicit.length > 0) return explicit;
  return normalizeEventName(envelope.hookEventName);
}

export async function runHookCommand(io: CliIo): Promise<number> {
  const parsed = await readStdinJson(io.stdin);
  if (parsed === null || typeof parsed !== 'object') {
    return 0;
  }

  const envelope = parsed as HookEnvelope;
  const eventName = resolveEventName(envelope);

  if (PRE_TOOL_USE_EVENT_ALIASES.has(eventName)) {
    await handlePreToolUse(parsed as PreToolUseEvent, io.stdout);
    return 0;
  }
  if (CLAUDE_USER_PROMPT_SUBMIT_ALIASES.has(eventName)) {
    await handleUserPromptSubmit(
      parsed as UserPromptSubmitEvent,
      io.stdout,
      'claude',
    );
    return 0;
  }
  if (CURSOR_USER_PROMPT_SUBMIT_ALIASES.has(eventName)) {
    await handleUserPromptSubmit(
      parsed as UserPromptSubmitEvent,
      io.stdout,
      'cursor',
    );
    return 0;
  }
  return 0;
}
