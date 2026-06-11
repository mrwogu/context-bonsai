import { once } from 'node:events';
import { createReadStream, createWriteStream } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { PassThrough, Readable, Transform, Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import {
  type LogStripCustomConfig,
  type LogStripSourceSignature,
  loadLogStripConfig,
} from './logstrip-config.js';
import { parseAggressiveness, toStaticAggressiveness } from './aggressiveness/levels.js';
import {
  createDynamicAggressivenessState,
  recordLineDecision,
} from './aggressiveness/dynamic.js';
import {
  CONTEXT_WINDOW_AFTER,
  CONTEXT_WINDOW_BEFORE,
  DEFAULT_FORMAT_SAMPLE,
  DEFAULT_MAX_STACK_FRAMES,
  INTERNAL_STACK_MARKER,
  SCORE_KEEP_THRESHOLD,
  TFIDF_PENALTY,
  TFIDF_REPEAT_THRESHOLD,
} from './constants.js';
import {
  addRepeatGroupLine,
  createRepeatGroup,
  createRepeatSignature,
  renderRepeatGroup,
  type RepeatGroup,
} from './dedupe/repeat-grouper.js';
import {
  collectDetectedSourceHits,
  createSourceDetectionState,
  rankDetectedSources,
  scoreSourceDiagnosticBoost,
} from './detection/source-detector.js';
import {
  type ContinuationContext,
  type MultilineMode,
  createContinuationContext,
  isContinuationLine,
} from './multiline/multiline-buffer.js';
import { effectiveMultilineMode } from './multiline/auto-multiline-resolver.js';
import {
  type AdaptiveAfterBounds,
  buildAdaptiveAfterBounds,
  neutralErrorGap,
  resolveAdaptiveAfterWindow,
} from './context/adaptive-window.js';
import { applyTokenBudget, type BudgetLine } from './budget/token-budget.js';
import { planBlockDedupe } from './dedupe/block-deduper.js';
import {
  accessBucketPush,
  flushAccessBucket,
  type AccessBucket,
} from './formats/access-log-bucket.js';
import { CountMinSketch } from './dedupe/count-min-sketch.js';
import { detectFormat } from './formats/format-detector.js';
import {
  createFormatVoter,
  decideFormat,
  observeFormatDrift,
  voteFormat,
} from './formats/format-voter.js';
import { scoreJsonLine } from './formats/json-line-extractor.js';
import {
  normalizeStackFrameLineCol,
  stackWindowSignature,
} from './dedupe/stack-fingerprint.js';
import { sanitizeLine } from './sanitize/sanitize-line.js';
import {
  createPemBlockState,
  maskPemBlock,
  type PemBlockState,
} from './sanitize/pem-block.js';
import { passesSeverityFilter } from './severity/severity-filter.js';
import { isCascadeNoiseLine } from './scoring/cascade-filter.js';
import { isMultilingualDiagnosticLine } from './scoring/multilingual-keywords.js';
import type { SeverityLevel } from './severity/severity-filter.js';
import {
  estimateTokens,
  isAccessLogNoiseLine,
  isCiNoiseLine,
  isIgnoredLogLine,
  isInternalStackTraceLine,
  isProgressBarLine,
  isStackFrameLine,
  scoreLineRelevance,
} from './scoring/relevance-score.js';
import { LOG_SOURCE_SIGNATURES } from './sources/catalog.js';
import type {
  Aggressiveness,
  LogStripDecisionReason,
  LogStripErrorCode,
  LogStripFileJob,
  LogStripLineDecision,
  LogStripOptions,
  LogStripResult,
  LogStripStats,
  LogStripStringResult,
  StaticAggressiveness,
} from './types.js';

export { inferSeverity, parseSeverityLevel, passesSeverityFilter } from './severity/severity-filter.js';
export type { SeverityLevel } from './severity/severity-filter.js';
export { detectFormat } from './formats/format-detector.js';
export {
  type FormatVoter,
  FORMAT_DRIFT_THRESHOLD,
  createFormatVoter,
  decideFormat,
  observeFormatDrift,
  voteFormat,
} from './formats/format-voter.js';
export { parseAggressiveness } from './aggressiveness/levels.js';
export {
  CONTEXT_WINDOW_AFTER,
  CONTEXT_WINDOW_BEFORE,
  DEFAULT_MAX_STACK_FRAMES,
  INTERNAL_STACK_MARKER,
  MAX_REPEAT_DELTA_VALUES,
  RARITY_BOOST,
  RARITY_MIN_INPUT_LINES,
  SCORE_KEEP_THRESHOLD,
  TFIDF_MAP_LIMIT,
  TFIDF_PENALTY,
  TFIDF_REPEAT_THRESHOLD,
} from './constants.js';
export { createRepeatSignature } from './dedupe/repeat-grouper.js';
export {
  normalizeStackFrameLineCol,
  stackWindowSignature,
} from './dedupe/stack-fingerprint.js';
export { detectLogSources } from './detection/source-detector.js';
export {
  type MultilineMode,
  isContinuationLine,
} from './multiline/multiline-buffer.js';
export {
  effectiveMultilineMode,
  resolveAutoMultiline,
} from './multiline/auto-multiline-resolver.js';
export {
  type BudgetLine,
  type BudgetResult,
  applyTokenBudget,
} from './budget/token-budget.js';
export {
  type AdaptiveAfterBounds,
  buildAdaptiveAfterBounds,
  neutralErrorGap,
  resolveAdaptiveAfterWindow,
} from './context/adaptive-window.js';
export { isCascadeNoiseLine } from './scoring/cascade-filter.js';
export { isMultilingualDiagnosticLine } from './scoring/multilingual-keywords.js';
export {
  type BlockDedupeOp,
  type BlockDedupePlan,
  planBlockDedupe,
} from './dedupe/block-deduper.js';
export { sanitizeLine } from './sanitize/sanitize-line.js';
export {
  ENTROPY_MIN_TOKEN_LENGTH,
  ENTROPY_SECRET_THRESHOLD,
  maskHighEntropyTokens,
  shannonEntropy,
} from './sanitize/entropy-secret.js';
export {
  createPemBlockState,
  maskPemBlock,
  type PemBlockState,
} from './sanitize/pem-block.js';
export {
  estimateTokens,
  isAccessLogNoiseLine,
  isInternalStackTraceLine,
  isCiNoiseLine,
  isProgressBarLine,
  isStackFrameLine,
  looksLikeDiagnosticLine,
  scoreLineRelevance,
  shouldKeepLine,
} from './scoring/relevance-score.js';
export { KNOWN_LOG_SOURCES, LOG_SOURCE_SIGNATURES } from './sources/catalog.js';
export type {
  Aggressiveness,
  LogStripDecisionReason,
  LogStripErrorCode,
  LogStripFileJob,
  LogStripLineDecision,
  LogStripOptions,
  LogStripResult,
  LogStripStats,
  LogStripStringResult,
  StaticAggressiveness,
} from './types.js';
export {
  parseLogStripConfig,
  resolveConfigPath,
} from './logstrip-config.js';
export type {
  LogStripCustomConfig,
  LogStripSourceSignature,
  SanitizeRule,
} from './logstrip-config.js';
export {
  type TelemetryEntry,
  type TelemetryStore,
  formatTelemetrySummary,
  loadTelemetry,
  recordTelemetry,
  saveTelemetry,
} from './telemetry/telemetry-store';

export class LogStripError extends Error {
  public readonly code: LogStripErrorCode;

  constructor(code: LogStripErrorCode, message: string) {
    super(message);
    this.name = 'LogStripError';
    this.code = code;
  }
}

// ---- Multiline-aware line reader ----

async function* readLogicalLines(
  lines: AsyncIterable<string>,
  multilineMode: MultilineMode,
  ctx?: ContinuationContext,
): AsyncIterable<string> {
  if (multilineMode === 'off') {
    yield* lines;
    return;
  }

  const continuationContext = ctx ?? createContinuationContext(multilineMode);
  let buffer: string[] = [];

  for await (const line of lines) {
    if (buffer.length > 0 && isContinuationLine(line, continuationContext)) {
      buffer.push(line);
      continuationContext.groupLineCount += 1;
      continuationContext.groupByteCount += Buffer.byteLength(line, 'utf8');
      continue;
    }

    if (buffer.length > 0) {
      yield buffer.join('\n');
    }

    continuationContext.previousLine = line;
    continuationContext.groupLineCount = 1;
    continuationContext.groupByteCount = Buffer.byteLength(line, 'utf8');
    buffer = [line];
  }

  if (buffer.length > 0) {
    yield buffer.join('\n');
  }
}

export function buildMergedConfig(
  options: LogStripOptions = {},
): LogStripCustomConfig & { mergedSources: readonly (readonly [string, readonly string[]])[] } {
  const fileConfig = loadLogStripConfig(options.configPath);
  const config = mergeCustomConfigs(fileConfig, options.config);
  const mergedSources: (readonly [string, readonly string[]])[] = [
    ...LOG_SOURCE_SIGNATURES,
  ];

  for (const sig of config.sources) {
    const existing = mergedSources.find(([name]) => name === sig.name);
    if (existing !== undefined) {
      const merged = [...new Set([...existing[1], ...sig.markers])];
      const idx = mergedSources.indexOf(existing);
      mergedSources[idx] = [sig.name, merged] as const;
    } else {
      mergedSources.push([sig.name, sig.markers] as const);
    }
  }

  return { ...config, mergedSources };
}

function mergeCustomConfigs(
  base: LogStripCustomConfig,
  override?: LogStripCustomConfig,
): LogStripCustomConfig {
  if (override === undefined) {
    return base;
  }

  return {
    sources: [...base.sources, ...override.sources],
    diagnosticPatterns: [
      ...base.diagnosticPatterns,
      ...override.diagnosticPatterns,
    ],
    ignorePatterns: [...base.ignorePatterns, ...override.ignorePatterns],
    sanitizePatterns: [...base.sanitizePatterns, ...override.sanitizePatterns],
    internalStackPatterns: [
      ...base.internalStackPatterns,
      ...override.internalStackPatterns,
    ],
  };
}

export async function processLogStream(
  input: NodeJS.ReadableStream,
  output: Writable,
  options: LogStripOptions = {},
): Promise<LogStripResult> {
  if (options.timeoutMs !== undefined) {
    const { timeoutMs, ...streamOptions } = options;
    return processLogStreamWithTimeout(input, output, streamOptions, timeoutMs);
  }

  throwIfAborted(options.signal);

  const requestedAggressiveness = parseAggressiveness(options.aggressiveness);
  const dynamicAggressiveness =
    createDynamicAggressivenessState(requestedAggressiveness);
  const merged = buildMergedConfig(options);
  const multilineMode = options.multiline ?? 'off';
  const severityLevel: SeverityLevel | undefined = options.severity;
  const maxLineLength = Math.max(1, Math.floor(options.maxLineLength ?? 100_000));
  const includePattern = options.include;
  const excludePattern = options.exclude;
  const sampleSize = options.sampleSize;
  const contextWindowBefore = Math.max(
    0,
    Math.floor(options.contextBefore ?? CONTEXT_WINDOW_BEFORE),
  );
  const contextWindowAfter = Math.max(
    0,
    Math.floor(options.contextAfter ?? CONTEXT_WINDOW_AFTER),
  );
  // Adaptive context window: ON by default in auto mode. Explicit context
  // sizes (contextBefore/contextAfter) opt out so a caller-pinned window is
  // always honored verbatim.
  const adaptiveContext =
    options.adaptiveContext ??
    (requestedAggressiveness === 'auto' &&
      options.contextBefore === undefined &&
      options.contextAfter === undefined);
  const adaptiveBounds: AdaptiveAfterBounds =
    buildAdaptiveAfterBounds(contextWindowAfter);
  let linesSinceError = neutralErrorGap(adaptiveBounds);
  const dedupeEnabled =
    options.dedupe !== false && options.outputFormat !== 'jsonl-preserve';
  // Behavioral detection/compression boosters are ON by default in auto mode;
  // pass the matching option explicitly as false (CLI: --no-*) to disable.
  const collapseRepeatedStacks = options.collapseRepeatedStacks !== false;
  // Template mining: near-identical lines differing only in a number after a
  // generic word label fold into one [xN] group with a delta list.
  const templateMining = options.templateMining !== false;
  const baseRepeatSignature = (line: string): string =>
    createRepeatSignature(line, templateMining);
  const repeatSignature = collapseRepeatedStacks
    ? (line: string): string => stackWindowSignature(line) ?? baseRepeatSignature(line)
    : baseRepeatSignature;
  // App-stack truncation: cap consecutive application stack frames per trace.
  const maxStackFrames =
    options.maxStackFrames !== undefined
      ? Math.floor(options.maxStackFrames)
      : DEFAULT_MAX_STACK_FRAMES;
  const stackFramesLimited = maxStackFrames > 0;
  let appStackRun = 0;
  let truncatedAppFrames = 0;
  // Sliding dedup window: 1 = adjacent-only (default), >1 collapses
  // non-adjacent duplicates seen within the last N distinct lines.
  const dedupeWindowSize = Math.max(1, Math.floor(options.dedupeWindow ?? 1));
  const rootCause = options.rootCause !== false;
  const multilingual = options.multilingual !== false;
  // Format detection is automatic: lock onto the first recognizable line for
  // the fast path, then let a majority vote over the first N non-blank lines
  // correct an unrepresentative first guess (mixed-format logs).
  const formatSampleSize = Math.max(
    2,
    Math.floor(options.formatDetectionSampleSize ?? DEFAULT_FORMAT_SAMPLE),
  );
  const formatVoter = createFormatVoter(formatSampleSize);
  let formatVoteApplied = false;
  const tokenEstimator = options.tokenEstimator;
  const maxTokens =
    options.maxTokens !== undefined ? Math.max(0, Math.floor(options.maxTokens)) : undefined;
  const collapseBlocks =
    options.collapseBlocks !== undefined
      ? Math.max(2, Math.floor(options.collapseBlocks))
      : undefined;
  // A single deferred-output buffer backs both the block-collapse and
  // token-budget post-passes (only the small, already-compressed output is
  // buffered; raw input still streams line-by-line).
  const outputBuffer: BudgetLine[] | null =
    maxTokens !== undefined || collapseBlocks !== undefined ? [] : null;
  let inputTokensFromEstimator = 0;
  let outputTokensFromEstimator = 0;

  // Compile custom patterns once per stream
  const customDiagnosticRegexes = merged.diagnosticPatterns.map(
    (p) => compileConfigRegex(p, 'u'),
  );
  const customIgnoreRegexes = merged.ignorePatterns.map(
    (p) => compileConfigRegex(p, 'u'),
  );
  const customInternalStackRegexes = merged.internalStackPatterns.map(
    (p) => compileConfigRegex(p, 'u'),
  );
  const customSanitizeRules = merged.sanitizePatterns.map(
    (r) => ({ regex: compileConfigRegex(r.pattern, r.flags ?? 'gu'), replacement: r.replacement }),
  );

  const stats = createEmptyStats();
  const pemState: PemBlockState = createPemBlockState();
  const detectedSourceState = createSourceDetectionState(merged.mergedSources);

  // TF-IDF: frequency counter for sanitized lines.
  // Count-Min Sketch provides constant-memory approximate counting
  // (~128 KB regardless of stream size).
  const seenLines = new CountMinSketch(8192, 4);

  // Context window: ring-buffer of soft-scored lines pending near-error promotion
  const contextBefore: string[] = [];

  // Access-log burst bucket: collapse repeated 2xx/3xx access-log lines in
  // the context-before buffer so error context is not drowned by health checks.
  let accessBucket: AccessBucket | null = null;
  let afterContextRemaining = 0;

  // Auto-source multiline: share the context so detected sources can steer grouping.
  const multilineCtx: ContinuationContext | undefined =
    multilineMode === 'auto-source'
      ? createContinuationContext(multilineMode)
      : undefined;

  const rawLines = createInterface({ input, crlfDelay: Infinity });
  const lines = readLogicalLines(rawLines, multilineMode, multilineCtx);
  const pendingGroups: RepeatGroup[] = [];
  // Signature index over pendingGroups so wide --dedupe-window stays O(1).
  const pendingBySignature = new Map<string, RepeatGroup>();
  let hidingInternalStack = false;
  let detectedFormat: string | undefined;
  let outputLineCount = 0;

  const recordDecision = (decision: LogStripLineDecision): void => {
    options.onDecision?.(decision);
    recordLineDecision(dynamicAggressiveness, decision);
  };

  const emitOutputLine = async (line: string, score = 0): Promise<boolean> => {
    if (sampleSize !== undefined && outputLineCount >= sampleSize) {
      stats.droppedLines += line.split('\n').length;
      recordDecision({
        line,
        kept: false,
        dropped: true,
        hardKeep: false,
        repeated: false,
        reason: 'sample-limit',
      });
      return false;
    }
    outputLineCount += 1;
    if (outputBuffer !== null) {
      outputBuffer.push({ text: line, score, tokens: estimateOutputLineTokens(line) });
      return true;
    }
    if (tokenEstimator !== undefined) {
      outputTokensFromEstimator += estimateLineTokens(tokenEstimator, `${line}\n`);
    }
    await writeOutputLine(output, line, stats);
    return true;
  };

  const estimateOutputLineTokens = (line: string): number =>
    tokenEstimator !== undefined
      ? estimateLineTokens(tokenEstimator, `${line}\n`)
      : estimateTokens(countWords(line));

  const flushGroup = async (group: RepeatGroup): Promise<void> => {
    const line =
      group.count > 1
        ? `[x${group.count}] ${renderRepeatGroup(group)}`
        : group.firstLine;

    if (group.count > 1) {
      stats.duplicateLines += group.count - 1;
    }

    await emitOutputLine(line, group.score);
  };

  const shiftPendingGroup = (): RepeatGroup => {
    const group = pendingGroups.shift()!;
    pendingBySignature.delete(group.signature);
    return group;
  };

  const flushPendingGroups = async (): Promise<void> => {
    while (pendingGroups.length > 0) {
      await flushGroup(shiftPendingGroup());
    }
  };

  const emitCandidate = async (line: string, score = 0): Promise<void> => {
    if (!dedupeEnabled) {
      await flushPendingGroups();
      await emitOutputLine(line, score);
      return;
    }

    const signature = repeatSignature(line);
    const existing = pendingBySignature.get(signature);
    if (existing !== undefined) {
      addRepeatGroupLine(existing, line, score, templateMining);
      return;
    }

    const group = createRepeatGroup(line, score, signature);
    pendingGroups.push(group);
    pendingBySignature.set(signature, group);
    if (pendingGroups.length > dedupeWindowSize) {
      await flushGroup(shiftPendingGroup());
    }
  };

  // Flush buffered context lines (retroactive promotion near an error)
  const flushContextBefore = async (): Promise<void> => {
    const ejected = flushAccessBucket(accessBucket);
    if (ejected !== null) contextBefore.push(ejected);
    accessBucket = null;

    for (const buffered of contextBefore) {
      await emitCandidate(buffered);
    }

    contextBefore.length = 0;
  };

  // Emit the pending app-stack truncation marker (frames beyond
  // maxStackFrames collapse into a single count line).
  const flushStackTruncation = async (): Promise<void> => {
    if (truncatedAppFrames === 0) {
      return;
    }
    const marker = `[... ${truncatedAppFrames} more application stack frames ...]`;
    truncatedAppFrames = 0;
    await emitCandidate(marker, SCORE_KEEP_THRESHOLD);
  };

  // Open the context window for a kept error: flush the before-context, open
  // the after-context window (sized by error density in auto mode), and reset
  // the error-distance counter that drives that sizing.
  const openContextWindow = async (): Promise<void> => {
    await flushContextBefore();
    afterContextRemaining = adaptiveContext
      ? resolveAdaptiveAfterWindow(linesSinceError, adaptiveBounds)
      : contextWindowAfter;
    linesSinceError = 0;
  };

  const dropLine = (
    line: string,
    physicalLineCount: number,
    reason: LogStripDecisionReason,
  ): void => {
    stats.droppedLines += physicalLineCount;
    hidingInternalStack = false;
    recordDecision({
      line,
      kept: false,
      dropped: true,
      hardKeep: false,
      repeated: false,
      reason,
    });
  };

  for await (const rawLine of lines) {
    throwIfAborted(options.signal);
    let line = String(rawLine);
    const physicalLineCount = line.split('\n').length;
    collectDetectedSourceHits(line, detectedSourceState);

    // Update auto-source multiline context when the top detected source changes.
    if (multilineCtx !== undefined) {
      const [top] = rankDetectedSources(detectedSourceState, 1);
      const resolved = effectiveMultilineMode('auto-source', top !== undefined ? [top] : []);
      if (resolved !== multilineCtx.effectiveMode) {
        multilineCtx.effectiveMode = resolved;
      }
    }

    stats.inputLines += physicalLineCount;
    stats.inputWords += countWords(line);
    stats.inputBytes += Buffer.byteLength(`${line}\n`, 'utf8');
    if (tokenEstimator !== undefined) {
      inputTokensFromEstimator += estimateLineTokens(tokenEstimator, `${line}\n`);
    }

    if (line.trim().length > 0) {
      if (detectedFormat === undefined) {
        const fmt = detectFormat(line);
        if (fmt !== 'unknown') detectedFormat = fmt;
      }
      if (!formatVoteApplied) {
        const voted = voteFormat(formatVoter, line);
        if (formatVoter.decided) {
          formatVoteApplied = true;
          if (voted !== undefined) detectedFormat = voted;
        }
      } else {
        // Mid-stream drift: a sustained run of differently-formatted lines
        // (e.g. plaintext boot output then JSON) re-elects the format.
        const drifted = observeFormatDrift(formatVoter, line);
        if (drifted !== undefined) detectedFormat = drifted;
      }
    }

    // Empty lines always dropped; don't disturb context state
    if (line.trim().length === 0) {
      stats.droppedLines += physicalLineCount;
      recordDecision({
        line,
        kept: false,
        dropped: true,
        hardKeep: false,
        repeated: false,
        reason: 'empty',
      });
      continue;
    }

    // Distance (in non-empty logical lines) since the last kept error. Drives
    // the adaptive context window: small gaps mean clustered, self-contextual
    // errors; large gaps mean isolated errors that warrant more context.
    linesSinceError += 1;

    if (includePattern !== undefined && !testRegex(includePattern, line)) {
      dropLine(line, physicalLineCount, 'include-filter');
      continue;
    }

    if (excludePattern !== undefined && testRegex(excludePattern, line)) {
      dropLine(line, physicalLineCount, 'exclude-filter');
      continue;
    }

    if (line.length > maxLineLength) {
      stats.truncatedLines = Number(stats.truncatedLines) + physicalLineCount;
      line = `${line.slice(0, maxLineLength)}… [truncated]`;
    }

    // Custom ignore patterns (drop matching lines early)
    if (customIgnoreRegexes.some((r) => testRegex(r, line))) {
      dropLine(line, physicalLineCount, 'custom-ignore');
      continue;
    }

    // Severity filter (Phase 1.4): drop lines below threshold
    if (severityLevel !== undefined && !passesSeverityFilter(line, severityLevel)) {
      dropLine(line, physicalLineCount, 'severity');
      continue;
    }

    // CI noise: timestamp-only, K8s Normal, rate-limited
    if (isCiNoiseLine(line)) {
      dropLine(line, physicalLineCount, 'ci-noise');
      continue;
    }

    // CI noise: progress bars
    if (isProgressBarLine(line)) {
      dropLine(line, physicalLineCount, 'progress');
      continue;
    }

    // Access log noise: health checks, static assets, metrics with non-error status
    if (isAccessLogNoiseLine(line)) {
      dropLine(line, physicalLineCount, 'ci-noise');
      continue;
    }

    // Noise tags (INFO/DEBUG/TRACE/VERBOSE) are silently dropped without
    // disturbing afterContextRemaining so that sparse INFO lines between
    // errors do not close the context window prematurely.
    if (isIgnoredLogLine(line)) {
      dropLine(line, physicalLineCount, 'ignored-tag');
      continue;
    }

    // Root-cause anchoring: drop downstream cascade restatements so the
    // original error stands out.
    if (rootCause && isCascadeNoiseLine(line)) {
      dropLine(line, physicalLineCount, 'cascade');
      continue;
    }

    // PEM block masking (before sanitizeLine so IPs inside PEM are not double-annotated)
    const masked = maskPemBlock(line, pemState);
    if (masked === null) {
      dropLine(line, physicalLineCount, 'custom-ignore');
      continue;
    }
    line = masked;

    let sanitized = sanitizeLine(line, options.preserveIdSuffix ?? 0);

    // Apply custom sanitize rules
    for (const rule of customSanitizeRules) {
      sanitized = sanitized.replace(rule.regex, rule.replacement);
    }

    // Internal stack-frame collapsing (priority over scoring)
    const isCustomInternalStack =
      customInternalStackRegexes.length > 0 &&
      customInternalStackRegexes.some((r) => testRegex(r, sanitized));
    const skipInternalStack =
      detectedFormat === 'json' && sanitized.startsWith('{');
    if (
      !skipInternalStack &&
      (isInternalStackTraceLine(sanitized) || isCustomInternalStack)
    ) {
      stats.hiddenInternalStackLines += physicalLineCount;

      if (!hidingInternalStack) {
        appStackRun = 0;
        await flushStackTruncation();
        await flushContextBefore();
        await emitCandidate(INTERNAL_STACK_MARKER, SCORE_KEEP_THRESHOLD);
        hidingInternalStack = true;
        afterContextRemaining = 0;
      }

      recordDecision({
        line,
        sanitizedLine: INTERNAL_STACK_MARKER,
        kept: true,
        dropped: false,
        hardKeep: false,
        repeated: false,
        reason: 'internal-stack',
      });
      continue;
    }

    hidingInternalStack = false;

    // Normalize stack-frame line:column references so repeated
    // stack traces with identical structure collapse via deduplication.
    // Runs after internal-stack hiding so line/col in internal frames
    // are already collapsed.
    sanitized = normalizeStackFrameLineCol(sanitized);

    // TF-IDF: track how many times this sanitized form has appeared.
    // Count-Min Sketch provides approximate counts in constant memory.
    const seenCount = seenLines.increment(sanitized);

    // Structured JSON-line scoring (pino/winston/bunyan): when the detected
    // format is JSON, use the parsed level field for deterministic keep/drop
    // decisions instead of regex-matching the raw text.
    let jsonParsedScore: number | undefined;
    if (detectedFormat === 'json') {
      const parsed = scoreJsonLine(sanitized);
      if (parsed === null) {
        dropLine(line, physicalLineCount, 'ignored-tag');
        continue;
      }
      if (parsed !== undefined) {
        // Hard-keep error/fatal/critical JSON lines; warn lines (50) fall
        // through to standard context-window buffering.
        if (parsed >= 80) {
          await openContextWindow();
          await emitCandidate(sanitized, parsed);
          recordDecision({
            line,
            sanitizedLine: sanitized,
            kept: true,
            dropped: false,
            hardKeep: false,
            repeated: false,
            reason: 'hard-keep',
          });
          continue;
        }
        jsonParsedScore = parsed;
      }
    }

    // Score the sanitized line (built-in + custom diagnostic patterns).
    // Skip regex-based scoring for JSON lines that were successfully parsed
    // (their level-based score is used instead).
    const effectiveAggressiveness: StaticAggressiveness =
      dynamicAggressiveness.effective;
    let score = jsonParsedScore ?? scoreLineRelevance(
      sanitized,
      effectiveAggressiveness,
      seenCount,
      stats.inputLines,
    );

    // Custom diagnostic patterns contribute +50 per match (same as built-in DIAGNOSTIC_PATTERN)
    for (const regex of customDiagnosticRegexes) {
      if (testRegex(regex, sanitized)) {
        score += 50;
        break;
      }
    }
    if (multilingual && isMultilingualDiagnosticLine(sanitized)) {
      score += 50;
    }
    score += scoreSourceDiagnosticBoost(sanitized, detectedSourceState, stats.inputLines);

    if (score >= SCORE_KEEP_THRESHOLD) {
      // App-stack truncation: keep the first maxStackFrames consecutive
      // frames of a trace, collapse the rest into a single count marker.
      if (stackFramesLimited && isStackFrameLine(sanitized)) {
        appStackRun += 1;
        if (appStackRun > maxStackFrames) {
          truncatedAppFrames += 1;
          stats.droppedLines += physicalLineCount;
          recordDecision({
            line,
            sanitizedLine: sanitized,
            kept: false,
            dropped: true,
            hardKeep: false,
            repeated: seenCount > 1,
            reason: 'stack-truncated',
            score,
          });
          continue;
        }
      } else {
        appStackRun = 0;
        await flushStackTruncation();
      }

      // Hard keep: flush buffered context, emit, open after-context window
      await openContextWindow();
      await emitCandidate(sanitized, score);
      recordDecision({
        line,
        sanitizedLine: sanitized,
        kept: true,
        dropped: false,
        hardKeep: true,
        repeated: seenCount > 1,
        reason: 'hard-keep',
        score,
      });
    } else if (afterContextRemaining > 0) {
      // Inside after-context window: emit regardless of score
      await emitCandidate(sanitized, score);
      afterContextRemaining -= 1;
      recordDecision({
        line,
        sanitizedLine: sanitized,
        kept: true,
        dropped: false,
        hardKeep: false,
        repeated: seenCount > 1,
        reason: 'after-context',
        score,
      });
    } else if (score >= 0) {
      // Soft: buffer in context ring (oldest evicted & counted as dropped)
      let droppedBufferedLine = false;
      if (contextWindowBefore === 0) {
        stats.droppedLines += physicalLineCount;
        recordDecision({
          line,
          sanitizedLine: sanitized,
          kept: false,
          dropped: true,
          hardKeep: false,
          repeated: seenCount > 1,
          reason: 'context-disabled',
          score,
        });
        continue;
      }

      if (contextBefore.length >= contextWindowBefore) {
        contextBefore.shift();
        stats.droppedLines += 1;
        droppedBufferedLine = true;
      }

      // Collapse access-log 2xx/3xx bursts: successive health-check lines
      // for the same endpoint are folded into a single `[xN access-log 2xx]`
      // entry so error context is not drowned by request noise.
      if (detectedFormat !== 'json') {
        const { bucket, ejected, passThrough } = accessBucketPush(accessBucket, sanitized);
        accessBucket = bucket;
        if (ejected !== null) {
          contextBefore.push(ejected);
        }
        if (passThrough !== null) {
          contextBefore.push(passThrough);
        }
      } else {
        contextBefore.push(sanitized);
      }

      recordDecision({
        line,
        sanitizedLine: sanitized,
        kept: false,
        dropped: droppedBufferedLine,
        hardKeep: false,
        repeated: seenCount > 1,
        reason: 'context-buffered',
        score,
      });
    } else {
      // Hard drop (score < 0): negative TF-IDF or aggressive WARN suppression
      stats.droppedLines += physicalLineCount;
      afterContextRemaining = 0;
      recordDecision({
        line,
        sanitizedLine: sanitized,
        kept: false,
        dropped: true,
        hardKeep: false,
        repeated: seenCount > 1,
        reason: 'low-score',
        score,
      });
    }
  }

  // A trace truncated at end-of-stream still gets its count marker.
  await flushStackTruncation();

  // Context lines left without a triggering error are discarded
  stats.droppedLines += contextBefore.length;
  contextBefore.length = 0;

  // Short stream: if no line was ever recognizable, fall back to the vote.
  if (!formatVoteApplied && detectedFormat === undefined) {
    detectedFormat = decideFormat(formatVoter);
  }

  // Unterminated PEM block guard
  if (pemState.inside) {
    const warningLine = '[PEM block unterminated - input redacted]';
    stats.outputWords += countWords(warningLine);
    stats.outputBytes += Buffer.byteLength(`${warningLine}\n`, 'utf8');
    stats.truncatedLines = stats.truncatedLines! + 1;
    await emitOutputLine(warningLine, Number.MAX_SAFE_INTEGER);
  }

  await flushPendingGroups();

  if (outputBuffer !== null) {
    let buffered: BudgetLine[] = outputBuffer;

    if (collapseBlocks !== undefined) {
      const plan = planBlockDedupe(
        buffered.map((item) => item.text),
        collapseBlocks,
      );
      if (plan.removedLines > 0) {
        stats.duplicateLines += plan.removedLines;
        const rebuilt: BudgetLine[] = [];
        for (const op of plan.ops) {
          if (op.kind === 'line') {
            rebuilt.push(buffered[op.index]);
          } else {
            const text = `[block x${op.count}]`;
            rebuilt.push({ text, score: 0, tokens: estimateOutputLineTokens(text) });
          }
        }
        buffered = rebuilt;
      }
    }

    if (maxTokens !== undefined) {
      const budgeted = applyTokenBudget(buffered, maxTokens);
      stats.droppedLines += budgeted.droppedPhysicalLines;
      buffered = budgeted.kept;
    }

    for (const item of buffered) {
      if (tokenEstimator !== undefined) {
        outputTokensFromEstimator += item.tokens;
      }
      await writeOutputLine(output, item.text, stats);
    }
  }

  const inputTokens =
    tokenEstimator === undefined
      ? estimateTokens(stats.inputWords)
      : inputTokensFromEstimator;
  const outputTokens =
    tokenEstimator === undefined
      ? estimateTokens(stats.outputWords)
      : outputTokensFromEstimator;
  const savedTokens = Math.max(inputTokens - outputTokens, 0);
  const savingsPercent =
    inputTokens === 0 ? 0 : Math.round((savedTokens / inputTokens) * 10000) / 100;

  return {
    stats,
    inputTokens,
    outputTokens,
    savedTokens,
    savingsPercent,
    detectedSources: rankDetectedSources(detectedSourceState),
    detectedFormat,
  };
}

export async function processLogFile(
  inputPath: string,
  outputPath: string,
  options: LogStripOptions = {},
): Promise<LogStripResult> {
  if (pathsReferToSameFile(inputPath, outputPath)) {
    throw new LogStripError(
      'SAME_INPUT_OUTPUT',
      'Input and output paths must be different; refusing to overwrite the input log',
    );
  }

  const input = createReadStream(inputPath, { encoding: 'utf8' });
  const output = createWriteStream(outputPath, { encoding: 'utf8' });

  try {
    const result = await processLogStream(input, output, options);
    output.end();
    await finished(output);
    return { ...result, outputPath };
  } catch (error) {
    input.destroy();
    output.destroy();
    throw error;
  }
}

export async function processLogFiles(
  jobs: readonly LogStripFileJob[],
  options: LogStripOptions = {},
): Promise<LogStripResult[]> {
  const results: LogStripResult[] = [];

  for (const job of jobs) {
    results.push(
      await processLogFile(job.inputPath, job.outputPath, {
        ...options,
        ...job.options,
      }),
    );
  }

  return results;
}

export async function processLogString(
  inputText: string,
  options: LogStripOptions = {},
): Promise<LogStripStringResult> {
  const chunks: string[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
  const result = await processLogStream(
    Readable.from([inputText]),
    output,
    options,
  );

  return { ...result, output: chunks.join('') };
}

export interface LogStripTransform extends Transform {
  readonly result: Promise<LogStripResult>;
}

export function createLogStripTransform(
  options: LogStripOptions = {},
): LogStripTransform {
  const input = new PassThrough();
  let transform: Transform;
  let releaseBackpressure: (() => void) | undefined;
  const output = new Writable({
    write(chunk, encoding, callback) {
      if (transform.push(chunk, encoding)) {
        callback();
        return;
      }
      releaseBackpressure = callback;
    },
  });

  const result = processLogStream(input, output, options);
  transform = new Transform({
    highWaterMark: 1,
    transform(chunk, encoding, callback) {
      input.write(chunk, encoding, callback);
    },
    flush(callback) {
      input.end();
      result.then(() => callback(), callback);
    },
    read(size) {
      Transform.prototype._read.call(this, size);
      const release = releaseBackpressure;
      releaseBackpressure = undefined;
      release?.();
    },
    destroy(error, callback) {
      input.destroy();
      output.destroy();
      callback(error);
    },
  });

  result.catch((error: unknown) => {
    transform.destroy(error as Error);
  });

  return Object.assign(transform, { result }) as LogStripTransform;
}

export function explainLogLine(
  line: string,
  options: LogStripOptions = {},
): LogStripLineDecision {
  const merged = buildMergedConfig(options);
  const includePattern = options.include;
  const excludePattern = options.exclude;
  const severityLevel: SeverityLevel | undefined = options.severity;

  if (line.trim().length === 0) {
    return createDecision(line, undefined, false, 'empty');
  }
  if (includePattern !== undefined && !testRegex(includePattern, line)) {
    return createDecision(line, undefined, false, 'include-filter');
  }
  if (excludePattern !== undefined && testRegex(excludePattern, line)) {
    return createDecision(line, undefined, false, 'exclude-filter');
  }

  const customIgnoreRegexes = merged.ignorePatterns.map((p) =>
    compileConfigRegex(p, 'u'),
  );
  if (customIgnoreRegexes.some((r) => testRegex(r, line))) {
    return createDecision(line, undefined, false, 'custom-ignore');
  }
  if (severityLevel !== undefined && !passesSeverityFilter(line, severityLevel)) {
    return createDecision(line, undefined, false, 'severity');
  }
  if (isCiNoiseLine(line)) {
    return createDecision(line, undefined, false, 'ci-noise');
  }
  if (isProgressBarLine(line)) {
    return createDecision(line, undefined, false, 'progress');
  }
  if (isAccessLogNoiseLine(line)) {
    return createDecision(line, undefined, false, 'ci-noise');
  }
  if (isIgnoredLogLine(line)) {
    return createDecision(line, undefined, false, 'ignored-tag');
  }
  if (options.rootCause !== false && isCascadeNoiseLine(line)) {
    return createDecision(line, undefined, false, 'cascade');
  }

  let sanitized = sanitizeLine(line, options.preserveIdSuffix ?? 0);
  for (const rule of merged.sanitizePatterns) {
    sanitized = sanitized.replace(
      compileConfigRegex(rule.pattern, rule.flags ?? 'gu'),
      rule.replacement,
    );
  }

  const customInternalStackRegexes = merged.internalStackPatterns.map((p) =>
    compileConfigRegex(p, 'u'),
  );
  const isCustomInternalStack =
    customInternalStackRegexes.length > 0 &&
    customInternalStackRegexes.some((r) => testRegex(r, sanitized));
  if (isInternalStackTraceLine(sanitized) || isCustomInternalStack) {
    return createDecision(
      line,
      INTERNAL_STACK_MARKER,
      true,
      'internal-stack',
    );
  }

  let score = scoreLineRelevance(
    sanitized,
    requestedStaticAggressiveness(options.aggressiveness),
  );
  const customDiagnosticRegexes = merged.diagnosticPatterns.map((p) =>
    compileConfigRegex(p, 'u'),
  );
  for (const regex of customDiagnosticRegexes) {
    if (testRegex(regex, sanitized)) {
      score += 50;
      break;
    }
  }
  if (options.multilingual !== false && isMultilingualDiagnosticLine(sanitized)) {
    score += 50;
  }

  if (score >= SCORE_KEEP_THRESHOLD) {
    return createDecision(line, sanitized, true, 'hard-keep', score);
  }

  return createDecision(line, sanitized, false, 'low-score', score);
}

export function pathsReferToSameFile(
  inputPath: string,
  outputPath: string,
): boolean {
  return (
    path.resolve(inputPath).toLowerCase() ===
    path.resolve(outputPath).toLowerCase()
  );
}

function compileConfigRegex(pattern: string, flags: string): RegExp {
  try {
    return new RegExp(pattern, flags);
  } catch (error) {
    throw new LogStripError(
      'INVALID_CONFIG',
      `Invalid logstrip config regex "${pattern}": ${String(error)}`,
    );
  }
}

function createDecision(
  line: string,
  sanitizedLine: string | undefined,
  kept: boolean,
  reason: LogStripDecisionReason,
  score?: number,
): LogStripLineDecision {
  return {
    line,
    sanitizedLine,
    kept,
    dropped: !kept,
    hardKeep: kept && reason === 'hard-keep',
    repeated: false,
    reason,
    score,
  };
}

function estimateLineTokens(
  estimator: (line: string) => number,
  line: string,
): number {
  return Math.max(0, Math.ceil(estimator(line)));
}

function requestedStaticAggressiveness(
  aggressiveness: Aggressiveness | undefined,
): StaticAggressiveness {
  return toStaticAggressiveness(parseAggressiveness(aggressiveness));
}

function testRegex(regex: RegExp, line: string): boolean {
  regex.lastIndex = 0;
  return regex.test(line);
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new LogStripError('ABORTED', 'Processing aborted');
  }
}

function createEmptyStats(): LogStripStats {
  return {
    inputLines: 0,
    outputLines: 0,
    inputWords: 0,
    outputWords: 0,
    inputBytes: 0,
    outputBytes: 0,
    droppedLines: 0,
    duplicateLines: 0,
    hiddenInternalStackLines: 0,
    truncatedLines: 0,
  };
}

function countWords(line: string): number {
  return line.trim().match(/\S+/gu)?.length ?? 0;
}

async function writeOutputLine(
  output: Writable,
  line: string,
  stats: LogStripStats,
): Promise<void> {
  const rendered = `${line}\n`;
  stats.outputLines += 1;
  stats.outputWords += countWords(line);
  stats.outputBytes += Buffer.byteLength(rendered, 'utf8');

  if (!output.write(rendered)) {
    await once(output, 'drain');
  }
}

// ---- Timeout wrapper ----

export async function processLogStreamWithTimeout(
  input: NodeJS.ReadableStream,
  output: Writable,
  options: LogStripOptions = {},
  timeoutMs?: number,
): Promise<LogStripResult> {
  if (timeoutMs === undefined) {
    return processLogStream(input, output, options);
  }

  let rejectTimeout!: (reason?: unknown) => void;
  const timeoutPromise = new Promise<never>((_, reject) => {
    rejectTimeout = reject;
  });
  const timer = setTimeout(
    () => rejectTimeout(new LogStripError('TIMEOUT', 'Processing timed out')),
    timeoutMs,
  );
  const { timeoutMs: _ignoredTimeoutMs, ...streamOptions } = options;

  try {
    return await Promise.race([
      processLogStream(input, output, streamOptions),
      timeoutPromise,
    ]);
  } catch (error) {
    if (error instanceof LogStripError && error.code === 'TIMEOUT') {
      (input as Readable).destroy();
      return {
        stats: createEmptyStats(),
        inputTokens: 0,
        outputTokens: 0,
        savedTokens: 0,
        savingsPercent: 0,
        timedOut: true,
      };
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
