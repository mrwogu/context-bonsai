"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.maskPemBlock = exports.createPemBlockState = exports.shannonEntropy = exports.maskHighEntropyTokens = exports.ENTROPY_SECRET_THRESHOLD = exports.ENTROPY_MIN_TOKEN_LENGTH = exports.sanitizeLine = exports.compressJsonReport = exports.claimJsonDocument = exports.JSON_REPORT_MIN_REFERENCE_LENGTH = exports.JSON_REPORT_MAX_VARIANT_VALUES = exports.JSON_REPORT_MAX_BYTES = exports.JSON_META_NOTE_MARKER = exports.JSON_META_MARKER = exports.JSON_GROUP_MARKER = exports.planBlockDedupe = exports.isMultilingualDiagnosticLine = exports.isCascadeNoiseLine = exports.resolveAdaptiveAfterWindow = exports.neutralErrorGap = exports.buildAdaptiveAfterBounds = exports.applyTokenBudget = exports.resolveAutoMultiline = exports.effectiveMultilineMode = exports.isContinuationLine = exports.detectLogSources = exports.stackWindowSignature = exports.normalizeStackFrameLineCol = exports.createRepeatSignature = exports.TFIDF_REPEAT_THRESHOLD = exports.TFIDF_PENALTY = exports.TFIDF_MAP_LIMIT = exports.SCORE_KEEP_THRESHOLD = exports.RARITY_MIN_INPUT_LINES = exports.RARITY_BOOST = exports.MAX_REPEAT_DELTA_VALUES = exports.INTERNAL_STACK_MARKER = exports.DEFAULT_MAX_STACK_FRAMES = exports.CONTEXT_WINDOW_BEFORE = exports.CONTEXT_WINDOW_AFTER = exports.parseAggressiveness = exports.voteFormat = exports.observeFormatDrift = exports.decideFormat = exports.createFormatVoter = exports.FORMAT_DRIFT_THRESHOLD = exports.detectFormat = exports.passesSeverityFilter = exports.parseSeverityLevel = exports.inferSeverity = void 0;
exports.LogStripError = exports.saveTelemetry = exports.recordTelemetry = exports.loadTelemetry = exports.formatTelemetrySummary = exports.resolveConfigPath = exports.parseLogStripConfig = exports.LOG_SOURCE_SIGNATURES = exports.KNOWN_LOG_SOURCES = exports.shouldKeepLine = exports.scoreLineRelevance = exports.looksLikeDiagnosticLine = exports.isStackFrameLine = exports.isProgressBarLine = exports.isCiNoiseLine = exports.isInternalStackTraceLine = exports.isAccessLogNoiseLine = exports.estimateTokens = void 0;
exports.buildMergedConfig = buildMergedConfig;
exports.processLogStream = processLogStream;
exports.processLogFile = processLogFile;
exports.processLogFiles = processLogFiles;
exports.processLogString = processLogString;
exports.createLogStripTransform = createLogStripTransform;
exports.explainLogLine = explainLogLine;
exports.pathsReferToSameFile = pathsReferToSameFile;
exports.processLogStreamWithTimeout = processLogStreamWithTimeout;
const node_events_1 = require("node:events");
const node_fs_1 = require("node:fs");
const node_path_1 = __importDefault(require("node:path"));
const node_readline_1 = require("node:readline");
const node_stream_1 = require("node:stream");
const promises_1 = require("node:stream/promises");
const logstrip_config_js_1 = require("./logstrip-config.js");
const levels_js_1 = require("./aggressiveness/levels.js");
const dynamic_js_1 = require("./aggressiveness/dynamic.js");
const constants_js_1 = require("./constants.js");
const repeat_grouper_js_1 = require("./dedupe/repeat-grouper.js");
const source_detector_js_1 = require("./detection/source-detector.js");
const multiline_buffer_js_1 = require("./multiline/multiline-buffer.js");
const auto_multiline_resolver_js_1 = require("./multiline/auto-multiline-resolver.js");
const adaptive_window_js_1 = require("./context/adaptive-window.js");
const token_budget_js_1 = require("./budget/token-budget.js");
const block_deduper_js_1 = require("./dedupe/block-deduper.js");
const access_log_bucket_js_1 = require("./formats/access-log-bucket.js");
const count_min_sketch_js_1 = require("./dedupe/count-min-sketch.js");
const format_detector_js_1 = require("./formats/format-detector.js");
const format_voter_js_1 = require("./formats/format-voter.js");
const json_line_extractor_js_1 = require("./formats/json-line-extractor.js");
const json_report_js_1 = require("./formats/json-report.js");
const stack_fingerprint_js_1 = require("./dedupe/stack-fingerprint.js");
const sanitize_line_js_1 = require("./sanitize/sanitize-line.js");
const pem_block_js_1 = require("./sanitize/pem-block.js");
const severity_filter_js_1 = require("./severity/severity-filter.js");
const cascade_filter_js_1 = require("./scoring/cascade-filter.js");
const multilingual_keywords_js_1 = require("./scoring/multilingual-keywords.js");
const relevance_score_js_1 = require("./scoring/relevance-score.js");
const catalog_js_1 = require("./sources/catalog.js");
var severity_filter_js_2 = require("./severity/severity-filter.js");
Object.defineProperty(exports, "inferSeverity", { enumerable: true, get: function () { return severity_filter_js_2.inferSeverity; } });
Object.defineProperty(exports, "parseSeverityLevel", { enumerable: true, get: function () { return severity_filter_js_2.parseSeverityLevel; } });
Object.defineProperty(exports, "passesSeverityFilter", { enumerable: true, get: function () { return severity_filter_js_2.passesSeverityFilter; } });
var format_detector_js_2 = require("./formats/format-detector.js");
Object.defineProperty(exports, "detectFormat", { enumerable: true, get: function () { return format_detector_js_2.detectFormat; } });
var format_voter_js_2 = require("./formats/format-voter.js");
Object.defineProperty(exports, "FORMAT_DRIFT_THRESHOLD", { enumerable: true, get: function () { return format_voter_js_2.FORMAT_DRIFT_THRESHOLD; } });
Object.defineProperty(exports, "createFormatVoter", { enumerable: true, get: function () { return format_voter_js_2.createFormatVoter; } });
Object.defineProperty(exports, "decideFormat", { enumerable: true, get: function () { return format_voter_js_2.decideFormat; } });
Object.defineProperty(exports, "observeFormatDrift", { enumerable: true, get: function () { return format_voter_js_2.observeFormatDrift; } });
Object.defineProperty(exports, "voteFormat", { enumerable: true, get: function () { return format_voter_js_2.voteFormat; } });
var levels_js_2 = require("./aggressiveness/levels.js");
Object.defineProperty(exports, "parseAggressiveness", { enumerable: true, get: function () { return levels_js_2.parseAggressiveness; } });
var constants_js_2 = require("./constants.js");
Object.defineProperty(exports, "CONTEXT_WINDOW_AFTER", { enumerable: true, get: function () { return constants_js_2.CONTEXT_WINDOW_AFTER; } });
Object.defineProperty(exports, "CONTEXT_WINDOW_BEFORE", { enumerable: true, get: function () { return constants_js_2.CONTEXT_WINDOW_BEFORE; } });
Object.defineProperty(exports, "DEFAULT_MAX_STACK_FRAMES", { enumerable: true, get: function () { return constants_js_2.DEFAULT_MAX_STACK_FRAMES; } });
Object.defineProperty(exports, "INTERNAL_STACK_MARKER", { enumerable: true, get: function () { return constants_js_2.INTERNAL_STACK_MARKER; } });
Object.defineProperty(exports, "MAX_REPEAT_DELTA_VALUES", { enumerable: true, get: function () { return constants_js_2.MAX_REPEAT_DELTA_VALUES; } });
Object.defineProperty(exports, "RARITY_BOOST", { enumerable: true, get: function () { return constants_js_2.RARITY_BOOST; } });
Object.defineProperty(exports, "RARITY_MIN_INPUT_LINES", { enumerable: true, get: function () { return constants_js_2.RARITY_MIN_INPUT_LINES; } });
Object.defineProperty(exports, "SCORE_KEEP_THRESHOLD", { enumerable: true, get: function () { return constants_js_2.SCORE_KEEP_THRESHOLD; } });
Object.defineProperty(exports, "TFIDF_MAP_LIMIT", { enumerable: true, get: function () { return constants_js_2.TFIDF_MAP_LIMIT; } });
Object.defineProperty(exports, "TFIDF_PENALTY", { enumerable: true, get: function () { return constants_js_2.TFIDF_PENALTY; } });
Object.defineProperty(exports, "TFIDF_REPEAT_THRESHOLD", { enumerable: true, get: function () { return constants_js_2.TFIDF_REPEAT_THRESHOLD; } });
var repeat_grouper_js_2 = require("./dedupe/repeat-grouper.js");
Object.defineProperty(exports, "createRepeatSignature", { enumerable: true, get: function () { return repeat_grouper_js_2.createRepeatSignature; } });
var stack_fingerprint_js_2 = require("./dedupe/stack-fingerprint.js");
Object.defineProperty(exports, "normalizeStackFrameLineCol", { enumerable: true, get: function () { return stack_fingerprint_js_2.normalizeStackFrameLineCol; } });
Object.defineProperty(exports, "stackWindowSignature", { enumerable: true, get: function () { return stack_fingerprint_js_2.stackWindowSignature; } });
var source_detector_js_2 = require("./detection/source-detector.js");
Object.defineProperty(exports, "detectLogSources", { enumerable: true, get: function () { return source_detector_js_2.detectLogSources; } });
var multiline_buffer_js_2 = require("./multiline/multiline-buffer.js");
Object.defineProperty(exports, "isContinuationLine", { enumerable: true, get: function () { return multiline_buffer_js_2.isContinuationLine; } });
var auto_multiline_resolver_js_2 = require("./multiline/auto-multiline-resolver.js");
Object.defineProperty(exports, "effectiveMultilineMode", { enumerable: true, get: function () { return auto_multiline_resolver_js_2.effectiveMultilineMode; } });
Object.defineProperty(exports, "resolveAutoMultiline", { enumerable: true, get: function () { return auto_multiline_resolver_js_2.resolveAutoMultiline; } });
var token_budget_js_2 = require("./budget/token-budget.js");
Object.defineProperty(exports, "applyTokenBudget", { enumerable: true, get: function () { return token_budget_js_2.applyTokenBudget; } });
var adaptive_window_js_2 = require("./context/adaptive-window.js");
Object.defineProperty(exports, "buildAdaptiveAfterBounds", { enumerable: true, get: function () { return adaptive_window_js_2.buildAdaptiveAfterBounds; } });
Object.defineProperty(exports, "neutralErrorGap", { enumerable: true, get: function () { return adaptive_window_js_2.neutralErrorGap; } });
Object.defineProperty(exports, "resolveAdaptiveAfterWindow", { enumerable: true, get: function () { return adaptive_window_js_2.resolveAdaptiveAfterWindow; } });
var cascade_filter_js_2 = require("./scoring/cascade-filter.js");
Object.defineProperty(exports, "isCascadeNoiseLine", { enumerable: true, get: function () { return cascade_filter_js_2.isCascadeNoiseLine; } });
var multilingual_keywords_js_2 = require("./scoring/multilingual-keywords.js");
Object.defineProperty(exports, "isMultilingualDiagnosticLine", { enumerable: true, get: function () { return multilingual_keywords_js_2.isMultilingualDiagnosticLine; } });
var block_deduper_js_2 = require("./dedupe/block-deduper.js");
Object.defineProperty(exports, "planBlockDedupe", { enumerable: true, get: function () { return block_deduper_js_2.planBlockDedupe; } });
var json_report_js_2 = require("./formats/json-report.js");
Object.defineProperty(exports, "JSON_GROUP_MARKER", { enumerable: true, get: function () { return json_report_js_2.JSON_GROUP_MARKER; } });
Object.defineProperty(exports, "JSON_META_MARKER", { enumerable: true, get: function () { return json_report_js_2.JSON_META_MARKER; } });
Object.defineProperty(exports, "JSON_META_NOTE_MARKER", { enumerable: true, get: function () { return json_report_js_2.JSON_META_NOTE_MARKER; } });
Object.defineProperty(exports, "JSON_REPORT_MAX_BYTES", { enumerable: true, get: function () { return json_report_js_2.JSON_REPORT_MAX_BYTES; } });
Object.defineProperty(exports, "JSON_REPORT_MAX_VARIANT_VALUES", { enumerable: true, get: function () { return json_report_js_2.JSON_REPORT_MAX_VARIANT_VALUES; } });
Object.defineProperty(exports, "JSON_REPORT_MIN_REFERENCE_LENGTH", { enumerable: true, get: function () { return json_report_js_2.JSON_REPORT_MIN_REFERENCE_LENGTH; } });
Object.defineProperty(exports, "claimJsonDocument", { enumerable: true, get: function () { return json_report_js_2.claimJsonDocument; } });
Object.defineProperty(exports, "compressJsonReport", { enumerable: true, get: function () { return json_report_js_2.compressJsonReport; } });
var sanitize_line_js_2 = require("./sanitize/sanitize-line.js");
Object.defineProperty(exports, "sanitizeLine", { enumerable: true, get: function () { return sanitize_line_js_2.sanitizeLine; } });
var entropy_secret_js_1 = require("./sanitize/entropy-secret.js");
Object.defineProperty(exports, "ENTROPY_MIN_TOKEN_LENGTH", { enumerable: true, get: function () { return entropy_secret_js_1.ENTROPY_MIN_TOKEN_LENGTH; } });
Object.defineProperty(exports, "ENTROPY_SECRET_THRESHOLD", { enumerable: true, get: function () { return entropy_secret_js_1.ENTROPY_SECRET_THRESHOLD; } });
Object.defineProperty(exports, "maskHighEntropyTokens", { enumerable: true, get: function () { return entropy_secret_js_1.maskHighEntropyTokens; } });
Object.defineProperty(exports, "shannonEntropy", { enumerable: true, get: function () { return entropy_secret_js_1.shannonEntropy; } });
var pem_block_js_2 = require("./sanitize/pem-block.js");
Object.defineProperty(exports, "createPemBlockState", { enumerable: true, get: function () { return pem_block_js_2.createPemBlockState; } });
Object.defineProperty(exports, "maskPemBlock", { enumerable: true, get: function () { return pem_block_js_2.maskPemBlock; } });
var relevance_score_js_2 = require("./scoring/relevance-score.js");
Object.defineProperty(exports, "estimateTokens", { enumerable: true, get: function () { return relevance_score_js_2.estimateTokens; } });
Object.defineProperty(exports, "isAccessLogNoiseLine", { enumerable: true, get: function () { return relevance_score_js_2.isAccessLogNoiseLine; } });
Object.defineProperty(exports, "isInternalStackTraceLine", { enumerable: true, get: function () { return relevance_score_js_2.isInternalStackTraceLine; } });
Object.defineProperty(exports, "isCiNoiseLine", { enumerable: true, get: function () { return relevance_score_js_2.isCiNoiseLine; } });
Object.defineProperty(exports, "isProgressBarLine", { enumerable: true, get: function () { return relevance_score_js_2.isProgressBarLine; } });
Object.defineProperty(exports, "isStackFrameLine", { enumerable: true, get: function () { return relevance_score_js_2.isStackFrameLine; } });
Object.defineProperty(exports, "looksLikeDiagnosticLine", { enumerable: true, get: function () { return relevance_score_js_2.looksLikeDiagnosticLine; } });
Object.defineProperty(exports, "scoreLineRelevance", { enumerable: true, get: function () { return relevance_score_js_2.scoreLineRelevance; } });
Object.defineProperty(exports, "shouldKeepLine", { enumerable: true, get: function () { return relevance_score_js_2.shouldKeepLine; } });
var catalog_js_2 = require("./sources/catalog.js");
Object.defineProperty(exports, "KNOWN_LOG_SOURCES", { enumerable: true, get: function () { return catalog_js_2.KNOWN_LOG_SOURCES; } });
Object.defineProperty(exports, "LOG_SOURCE_SIGNATURES", { enumerable: true, get: function () { return catalog_js_2.LOG_SOURCE_SIGNATURES; } });
var logstrip_config_js_2 = require("./logstrip-config.js");
Object.defineProperty(exports, "parseLogStripConfig", { enumerable: true, get: function () { return logstrip_config_js_2.parseLogStripConfig; } });
Object.defineProperty(exports, "resolveConfigPath", { enumerable: true, get: function () { return logstrip_config_js_2.resolveConfigPath; } });
var telemetry_store_1 = require("./telemetry/telemetry-store");
Object.defineProperty(exports, "formatTelemetrySummary", { enumerable: true, get: function () { return telemetry_store_1.formatTelemetrySummary; } });
Object.defineProperty(exports, "loadTelemetry", { enumerable: true, get: function () { return telemetry_store_1.loadTelemetry; } });
Object.defineProperty(exports, "recordTelemetry", { enumerable: true, get: function () { return telemetry_store_1.recordTelemetry; } });
Object.defineProperty(exports, "saveTelemetry", { enumerable: true, get: function () { return telemetry_store_1.saveTelemetry; } });
class LogStripError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'LogStripError';
        this.code = code;
    }
}
exports.LogStripError = LogStripError;
// ---- Multiline-aware line reader ----
async function* readLogicalLines(lines, multilineMode, ctx) {
    if (multilineMode === 'off') {
        yield* lines;
        return;
    }
    const continuationContext = ctx ?? (0, multiline_buffer_js_1.createContinuationContext)(multilineMode);
    let buffer = [];
    for await (const line of lines) {
        if (buffer.length > 0 && (0, multiline_buffer_js_1.isContinuationLine)(line, continuationContext)) {
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
function buildMergedConfig(options = {}) {
    const fileConfig = (0, logstrip_config_js_1.loadLogStripConfig)(options.configPath);
    const config = mergeCustomConfigs(fileConfig, options.config);
    const mergedSources = [
        ...catalog_js_1.LOG_SOURCE_SIGNATURES,
    ];
    for (const sig of config.sources) {
        const existing = mergedSources.find(([name]) => name === sig.name);
        if (existing !== undefined) {
            const merged = [...new Set([...existing[1], ...sig.markers])];
            const idx = mergedSources.indexOf(existing);
            mergedSources[idx] = [sig.name, merged];
        }
        else {
            mergedSources.push([sig.name, sig.markers]);
        }
    }
    return { ...config, mergedSources };
}
function mergeCustomConfigs(base, override) {
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
async function processLogStream(input, output, options = {}) {
    if (options.timeoutMs !== undefined) {
        const { timeoutMs, ...streamOptions } = options;
        return processLogStreamWithTimeout(input, output, streamOptions, timeoutMs);
    }
    throwIfAborted(options.signal);
    const requestedAggressiveness = (0, levels_js_1.parseAggressiveness)(options.aggressiveness);
    const dynamicAggressiveness = (0, dynamic_js_1.createDynamicAggressivenessState)(requestedAggressiveness);
    const merged = buildMergedConfig(options);
    const multilineMode = options.multiline ?? 'off';
    const severityLevel = options.severity;
    const maxLineLength = Math.max(1, Math.floor(options.maxLineLength ?? 100_000));
    const includePattern = options.include;
    const excludePattern = options.exclude;
    const sampleSize = options.sampleSize;
    const contextWindowBefore = Math.max(0, Math.floor(options.contextBefore ?? constants_js_1.CONTEXT_WINDOW_BEFORE));
    const contextWindowAfter = Math.max(0, Math.floor(options.contextAfter ?? constants_js_1.CONTEXT_WINDOW_AFTER));
    // Adaptive context window: ON by default in auto mode. Explicit context
    // sizes (contextBefore/contextAfter) opt out so a caller-pinned window is
    // always honored verbatim.
    const adaptiveContext = options.adaptiveContext ??
        (requestedAggressiveness === 'auto' &&
            options.contextBefore === undefined &&
            options.contextAfter === undefined);
    const adaptiveBounds = (0, adaptive_window_js_1.buildAdaptiveAfterBounds)(contextWindowAfter);
    let linesSinceError = (0, adaptive_window_js_1.neutralErrorGap)(adaptiveBounds);
    const dedupeEnabled = options.dedupe !== false && options.outputFormat !== 'jsonl-preserve';
    // Behavioral detection/compression boosters are ON by default in auto mode;
    // pass the matching option explicitly as false (CLI: --no-*) to disable.
    const collapseRepeatedStacks = options.collapseRepeatedStacks !== false;
    // Template mining: near-identical lines differing only in a number after a
    // generic word label fold into one [xN] group with a delta list.
    const templateMining = options.templateMining !== false;
    const baseRepeatSignature = (line) => (0, repeat_grouper_js_1.createRepeatSignature)(line, templateMining);
    const repeatSignature = collapseRepeatedStacks
        ? (line) => (0, stack_fingerprint_js_1.stackWindowSignature)(line) ?? baseRepeatSignature(line)
        : baseRepeatSignature;
    // App-stack truncation: cap consecutive application stack frames per trace.
    const maxStackFrames = options.maxStackFrames !== undefined
        ? Math.floor(options.maxStackFrames)
        : constants_js_1.DEFAULT_MAX_STACK_FRAMES;
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
    const formatSampleSize = Math.max(2, Math.floor(options.formatDetectionSampleSize ?? constants_js_1.DEFAULT_FORMAT_SAMPLE));
    const formatVoter = (0, format_voter_js_1.createFormatVoter)(formatSampleSize);
    let formatVoteApplied = false;
    const tokenEstimator = options.tokenEstimator;
    const maxTokens = options.maxTokens !== undefined ? Math.max(0, Math.floor(options.maxTokens)) : undefined;
    const collapseBlocks = options.collapseBlocks !== undefined
        ? Math.max(2, Math.floor(options.collapseBlocks))
        : undefined;
    // A single deferred-output buffer backs both the block-collapse and
    // token-budget post-passes (only the small, already-compressed output is
    // buffered; raw input still streams line-by-line).
    const outputBuffer = maxTokens !== undefined || collapseBlocks !== undefined ? [] : null;
    let inputTokensFromEstimator = 0;
    let outputTokensFromEstimator = 0;
    // Compile custom patterns once per stream
    const customDiagnosticRegexes = merged.diagnosticPatterns.map((p) => compileConfigRegex(p, 'u'));
    const customIgnoreRegexes = merged.ignorePatterns.map((p) => compileConfigRegex(p, 'u'));
    const customInternalStackRegexes = merged.internalStackPatterns.map((p) => compileConfigRegex(p, 'u'));
    const customSanitizeRules = merged.sanitizePatterns.map((r) => ({ regex: compileConfigRegex(r.pattern, r.flags ?? 'gu'), replacement: r.replacement }));
    const stats = createEmptyStats();
    const pemState = (0, pem_block_js_1.createPemBlockState)();
    const detectedSourceState = (0, source_detector_js_1.createSourceDetectionState)(merged.mergedSources);
    // TF-IDF: frequency counter for sanitized lines.
    // Count-Min Sketch provides constant-memory approximate counting
    // (~128 KB regardless of stream size).
    const seenLines = new count_min_sketch_js_1.CountMinSketch(8192, 4);
    // Context window: ring-buffer of soft-scored lines pending near-error promotion
    const contextBefore = [];
    // Access-log burst bucket: collapse repeated 2xx/3xx access-log lines in
    // the context-before buffer so error context is not drowned by health checks.
    let accessBucket = null;
    let afterContextRemaining = 0;
    // Auto-source multiline: share the context so detected sources can steer grouping.
    const multilineCtx = multilineMode === 'auto-source'
        ? (0, multiline_buffer_js_1.createContinuationContext)(multilineMode)
        : undefined;
    const rawLines = (0, node_readline_1.createInterface)({ input, crlfDelay: Infinity });
    const lines = readLogicalLines(rawLines, multilineMode, multilineCtx);
    // Structured JSON document (test report / scanner export): claim it before
    // the line pipeline, which would drop structural lines and emit invalid
    // JSON. Only the capped candidate document is ever buffered; everything
    // else is replayed into the streaming loop unchanged.
    let activeLines = lines;
    if (options.jsonReport !== false) {
        const claim = await (0, json_report_js_1.claimJsonDocument)(lines, Math.max(1, Math.floor(options.jsonReportMaxBytes ?? json_report_js_1.JSON_REPORT_MAX_BYTES)));
        if (claim.doc !== undefined) {
            return emitJsonReport(claim.doc, output, stats, detectedSourceState, tokenEstimator);
        }
        activeLines = claim.replay;
    }
    const pendingGroups = [];
    // Signature index over pendingGroups so wide --dedupe-window stays O(1).
    const pendingBySignature = new Map();
    let hidingInternalStack = false;
    let detectedFormat;
    let outputLineCount = 0;
    const recordDecision = (decision) => {
        options.onDecision?.(decision);
        (0, dynamic_js_1.recordLineDecision)(dynamicAggressiveness, decision);
    };
    const emitOutputLine = async (line, score = 0) => {
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
    const estimateOutputLineTokens = (line) => tokenEstimator !== undefined
        ? estimateLineTokens(tokenEstimator, `${line}\n`)
        : (0, relevance_score_js_1.estimateTokens)(countWords(line));
    const flushGroup = async (group) => {
        const line = group.count > 1
            ? `[x${group.count}] ${(0, repeat_grouper_js_1.renderRepeatGroup)(group)}`
            : group.firstLine;
        if (group.count > 1) {
            stats.duplicateLines += group.count - 1;
        }
        await emitOutputLine(line, group.score);
    };
    const shiftPendingGroup = () => {
        const group = pendingGroups.shift();
        pendingBySignature.delete(group.signature);
        return group;
    };
    const flushPendingGroups = async () => {
        while (pendingGroups.length > 0) {
            await flushGroup(shiftPendingGroup());
        }
    };
    const emitCandidate = async (line, score = 0) => {
        if (!dedupeEnabled) {
            await flushPendingGroups();
            await emitOutputLine(line, score);
            return;
        }
        const signature = repeatSignature(line);
        const existing = pendingBySignature.get(signature);
        if (existing !== undefined) {
            (0, repeat_grouper_js_1.addRepeatGroupLine)(existing, line, score, templateMining);
            return;
        }
        const group = (0, repeat_grouper_js_1.createRepeatGroup)(line, score, signature);
        pendingGroups.push(group);
        pendingBySignature.set(signature, group);
        if (pendingGroups.length > dedupeWindowSize) {
            await flushGroup(shiftPendingGroup());
        }
    };
    // Flush buffered context lines (retroactive promotion near an error)
    const flushContextBefore = async () => {
        const ejected = (0, access_log_bucket_js_1.flushAccessBucket)(accessBucket);
        if (ejected !== null)
            contextBefore.push(ejected);
        accessBucket = null;
        for (const buffered of contextBefore) {
            await emitCandidate(buffered);
        }
        contextBefore.length = 0;
    };
    // Emit the pending app-stack truncation marker (frames beyond
    // maxStackFrames collapse into a single count line).
    const flushStackTruncation = async () => {
        if (truncatedAppFrames === 0) {
            return;
        }
        const marker = `[... ${truncatedAppFrames} more application stack frames ...]`;
        truncatedAppFrames = 0;
        await emitCandidate(marker, constants_js_1.SCORE_KEEP_THRESHOLD);
    };
    // Open the context window for a kept error: flush the before-context, open
    // the after-context window (sized by error density in auto mode), and reset
    // the error-distance counter that drives that sizing.
    const openContextWindow = async () => {
        await flushContextBefore();
        afterContextRemaining = adaptiveContext
            ? (0, adaptive_window_js_1.resolveAdaptiveAfterWindow)(linesSinceError, adaptiveBounds)
            : contextWindowAfter;
        linesSinceError = 0;
    };
    const dropLine = (line, physicalLineCount, reason) => {
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
    for await (const rawLine of activeLines) {
        throwIfAborted(options.signal);
        let line = String(rawLine);
        const physicalLineCount = line.split('\n').length;
        (0, source_detector_js_1.collectDetectedSourceHits)(line, detectedSourceState);
        // Update auto-source multiline context when the top detected source changes.
        if (multilineCtx !== undefined) {
            const [top] = (0, source_detector_js_1.rankDetectedSources)(detectedSourceState, 1);
            const resolved = (0, auto_multiline_resolver_js_1.effectiveMultilineMode)('auto-source', top !== undefined ? [top] : []);
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
                const fmt = (0, format_detector_js_1.detectFormat)(line);
                if (fmt !== 'unknown')
                    detectedFormat = fmt;
            }
            if (!formatVoteApplied) {
                const voted = (0, format_voter_js_1.voteFormat)(formatVoter, line);
                if (formatVoter.decided) {
                    formatVoteApplied = true;
                    if (voted !== undefined)
                        detectedFormat = voted;
                }
            }
            else {
                // Mid-stream drift: a sustained run of differently-formatted lines
                // (e.g. plaintext boot output then JSON) re-elects the format.
                const drifted = (0, format_voter_js_1.observeFormatDrift)(formatVoter, line);
                if (drifted !== undefined)
                    detectedFormat = drifted;
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
        if (severityLevel !== undefined && !(0, severity_filter_js_1.passesSeverityFilter)(line, severityLevel)) {
            dropLine(line, physicalLineCount, 'severity');
            continue;
        }
        // CI noise: timestamp-only, K8s Normal, rate-limited
        if ((0, relevance_score_js_1.isCiNoiseLine)(line)) {
            dropLine(line, physicalLineCount, 'ci-noise');
            continue;
        }
        // CI noise: progress bars
        if ((0, relevance_score_js_1.isProgressBarLine)(line)) {
            dropLine(line, physicalLineCount, 'progress');
            continue;
        }
        // Access log noise: health checks, static assets, metrics with non-error status
        if ((0, relevance_score_js_1.isAccessLogNoiseLine)(line)) {
            dropLine(line, physicalLineCount, 'ci-noise');
            continue;
        }
        // Noise tags (INFO/DEBUG/TRACE/VERBOSE) are silently dropped without
        // disturbing afterContextRemaining so that sparse INFO lines between
        // errors do not close the context window prematurely.
        if ((0, relevance_score_js_1.isIgnoredLogLine)(line)) {
            dropLine(line, physicalLineCount, 'ignored-tag');
            continue;
        }
        // Root-cause anchoring: drop downstream cascade restatements so the
        // original error stands out.
        if (rootCause && (0, cascade_filter_js_1.isCascadeNoiseLine)(line)) {
            dropLine(line, physicalLineCount, 'cascade');
            continue;
        }
        // PEM block masking (before sanitizeLine so IPs inside PEM are not double-annotated)
        const masked = (0, pem_block_js_1.maskPemBlock)(line, pemState);
        if (masked === null) {
            dropLine(line, physicalLineCount, 'custom-ignore');
            continue;
        }
        line = masked;
        let sanitized = (0, sanitize_line_js_1.sanitizeLine)(line, options.preserveIdSuffix ?? 0);
        // Apply custom sanitize rules
        for (const rule of customSanitizeRules) {
            sanitized = sanitized.replace(rule.regex, rule.replacement);
        }
        // Internal stack-frame collapsing (priority over scoring)
        const isCustomInternalStack = customInternalStackRegexes.length > 0 &&
            customInternalStackRegexes.some((r) => testRegex(r, sanitized));
        const skipInternalStack = detectedFormat === 'json' && sanitized.startsWith('{');
        if (!skipInternalStack &&
            ((0, relevance_score_js_1.isInternalStackTraceLine)(sanitized) || isCustomInternalStack)) {
            stats.hiddenInternalStackLines += physicalLineCount;
            if (!hidingInternalStack) {
                appStackRun = 0;
                await flushStackTruncation();
                await flushContextBefore();
                await emitCandidate(constants_js_1.INTERNAL_STACK_MARKER, constants_js_1.SCORE_KEEP_THRESHOLD);
                hidingInternalStack = true;
                afterContextRemaining = 0;
            }
            recordDecision({
                line,
                sanitizedLine: constants_js_1.INTERNAL_STACK_MARKER,
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
        sanitized = (0, stack_fingerprint_js_1.normalizeStackFrameLineCol)(sanitized);
        // TF-IDF: track how many times this sanitized form has appeared.
        // Count-Min Sketch provides approximate counts in constant memory.
        const seenCount = seenLines.increment(sanitized);
        // Structured JSON-line scoring (pino/winston/bunyan): when the detected
        // format is JSON, use the parsed level field for deterministic keep/drop
        // decisions instead of regex-matching the raw text.
        let jsonParsedScore;
        if (detectedFormat === 'json') {
            const parsed = (0, json_line_extractor_js_1.scoreJsonLine)(sanitized);
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
        const effectiveAggressiveness = dynamicAggressiveness.effective;
        let score = jsonParsedScore ?? (0, relevance_score_js_1.scoreLineRelevance)(sanitized, effectiveAggressiveness, seenCount, stats.inputLines);
        // Custom diagnostic patterns contribute +50 per match (same as built-in DIAGNOSTIC_PATTERN)
        for (const regex of customDiagnosticRegexes) {
            if (testRegex(regex, sanitized)) {
                score += 50;
                break;
            }
        }
        if (multilingual && (0, multilingual_keywords_js_1.isMultilingualDiagnosticLine)(sanitized)) {
            score += 50;
        }
        score += (0, source_detector_js_1.scoreSourceDiagnosticBoost)(sanitized, detectedSourceState, stats.inputLines);
        if (score >= constants_js_1.SCORE_KEEP_THRESHOLD) {
            // App-stack truncation: keep the first maxStackFrames consecutive
            // frames of a trace, collapse the rest into a single count marker.
            if (stackFramesLimited && (0, relevance_score_js_1.isStackFrameLine)(sanitized)) {
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
            }
            else {
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
        }
        else if (afterContextRemaining > 0) {
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
        }
        else if (score >= 0) {
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
                const { bucket, ejected, passThrough } = (0, access_log_bucket_js_1.accessBucketPush)(accessBucket, sanitized);
                accessBucket = bucket;
                if (ejected !== null) {
                    contextBefore.push(ejected);
                }
                if (passThrough !== null) {
                    contextBefore.push(passThrough);
                }
            }
            else {
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
        }
        else {
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
        detectedFormat = (0, format_voter_js_1.decideFormat)(formatVoter);
    }
    // Unterminated PEM block guard
    if (pemState.inside) {
        const warningLine = '[PEM block unterminated - input redacted]';
        stats.outputWords += countWords(warningLine);
        stats.outputBytes += Buffer.byteLength(`${warningLine}\n`, 'utf8');
        stats.truncatedLines = stats.truncatedLines + 1;
        await emitOutputLine(warningLine, Number.MAX_SAFE_INTEGER);
    }
    await flushPendingGroups();
    if (outputBuffer !== null) {
        let buffered = outputBuffer;
        if (collapseBlocks !== undefined) {
            const plan = (0, block_deduper_js_1.planBlockDedupe)(buffered.map((item) => item.text), collapseBlocks);
            if (plan.removedLines > 0) {
                stats.duplicateLines += plan.removedLines;
                const rebuilt = [];
                for (const op of plan.ops) {
                    if (op.kind === 'line') {
                        rebuilt.push(buffered[op.index]);
                    }
                    else {
                        const text = `[block x${op.count}]`;
                        rebuilt.push({ text, score: 0, tokens: estimateOutputLineTokens(text) });
                    }
                }
                buffered = rebuilt;
            }
        }
        if (maxTokens !== undefined) {
            const budgeted = (0, token_budget_js_1.applyTokenBudget)(buffered, maxTokens);
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
    const inputTokens = tokenEstimator === undefined
        ? (0, relevance_score_js_1.estimateTokens)(stats.inputWords)
        : inputTokensFromEstimator;
    const outputTokens = tokenEstimator === undefined
        ? (0, relevance_score_js_1.estimateTokens)(stats.outputWords)
        : outputTokensFromEstimator;
    const savedTokens = Math.max(inputTokens - outputTokens, 0);
    const savingsPercent = inputTokens === 0 ? 0 : Math.round((savedTokens / inputTokens) * 10000) / 100;
    return {
        stats,
        inputTokens,
        outputTokens,
        savedTokens,
        savingsPercent,
        detectedSources: (0, source_detector_js_1.rankDetectedSources)(detectedSourceState),
        detectedFormat,
    };
}
async function emitJsonReport(doc, output, stats, detectedSourceState, tokenEstimator) {
    let inputTokensFromEstimator = 0;
    let outputTokensFromEstimator = 0;
    for (const line of doc.text.split('\n')) {
        stats.inputLines += 1;
        stats.inputWords += countWords(line);
        stats.inputBytes += Buffer.byteLength(`${line}\n`, 'utf8');
        (0, source_detector_js_1.collectDetectedSourceHits)(line, detectedSourceState);
        if (tokenEstimator !== undefined) {
            inputTokensFromEstimator += estimateLineTokens(tokenEstimator, `${line}\n`);
        }
    }
    const compression = (0, json_report_js_1.compressJsonReport)(doc.value);
    for (const line of compression.text.split('\n')) {
        if (tokenEstimator !== undefined) {
            outputTokensFromEstimator += estimateLineTokens(tokenEstimator, `${line}\n`);
        }
        await writeOutputLine(output, line, stats);
    }
    stats.duplicateLines += compression.duplicateEntries;
    stats.droppedLines = Math.max(0, stats.inputLines - stats.outputLines);
    const inputTokens = tokenEstimator === undefined
        ? (0, relevance_score_js_1.estimateTokens)(stats.inputWords)
        : inputTokensFromEstimator;
    const outputTokens = tokenEstimator === undefined
        ? (0, relevance_score_js_1.estimateTokens)(stats.outputWords)
        : outputTokensFromEstimator;
    const savedTokens = Math.max(inputTokens - outputTokens, 0);
    const savingsPercent = inputTokens === 0 ? 0 : Math.round((savedTokens / inputTokens) * 10000) / 100;
    return {
        stats,
        inputTokens,
        outputTokens,
        savedTokens,
        savingsPercent,
        detectedSources: (0, source_detector_js_1.rankDetectedSources)(detectedSourceState),
        detectedFormat: 'json',
    };
}
async function processLogFile(inputPath, outputPath, options = {}) {
    if (pathsReferToSameFile(inputPath, outputPath)) {
        throw new LogStripError('SAME_INPUT_OUTPUT', 'Input and output paths must be different; refusing to overwrite the input log');
    }
    const input = (0, node_fs_1.createReadStream)(inputPath, { encoding: 'utf8' });
    const output = (0, node_fs_1.createWriteStream)(outputPath, { encoding: 'utf8' });
    try {
        const result = await processLogStream(input, output, options);
        output.end();
        await (0, promises_1.finished)(output);
        return { ...result, outputPath };
    }
    catch (error) {
        input.destroy();
        output.destroy();
        throw error;
    }
}
async function processLogFiles(jobs, options = {}) {
    const results = [];
    for (const job of jobs) {
        results.push(await processLogFile(job.inputPath, job.outputPath, {
            ...options,
            ...job.options,
        }));
    }
    return results;
}
async function processLogString(inputText, options = {}) {
    const chunks = [];
    const output = new node_stream_1.Writable({
        write(chunk, _encoding, callback) {
            chunks.push(String(chunk));
            callback();
        },
    });
    const result = await processLogStream(node_stream_1.Readable.from([inputText]), output, options);
    return { ...result, output: chunks.join('') };
}
function createLogStripTransform(options = {}) {
    const input = new node_stream_1.PassThrough();
    let transform;
    let releaseBackpressure;
    const output = new node_stream_1.Writable({
        write(chunk, encoding, callback) {
            if (transform.push(chunk, encoding)) {
                callback();
                return;
            }
            releaseBackpressure = callback;
        },
    });
    const result = processLogStream(input, output, options);
    transform = new node_stream_1.Transform({
        highWaterMark: 1,
        transform(chunk, encoding, callback) {
            input.write(chunk, encoding, callback);
        },
        flush(callback) {
            input.end();
            result.then(() => callback(), callback);
        },
        read(size) {
            node_stream_1.Transform.prototype._read.call(this, size);
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
    result.catch((error) => {
        transform.destroy(error);
    });
    return Object.assign(transform, { result });
}
function explainLogLine(line, options = {}) {
    const merged = buildMergedConfig(options);
    const includePattern = options.include;
    const excludePattern = options.exclude;
    const severityLevel = options.severity;
    if (line.trim().length === 0) {
        return createDecision(line, undefined, false, 'empty');
    }
    if (includePattern !== undefined && !testRegex(includePattern, line)) {
        return createDecision(line, undefined, false, 'include-filter');
    }
    if (excludePattern !== undefined && testRegex(excludePattern, line)) {
        return createDecision(line, undefined, false, 'exclude-filter');
    }
    const customIgnoreRegexes = merged.ignorePatterns.map((p) => compileConfigRegex(p, 'u'));
    if (customIgnoreRegexes.some((r) => testRegex(r, line))) {
        return createDecision(line, undefined, false, 'custom-ignore');
    }
    if (severityLevel !== undefined && !(0, severity_filter_js_1.passesSeverityFilter)(line, severityLevel)) {
        return createDecision(line, undefined, false, 'severity');
    }
    if ((0, relevance_score_js_1.isCiNoiseLine)(line)) {
        return createDecision(line, undefined, false, 'ci-noise');
    }
    if ((0, relevance_score_js_1.isProgressBarLine)(line)) {
        return createDecision(line, undefined, false, 'progress');
    }
    if ((0, relevance_score_js_1.isAccessLogNoiseLine)(line)) {
        return createDecision(line, undefined, false, 'ci-noise');
    }
    if ((0, relevance_score_js_1.isIgnoredLogLine)(line)) {
        return createDecision(line, undefined, false, 'ignored-tag');
    }
    if (options.rootCause !== false && (0, cascade_filter_js_1.isCascadeNoiseLine)(line)) {
        return createDecision(line, undefined, false, 'cascade');
    }
    let sanitized = (0, sanitize_line_js_1.sanitizeLine)(line, options.preserveIdSuffix ?? 0);
    for (const rule of merged.sanitizePatterns) {
        sanitized = sanitized.replace(compileConfigRegex(rule.pattern, rule.flags ?? 'gu'), rule.replacement);
    }
    const customInternalStackRegexes = merged.internalStackPatterns.map((p) => compileConfigRegex(p, 'u'));
    const isCustomInternalStack = customInternalStackRegexes.length > 0 &&
        customInternalStackRegexes.some((r) => testRegex(r, sanitized));
    if ((0, relevance_score_js_1.isInternalStackTraceLine)(sanitized) || isCustomInternalStack) {
        return createDecision(line, constants_js_1.INTERNAL_STACK_MARKER, true, 'internal-stack');
    }
    let score = (0, relevance_score_js_1.scoreLineRelevance)(sanitized, requestedStaticAggressiveness(options.aggressiveness));
    const customDiagnosticRegexes = merged.diagnosticPatterns.map((p) => compileConfigRegex(p, 'u'));
    for (const regex of customDiagnosticRegexes) {
        if (testRegex(regex, sanitized)) {
            score += 50;
            break;
        }
    }
    if (options.multilingual !== false && (0, multilingual_keywords_js_1.isMultilingualDiagnosticLine)(sanitized)) {
        score += 50;
    }
    if (score >= constants_js_1.SCORE_KEEP_THRESHOLD) {
        return createDecision(line, sanitized, true, 'hard-keep', score);
    }
    return createDecision(line, sanitized, false, 'low-score', score);
}
function pathsReferToSameFile(inputPath, outputPath) {
    return (node_path_1.default.resolve(inputPath).toLowerCase() ===
        node_path_1.default.resolve(outputPath).toLowerCase());
}
function compileConfigRegex(pattern, flags) {
    try {
        return new RegExp(pattern, flags);
    }
    catch (error) {
        throw new LogStripError('INVALID_CONFIG', `Invalid logstrip config regex "${pattern}": ${String(error)}`);
    }
}
function createDecision(line, sanitizedLine, kept, reason, score) {
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
function estimateLineTokens(estimator, line) {
    return Math.max(0, Math.ceil(estimator(line)));
}
function requestedStaticAggressiveness(aggressiveness) {
    return (0, levels_js_1.toStaticAggressiveness)((0, levels_js_1.parseAggressiveness)(aggressiveness));
}
function testRegex(regex, line) {
    regex.lastIndex = 0;
    return regex.test(line);
}
function throwIfAborted(signal) {
    if (signal?.aborted === true) {
        throw new LogStripError('ABORTED', 'Processing aborted');
    }
}
function createEmptyStats() {
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
function countWords(line) {
    return line.trim().match(/\S+/gu)?.length ?? 0;
}
async function writeOutputLine(output, line, stats) {
    const rendered = `${line}\n`;
    stats.outputLines += 1;
    stats.outputWords += countWords(line);
    stats.outputBytes += Buffer.byteLength(rendered, 'utf8');
    if (!output.write(rendered)) {
        await (0, node_events_1.once)(output, 'drain');
    }
}
// ---- Timeout wrapper ----
async function processLogStreamWithTimeout(input, output, options = {}, timeoutMs) {
    if (timeoutMs === undefined) {
        return processLogStream(input, output, options);
    }
    let rejectTimeout;
    const timeoutPromise = new Promise((_, reject) => {
        rejectTimeout = reject;
    });
    const timer = setTimeout(() => rejectTimeout(new LogStripError('TIMEOUT', 'Processing timed out')), timeoutMs);
    const { timeoutMs: _ignoredTimeoutMs, ...streamOptions } = options;
    try {
        return await Promise.race([
            processLogStream(input, output, streamOptions),
            timeoutPromise,
        ]);
    }
    catch (error) {
        if (error instanceof LogStripError && error.code === 'TIMEOUT') {
            input.destroy();
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
    }
    finally {
        clearTimeout(timer);
    }
}
