"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isAccessLogNoiseLine = void 0;
exports.isIgnoredLogLine = isIgnoredLogLine;
exports.shouldKeepLine = shouldKeepLine;
exports.isStackFrameLine = isStackFrameLine;
exports.looksLikeDiagnosticLine = looksLikeDiagnosticLine;
exports.isInternalStackTraceLine = isInternalStackTraceLine;
exports.estimateTokens = estimateTokens;
exports.scoreLineRelevance = scoreLineRelevance;
exports.isCiNoiseLine = isCiNoiseLine;
exports.isProgressBarLine = isProgressBarLine;
const constants_js_1 = require("../constants.js");
const diagnostic_boosters_js_1 = require("./diagnostic-boosters.js");
const IGNORED_LOG_TAG_PATTERN = /\[(?:INFO|DEBUG|TRACE|VERBOSE)\]|"level"\s*:\s*"(?:info|debug|trace|verbose)"/iu;
const APACHE_ROUTINE_NOTICE_PATTERN = /^(?:\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?\s+\d{4}\]|\[TIME\])\s+\[notice\]\s+(?:workerEnv\.init\(\) ok\b|jk2_init\(\) Found child \d+ in scoreboard slot \d+\b)/iu;
const IMPORTANT_LOG_TAG_PATTERN = /\[(?:ERROR|WARN|FATAL|CRITICAL|FAIL)\]/iu;
const EXPLICIT_LOG_TAG_PATTERN = /\[[A-Z]+\]/iu;
// Frame patterns accept either raw digits or the [NN] placeholder that
// normalizeStackFrameLineCol substitutes, so frames stay recognizable
// (and scorable) after line:column normalization.
const STACK_FRAME_PATTERN = /^\s*at\s+.*(?:\(|\s).+:(?:\d+|\[NN\]):(?:\d+|\[NN\])\)?$/;
const JAVA_STACK_FRAME_PATTERN = /^\s*at\s+[\w$_.<>/]+\([^)]+:(?:\d+|\[NN\])\)$/;
const PYTHON_STACK_FRAME_PATTERN = /^\s*File\s+"[^"]+",\s+line\s+(?:\d+|\[NN\]),\s+in\s+.+$/;
const GO_STACK_FRAME_PATTERN = /^\s*(?:(?:[\w.-]+\/)+[\w./-]+|[\w.-]+\.\(\*?[\w.]+\)\.[\w.]+|[\w.-]+\.[A-Z]\w*)\(.*\)$/;
const GO_FILE_FRAME_PATTERN = /^\s*(?:\/[^\s]+|[A-Za-z]:[\\/][^\s]+):(?:\d+|\[NN\])(?:\s+\+\S+)?$/;
const GO_GOROUTINE_PATTERN = /^\s*goroutine\s+\d+\s+\[.+\]:$/iu;
const PYTHON_TRACEBACK_PATTERN = /^Traceback \(most recent call last\):$/;
const RUBY_STACK_FRAME_PATTERN = /^\s*from\s+\S+:\d+:in\s+[`'].+$/u;
const RUST_PANIC_PATTERN = /^thread '[^']*' panicked at\b/u;
const RUST_BACKTRACE_FRAME_PATTERN = /^\s*\d+:\s+(?:0x[0-9a-f]+\s+-\s+)?\S*(?:::|[<>])\S*$/u;
const RUST_FILE_FRAME_PATTERN = /^\s*at\s+\S+\.rs:\d+:\d+:?$/u;
const CSHARP_STACK_FRAME_PATTERN = /^\s*at\s+[\w.<>`+\[\],$]+\([^)]*\)(?:\s+in\s+\S+:line\s+\d+)?$/u;
const PHP_STACK_FRAME_PATTERN = /^\s*#\d+\s+(?:\{main\}|\S+\(\d+\):\s+\S+.*)$/u;
const STACK_MORE_PATTERN = /^\s*\.\.\. \d+ more$/;
const GITHUB_ACTIONS_ANNOTATION_PATTERN = /^::(?:error|warning|notice)\b/u;
const GRADLE_FAILURE_PATTERN = /\b(?:Execution failed|What went wrong|BUILD FAILED|Task failed with an exception)\b/iu;
const MAKE_ERROR_PATTERN = /^make[:\s*]+/u;
const GO_TEST_FAIL_PATTERN = /---\s*FAIL:/u;
const SYSTEMD_STATUS_PATTERN = /\b(?:Failed to start|Failed to load|Failed to listen|Failed to mount|Failed to open|Failed to connect|status=\d+\s+\w+)\b/iu;
const CIRCLECI_STEP_PATTERN = /\b(?:Spin Cancelled|Step failed|job was not approved)\b/iu;
const JENKINS_MARKER_PATTERN = /\[(?:Pipeline|Checks|FCMaker)\]/u;
const AZURE_PIPELINE_PATTERN = /^##vso\[task\.(?:LogIssue|Complete)\b/u;
const TEAMCITY_MARKER_PATTERN = /^##teamcity\[(?:buildProblem|compilationFinished|message)\b/u;
const DIAGNOSTIC_PATTERN = /\b(?:Error|Exception|AssertionError|TypeError|ReferenceError|SyntaxError|RangeError|NullPointerException|Unhandled|failed|failure|fatal|panic|refused|timeout|timed\s+out|unreachable|unavailable|disconnected|killed|aborted|crashed|terminated|unauthorized)\b/iu;
// Compound exception class names (PaymentGatewayException, FooTimeoutError…)
// where the bare-word DIAGNOSTIC_PATTERN \b boundary cannot fire.
const COMPOUND_EXCEPTION_PATTERN = /\b[A-Z]\w+(?:Exception|Error|Fault)\b/u;
const JSON_SEVERITY_PATTERN = /"(?:level|severity)"\s*:\s*"(?:fatal|error|critical|warn|warning)"/iu;
const NPM_ERROR_PATTERN = /\b(?:npm|pnpm)\s+ERR!/iu;
const YARN_ERROR_PATTERN = /\byarn\s+error\b/iu;
const SCANNER_FINDING_PATTERN = /\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|vulnerabilit(?:y|ies)|severity:\s*(?:critical|high|medium)|(?:critical|high)\s+severity)\b/iu;
const CONTAINER_FAILURE_PATTERN = /\b(?:CrashLoopBackOff|ImagePullBackOff|ErrImagePull|OOMKilled|Back[- ]off restarting failed container|failed to pull image|(?:containerd|runc).*?(?:failed|error|panic|timeout|refused)|(?:failed|error|panic|timeout|refused).*?(?:containerd|runc)|rpc error: code = Unknown desc = failed to resolve reference)\b/iu;
const INTERNAL_STACK_PATTERN = /(?:node_modules[\\/]|node:internal|internal[\\/]modules|bootstrap_node|[\\/]usr[\\/]lib[\\/]|[\\/]usr[\\/]local[\\/]lib[\\/]|[\\/]usr[\\/]local[\\/]go[\\/]src[\\/]runtime[\\/]|site-packages[\\/]|dist-packages[\\/]|\.venv[\\/]|java\.base[\\/]|jdk\.internal|org\.springframework\.|[\\/]pkg[\\/]mod[\\/]|\.cargo[\\/]registry[\\/]|[\\/]gems[\\/]|vendor[\\/]bundle[\\/]|[\\/]rustc[\\/]|\bat System\.)/iu;
const LOW_EXTRA_TAG_PATTERN = /\[(?:NOTICE|STATUS)\]/iu;
const AGGRESSIVE_WARN_PATTERN = /\[(?:WARN|WARNING)\]/iu;
const AGGRESSIVE_WARNING_SIGNAL_PATTERN = DIAGNOSTIC_PATTERN;
function isIgnoredLogLine(line) {
    return (IGNORED_LOG_TAG_PATTERN.test(line) ||
        APACHE_ROUTINE_NOTICE_PATTERN.test(line));
}
function shouldKeepLine(line) {
    if (line.trim().length === 0) {
        return false;
    }
    if (isIgnoredLogLine(line)) {
        return false;
    }
    if (IMPORTANT_LOG_TAG_PATTERN.test(line)) {
        return true;
    }
    if (!EXPLICIT_LOG_TAG_PATTERN.test(line) && looksLikeDiagnosticLine(line)) {
        return true;
    }
    return false;
}
/**
 * True for lines that are a single stack-trace frame (any supported
 * language). Excludes trace headers (goroutine/Traceback/panic) on purpose:
 * the parser's app-stack truncation counts only consecutive frames.
 */
function isStackFrameLine(line) {
    return (STACK_FRAME_PATTERN.test(line) ||
        JAVA_STACK_FRAME_PATTERN.test(line) ||
        PYTHON_STACK_FRAME_PATTERN.test(line) ||
        GO_STACK_FRAME_PATTERN.test(line) ||
        GO_FILE_FRAME_PATTERN.test(line) ||
        RUBY_STACK_FRAME_PATTERN.test(line) ||
        RUST_BACKTRACE_FRAME_PATTERN.test(line) ||
        RUST_FILE_FRAME_PATTERN.test(line) ||
        CSHARP_STACK_FRAME_PATTERN.test(line) ||
        PHP_STACK_FRAME_PATTERN.test(line));
}
function looksLikeDiagnosticLine(line) {
    return (isStackFrameLine(line) ||
        GO_GOROUTINE_PATTERN.test(line) ||
        PYTHON_TRACEBACK_PATTERN.test(line) ||
        RUST_PANIC_PATTERN.test(line) ||
        STACK_MORE_PATTERN.test(line) ||
        DIAGNOSTIC_PATTERN.test(line) ||
        COMPOUND_EXCEPTION_PATTERN.test(line) ||
        JSON_SEVERITY_PATTERN.test(line) ||
        NPM_ERROR_PATTERN.test(line) ||
        YARN_ERROR_PATTERN.test(line) ||
        SCANNER_FINDING_PATTERN.test(line) ||
        CONTAINER_FAILURE_PATTERN.test(line) ||
        GITHUB_ACTIONS_ANNOTATION_PATTERN.test(line) ||
        GRADLE_FAILURE_PATTERN.test(line) ||
        MAKE_ERROR_PATTERN.test(line) ||
        GO_TEST_FAIL_PATTERN.test(line) ||
        SYSTEMD_STATUS_PATTERN.test(line) ||
        CIRCLECI_STEP_PATTERN.test(line) ||
        JENKINS_MARKER_PATTERN.test(line) ||
        AZURE_PIPELINE_PATTERN.test(line) ||
        TEAMCITY_MARKER_PATTERN.test(line));
}
function isInternalStackTraceLine(line) {
    if (IMPORTANT_LOG_TAG_PATTERN.test(line))
        return false;
    return looksLikeDiagnosticLine(line) && INTERNAL_STACK_PATTERN.test(line);
}
function estimateTokens(wordCountOrText) {
    if (typeof wordCountOrText === 'number') {
        return Math.ceil(wordCountOrText * 1.3);
    }
    const text = wordCountOrText;
    // CJK characters count roughly 1 token each; the rest average ~4 chars per token.
    const cjk = (text.match(/[\u3000-\u9fff\uac00-\ud7af\uff00-\uffef]/gu)?.length ?? 0);
    const rest = text.length - cjk;
    return Math.ceil(cjk * 1.0 + rest / 4);
}
const HTTP_5XX_PATTERN = /\bHTTP\/\d\.\d"\s+5\d{2}\b/u;
const HTTP_4XX_PATTERN = /\bHTTP\/\d\.\d"\s+4\d{2}\b/u;
function scoreLineRelevance(line, aggressiveness, seenCount = 0, inputLines = 0) {
    if (line.trim().length === 0)
        return -Infinity;
    if (isIgnoredLogLine(line))
        return -Infinity;
    let score = 0;
    // Iterate consolidated diagnostic booster table.
    for (const b of diagnostic_boosters_js_1.DIAGNOSTIC_BOOSTERS) {
        if (b.pattern.test(line))
            score += b.score;
    }
    if (aggressiveness === 'aggressive' &&
        AGGRESSIVE_WARN_PATTERN.test(line) &&
        !AGGRESSIVE_WARNING_SIGNAL_PATTERN.test(line) &&
        !COMPOUND_EXCEPTION_PATTERN.test(line)) {
        score = -1;
    }
    if (aggressiveness === 'low' && LOW_EXTRA_TAG_PATTERN.test(line)) {
        score += 30;
    }
    if (seenCount >= constants_js_1.TFIDF_REPEAT_THRESHOLD) {
        score -= constants_js_1.TFIDF_PENALTY * (seenCount - constants_js_1.TFIDF_REPEAT_THRESHOLD + 1);
    }
    // IDF-side rarity boost: in a large stream, a diagnostic-looking line seen
    // exactly once is more likely to be the interesting one. Only lines that
    // already carry signal (score > 0) qualify, so noise is never promoted.
    if (score > 0 &&
        seenCount === 1 &&
        inputLines >= constants_js_1.RARITY_MIN_INPUT_LINES) {
        score += constants_js_1.RARITY_BOOST;
    }
    return score;
}
// ---- CI noise patterns ----
const TIMESTAMP_ONLY_PATTERN = /^\s*(?:\d{4}[-\/]\d{2}[-\/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*)$/u;
const PROGRESS_SEPARATOR_PATTERN = /^[=\-#]{20,}$/u;
const PROGRESS_INDICATOR_PATTERN = /(?:(?:Downloading|Extracting|Pulling|Pushing|Fetching|Installing|Building|Receiving|Sending)[^\n]*?\d{1,3}%|\d{1,3}%\s*(?:[|][=#>-]+|(?:\d+\.?\d*\s*(?:[A-Za-z]+(?:\/s)?|ETA|s\b))))/u;
const PROGRESS_BAR_VISUAL_PATTERN = /[|[]\s*[=#>-]{5,}[>\s]*[|\]]/u;
const K8S_NORMAL_EVENT_PATTERN = /\b(?:type:\s*'?Normal'?|Normal\s+\d+[smhd])\b/iu;
const RATE_LIMITED_MESSAGE_PATTERN = /\b(?:(?:message|last message)\s+repeated\s+\d+\s+times?|\[\s*\d+\s*times?\s*\])/iu;
function isCiNoiseLine(line) {
    if (TIMESTAMP_ONLY_PATTERN.test(line))
        return true;
    if (K8S_NORMAL_EVENT_PATTERN.test(line))
        return true;
    if (RATE_LIMITED_MESSAGE_PATTERN.test(line))
        return true;
    return false;
}
function isProgressBarLine(line) {
    const trimmed = line.trim();
    if (trimmed.length === 0)
        return false;
    if (/\b(?:Error|error|fail|FAIL|crashed|timeout)\b/u.test(line))
        return false;
    if (PROGRESS_SEPARATOR_PATTERN.test(trimmed))
        return true;
    if (PROGRESS_INDICATOR_PATTERN.test(line))
        return true;
    if (PROGRESS_BAR_VISUAL_PATTERN.test(line))
        return true;
    return false;
}
// Re-export access-log noise classifier for use in the main pipeline
var access_log_classifier_js_1 = require("../formats/access-log-classifier.js");
Object.defineProperty(exports, "isAccessLogNoiseLine", { enumerable: true, get: function () { return access_log_classifier_js_1.isAccessLogNoiseLine; } });
