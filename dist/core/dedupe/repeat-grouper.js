"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRepeatSignature = createRepeatSignature;
exports.createRepeatGroup = createRepeatGroup;
exports.addRepeatGroupLine = addRepeatGroupLine;
exports.getRepeatGroupSpreadMs = getRepeatGroupSpreadMs;
exports.renderRepeatGroup = renderRepeatGroup;
const constants_js_1 = require("../constants.js");
const STANDALONE_REPEAT_VALUE_PATTERN = /^\d+(?:[.:,-]\d+)*$/u;
// Labels that precede an enumerable instance counter. Numbers after these
// collapse into a single delta-tracked group so otherwise-identical lines
// fold via [xN]. Intentionally excludes labels whose numbers carry meaning
// (e.g. "error"/"code"/"status"/"exit") to avoid merging distinct diagnostics.
const STANDALONE_REPEAT_LABELS = new Set([
    'attempt',
    'batch',
    'child',
    'chunk',
    'connection',
    'epoch',
    'iteration',
    'job',
    'partition',
    'pid',
    'replica',
    'retry',
    'session',
    'shard',
    'slot',
    'state',
    'task',
    'thread',
    'worker',
]);
// Template mining inverts the allowlist: a standalone number after ANY word
// label merges into a delta, except after labels whose numbers carry
// diagnostic meaning (exit codes, statuses, line numbers, versions).
const STANDALONE_VALUE_BLOCKLIST = new Set([
    'code',
    'errno',
    'error',
    'exit',
    'line',
    'signal',
    'status',
    'version',
]);
const TEMPLATE_LABEL_PATTERN = /^[A-Za-z][\w-]*:?$/u;
function createRepeatSignature(line, template = false) {
    const tokens = tokenizeRepeatLine(line);
    return tokens
        .map((token, index) => {
        const tokenValue = splitRepeatToken(token, tokens[index - 1], template);
        return tokenValue === undefined
            ? token
            : `${tokenValue.prefix}[VALUE]`;
    })
        .join(' ');
}
function createRepeatGroup(line, score = 0, signature) {
    const ts = extractTimestampMs(line);
    return {
        firstLine: line,
        firstTokens: tokenizeRepeatLine(line),
        signature: signature ?? createRepeatSignature(line),
        deltas: new Map(),
        count: 1,
        firstSeen: ts,
        lastSeen: ts,
        score,
    };
}
function addRepeatGroupLine(group, line, score = 0, template = false) {
    const tokens = tokenizeRepeatLine(line);
    if (score > group.score) {
        group.score = score;
    }
    for (const [index, firstToken] of group.firstTokens.entries()) {
        const firstValue = splitRepeatToken(firstToken, group.firstTokens[index - 1], template);
        const nextValue = splitRepeatToken(tokens[index], tokens[index - 1], template);
        if (firstValue === undefined ||
            nextValue === undefined ||
            firstValue.prefix !== nextValue.prefix ||
            firstValue.value === nextValue.value) {
            continue;
        }
        const delta = group.deltas.get(index) ?? {
            prefix: firstValue.prefix,
            values: [firstValue.value],
            hasMoreValues: false,
        };
        if (!group.deltas.has(index)) {
            group.deltas.set(index, delta);
        }
        if (delta.values.includes(nextValue.value)) {
            continue;
        }
        if (delta.values.length < constants_js_1.MAX_REPEAT_DELTA_VALUES) {
            delta.values.push(nextValue.value);
        }
        else {
            delta.hasMoreValues = true;
        }
    }
    const ts = extractTimestampMs(line);
    if (ts !== null && (group.lastSeen === null || ts > group.lastSeen)) {
        group.lastSeen = ts;
    }
    group.count += 1;
}
const TIMESTAMP_CANDIDATE = /\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z?)\b/u;
function extractTimestampMs(line) {
    const match = TIMESTAMP_CANDIDATE.exec(line);
    if (!match)
        return null;
    const ms = Date.parse(match[1]);
    return Number.isFinite(ms) ? ms : null;
}
function getRepeatGroupSpreadMs(group) {
    if (group.firstSeen === null || group.lastSeen === null)
        return null;
    return group.lastSeen - group.firstSeen;
}
function renderRepeatGroup(group) {
    const baseTokens = group.deltas.size === 0 ? group.firstTokens : mergeDeltaTokens(group);
    let line = baseTokens.join(' ');
    const spread = getRepeatGroupSpreadMs(group);
    if (spread !== null && spread > 5000) {
        const spreadStr = formatDurationMs(spread);
        line += ` [~${spreadStr}]`;
    }
    return line;
}
function mergeDeltaTokens(group) {
    const tokens = [...group.firstTokens];
    for (const [index, delta] of group.deltas) {
        const values = delta.hasMoreValues
            ? [...delta.values, '…']
            : delta.values;
        tokens[index] = `${delta.prefix}[${values.join(' | ')}]`;
    }
    return tokens;
}
function formatDurationMs(ms) {
    if (ms < 60_000)
        return `${Math.round(ms / 1000)}s`;
    if (ms < 3_600_000)
        return `${Math.round(ms / 60_000)}m`;
    return `${Math.round(ms / 3_600_000)}h`;
}
function tokenizeRepeatLine(line) {
    return line.trim().split(/\s+/u);
}
function splitRepeatToken(token, previousToken, template = false) {
    const separator = token.indexOf('=');
    if (separator > 0 && separator < token.length - 1) {
        return {
            prefix: token.slice(0, separator + 1),
            value: token.slice(separator + 1),
        };
    }
    if (previousToken !== undefined &&
        STANDALONE_REPEAT_VALUE_PATTERN.test(token) &&
        (template
            ? isTemplateMergeLabel(previousToken)
            : STANDALONE_REPEAT_LABELS.has(previousToken.toLowerCase()))) {
        return {
            prefix: '',
            value: token,
        };
    }
    return undefined;
}
function isTemplateMergeLabel(previousToken) {
    if (!TEMPLATE_LABEL_PATTERN.test(previousToken)) {
        return false;
    }
    const label = previousToken.replace(/:$/u, '').toLowerCase();
    return !STANDALONE_VALUE_BLOCKLIST.has(label);
}
