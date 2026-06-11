import { normalizeStackFrameLineCol } from '../dedupe/stack-fingerprint.js';
import { sanitizeLine } from '../sanitize/sanitize-line.js';
import { extractJsonLog } from './json-line-extractor.js';

// ---- Structured JSON report compression ----
//
// CI tooling increasingly emits whole JSON documents (test-runner reports,
// TMS exports, scanner results) instead of line-oriented logs. Running those
// through the line pipeline corrupts the document: structural braces score as
// noise and get dropped, leaving invalid JSON. This module detects a JSON
// document at the head of the stream and compresses it semantically instead:
//
//   1. every string value is sanitized line-by-line (PII/ID/secret masking),
//   2. empty fields ("", [], {}, null) are pruned,
//   3. a string field equal to (or contained in) an earlier sibling field is
//      replaced by a [logstrip:= field] reference,
//   4. arrays of objects are grouped: fields whose value is unique across the
//      whole array are "identity" fields; entries whose remaining fields match
//      exactly collapse into one representative plus a [logstrip:group] header
//      that lists each grouped entry's identity values (pairing preserved).
//
// The output is always valid JSON. Grouping uses exact post-sanitization
// equality, so two entries never merge unless their non-identity fields are
// identical - no diagnostic detail is folded away.

// Buffering cap: a candidate document larger than this falls back to the
// streaming line pipeline so a malformed giant input cannot exhaust memory.
export const JSON_REPORT_MAX_BYTES = 8 * 1024 * 1024;
// A sibling string field must be at least this long before a containment
// match is rewritten into a reference (short strings collide too easily).
export const JSON_REPORT_MIN_REFERENCE_LENGTH = 24;
// Cap on enumerated identity values per group; the tail is summarized.
export const JSON_REPORT_MAX_VARIANT_VALUES = 50;

export const JSON_GROUP_MARKER = '[logstrip:group]';
export const JSON_META_MARKER = '[logstrip:meta]';
export const JSON_META_NOTE_MARKER =
  '"[logstrip:= f]" repeats the text of sibling field f; empty fields pruned; ' +
  `"${JSON_GROUP_MARKER}" collapses entries identical except for the listed variant fields`;

export interface JsonReportCompression {
  text: string;
  duplicateEntries: number;
  prunedFields: number;
  fieldReferences: number;
}

export interface ClaimedJsonDocument {
  text: string;
  value: unknown;
}

export interface JsonDocumentClaim {
  doc?: ClaimedJsonDocument;
  replay: AsyncIterable<string>;
}

interface CompressionCounters {
  duplicateEntries: number;
  prunedFields: number;
  fieldReferences: number;
}

/**
 * Inspect the head of a line stream for a JSON document. Returns the parsed
 * document when the input is one, or a `replay` iterable that re-yields every
 * consumed line followed by the rest of the stream so the standard pipeline
 * sees the input unchanged.
 *
 * A document is claimed when the first non-blank line starts with `{`/`[` and
 * either the whole (capped) input parses as JSON, or that single line parses
 * and nothing but blank lines follow. A first line that parses on its own with
 * more content after it is JSONL (pino/bunyan) and is replayed untouched.
 */
export async function claimJsonDocument(
  lines: AsyncIterable<string>,
  maxBytes: number,
): Promise<JsonDocumentClaim> {
  const iterator = lines[Symbol.asyncIterator]();
  const buffered: string[] = [];
  const replay = (): AsyncIterable<string> => replayLines(buffered, iterator);

  let first: string | undefined;
  while (first === undefined) {
    const next = await iterator.next();
    if (next.done === true) {
      return { replay: replay() };
    }
    buffered.push(next.value);
    if (next.value.trim().length > 0) {
      first = next.value;
    }
  }

  const trimmed = first.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return { replay: replay() };
  }

  const single = parseJsonContainer(trimmed);
  if (single !== undefined) {
    // A lone JSON object carrying a level field is a structured log line
    // (pino/winston/bunyan), not a report; the line pipeline drops or keeps
    // it by severity.
    if (extractJsonLog(trimmed)?.level !== undefined) {
      return { replay: replay() };
    }
    // Complete JSON on one line: JSONL stream unless only blanks follow.
    while (true) {
      const next = await iterator.next();
      if (next.done === true) {
        return { doc: { text: first, value: single }, replay: replay() };
      }
      buffered.push(next.value);
      if (next.value.trim().length > 0) {
        return { replay: replay() };
      }
    }
  }

  let bytes = Buffer.byteLength(first, 'utf8');
  while (true) {
    const next = await iterator.next();
    if (next.done === true) {
      break;
    }
    buffered.push(next.value);
    bytes += Buffer.byteLength(next.value, 'utf8') + 1;
    if (bytes > maxBytes) {
      return { replay: replay() };
    }
  }

  const text = buffered.join('\n');
  const value = parseJsonContainer(text);
  if (value === undefined) {
    return { replay: replay() };
  }
  return { doc: { text, value }, replay: replay() };
}

async function* replayLines(
  buffered: readonly string[],
  iterator: AsyncIterator<string>,
): AsyncIterable<string> {
  yield* buffered;
  while (true) {
    const next = await iterator.next();
    if (next.done === true) {
      return;
    }
    yield next.value;
  }
}

// Callers pre-filter on a leading `{`/`[`, so a successful parse is always
// an object or array by the JSON grammar.
function parseJsonContainer(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Compress a parsed JSON document. Lossless by construction except for the
 * shared sanitizer masks and the per-group variant cap.
 */
export function compressJsonReport(value: unknown): JsonReportCompression {
  const counters: CompressionCounters = {
    duplicateEntries: 0,
    prunedFields: 0,
    fieldReferences: 0,
  };
  let compressed = compressValue(value, counters);

  const transformed =
    counters.duplicateEntries + counters.prunedFields + counters.fieldReferences > 0;
  if (transformed && isPlainObject(compressed)) {
    compressed = { [JSON_META_MARKER]: JSON_META_NOTE_MARKER, ...compressed };
  }

  return {
    text: JSON.stringify(compressed, null, 2),
    duplicateEntries: counters.duplicateEntries,
    prunedFields: counters.prunedFields,
    fieldReferences: counters.fieldReferences,
  };
}

function compressValue(value: unknown, counters: CompressionCounters): unknown {
  if (typeof value === 'string') {
    return sanitizeStringValue(value);
  }
  if (Array.isArray(value)) {
    return compressArray(value, counters);
  }
  if (isPlainObject(value)) {
    return compressObject(value, counters);
  }
  return value;
}

function compressObject(
  obj: Record<string, unknown>,
  counters: CompressionCounters,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  // Earlier sibling string fields, kept pre-reference so later fields match
  // against the original text rather than an already-rewritten marker.
  const earlier: { key: string; value: string }[] = [];

  for (const [key, raw] of Object.entries(obj)) {
    if (isEmptyJsonValue(raw)) {
      counters.prunedFields += 1;
      continue;
    }
    const compressed = compressValue(raw, counters);
    if (typeof compressed === 'string') {
      result[key] = applyFieldReferences(compressed, earlier, counters);
      earlier.push({ key, value: compressed });
    } else {
      result[key] = compressed;
    }
  }

  return result;
}

function applyFieldReferences(
  text: string,
  earlier: readonly { key: string; value: string }[],
  counters: CompressionCounters,
): string {
  let result = text;
  // Longest sibling first so a field embedded in another rewrites once.
  const candidates = [...earlier].sort((a, b) => b.value.length - a.value.length);
  for (const sibling of candidates) {
    if (
      sibling.value.length >= JSON_REPORT_MIN_REFERENCE_LENGTH &&
      result.includes(sibling.value)
    ) {
      result = result.split(sibling.value).join(`[logstrip:= ${sibling.key}]`);
      counters.fieldReferences += 1;
    }
  }
  return result;
}

function compressArray(
  values: readonly unknown[],
  counters: CompressionCounters,
): unknown[] {
  const items = values.map((item) => compressValue(item, counters));
  if (items.length < 2 || !items.every(isPlainObject)) {
    return items;
  }
  return groupArrayEntries(items, counters);
}

function groupArrayEntries(
  items: readonly Record<string, unknown>[],
  counters: CompressionCounters,
): unknown[] {
  const identityKeys = findIdentityKeys(items);
  if (identityKeys.length === Object.keys(items[0]).length) {
    // Every field is unique per entry: nothing shared to fold, grouping
    // would only rewrite distinct objects into variant lists.
    return [...items];
  }
  const signatureOf = (item: Record<string, unknown>): string =>
    JSON.stringify(
      Object.entries(item).filter(([key]) => !identityKeys.includes(key)),
    );

  const groups = new Map<string, Record<string, unknown>[]>();
  const order: string[] = [];
  for (const item of items) {
    const signature = signatureOf(item);
    const group = groups.get(signature);
    if (group === undefined) {
      groups.set(signature, [item]);
      order.push(signature);
    } else {
      group.push(item);
    }
  }

  if (groups.size === items.length) {
    return [...items];
  }

  return order.map((signature) => {
    const group = groups.get(signature)!;
    if (group.length === 1) {
      return group[0];
    }
    counters.duplicateEntries += group.length - 1;
    return renderGroup(group, identityKeys);
  });
}

/**
 * Identity keys: present in every entry with a distinct value per entry
 * (e.g. a test's fullName). They are excluded from the grouping signature
 * and enumerated per grouped entry instead, so pairing is preserved.
 */
function findIdentityKeys(
  items: readonly Record<string, unknown>[],
): readonly string[] {
  const keys = Object.keys(items[0]);
  return keys.filter((key) => {
    const canonical = new Set<string>();
    for (const item of items) {
      if (!(key in item)) {
        return false;
      }
      canonical.add(JSON.stringify(item[key]));
    }
    return canonical.size === items.length;
  });
}

function renderGroup(
  group: readonly Record<string, unknown>[],
  identityKeys: readonly string[],
): Record<string, unknown> {
  const representative = Object.fromEntries(
    Object.entries(group[0]).filter(([key]) => !identityKeys.includes(key)),
  );

  if (identityKeys.length === 0) {
    // Entries are fully identical: a bare count is enough.
    return {
      [JSON_GROUP_MARKER]: { count: group.length },
      ...representative,
    };
  }

  const variants: unknown[] =
    identityKeys.length === 1
      ? group.map((item) => item[identityKeys[0]])
      : group.map((item) =>
          Object.fromEntries(identityKeys.map((key) => [key, item[key]])),
        );

  const capped =
    variants.length > JSON_REPORT_MAX_VARIANT_VALUES
      ? [
          ...variants.slice(0, JSON_REPORT_MAX_VARIANT_VALUES),
          `… +${variants.length - JSON_REPORT_MAX_VARIANT_VALUES} more`,
        ]
      : variants;

  return {
    [JSON_GROUP_MARKER]: { count: group.length, variants: capped },
    ...representative,
  };
}

function sanitizeStringValue(value: string): string {
  return value
    .split('\n')
    .map((line) => normalizeStackFrameLineCol(sanitizeLine(line)))
    .join('\n');
}

function isEmptyJsonValue(value: unknown): boolean {
  if (value === null || value === '') {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length === 0;
  }
  if (typeof value === 'object') {
    return Object.keys(value).length === 0;
  }
  return false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
