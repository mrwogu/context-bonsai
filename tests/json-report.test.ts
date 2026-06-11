import { describe, expect, it } from 'vitest';
import {
  JSON_GROUP_MARKER,
  JSON_META_MARKER,
  JSON_REPORT_MAX_VARIANT_VALUES,
  claimJsonDocument,
  compressJsonReport,
  processLogString,
} from '../src/core/logstrip-parser';

async function* toLines(lines: readonly string[]): AsyncIterable<string> {
  yield* lines;
}

async function collect(lines: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const line of lines) {
    out.push(line);
  }
  return out;
}

describe('claimJsonDocument', () => {
  it('returns replay for empty input', async () => {
    const claim = await claimJsonDocument(toLines([]), 1024);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual([]);
  });

  it('replays blank lines followed by a plain log line untouched', async () => {
    const input = ['', '  ', '[ERROR] boom', 'next line'];
    const claim = await claimJsonDocument(toLines(input), 1024);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual(input);
  });

  it('claims a pretty-printed JSON object document', async () => {
    const claim = await claimJsonDocument(toLines(['{', '  "a": 1', '}']), 1024);

    expect(claim.doc?.value).toEqual({ a: 1 });
    expect(claim.doc?.text).toBe('{\n  "a": 1\n}');
  });

  it('claims a pretty-printed JSON array document', async () => {
    const claim = await claimJsonDocument(toLines(['[', '1,', '2', ']']), 1024);

    expect(claim.doc?.value).toEqual([1, 2]);
  });

  it('claims a single-line JSON document at end of stream', async () => {
    const claim = await claimJsonDocument(toLines(['{"a":1}']), 1024);

    expect(claim.doc?.value).toEqual({ a: 1 });
  });

  it('claims a single-line JSON document followed only by blank lines', async () => {
    const claim = await claimJsonDocument(toLines(['{"a":1}', '', '  ']), 1024);

    expect(claim.doc?.value).toEqual({ a: 1 });
    expect(claim.doc?.text).toBe('{"a":1}');
  });

  it('replays a lone structured log line carrying a level field', async () => {
    const input = ['{"level":30,"msg":"listening"}'];
    const claim = await claimJsonDocument(toLines(input), 1024);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual(input);
  });

  it('replays a JSONL stream (complete JSON line with content after it)', async () => {
    const input = ['{"a":1}', '{"a":2}'];
    const claim = await claimJsonDocument(toLines(input), 1024);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual(input);
  });

  it('replays when the buffered candidate exceeds maxBytes', async () => {
    const input = ['{', `"a": "${'x'.repeat(64)}",`, '"b": 1', '}', 'tail'];
    const claim = await claimJsonDocument(toLines(input), 16);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual(input);
  });

  it('replays when the buffered candidate never parses as JSON', async () => {
    const input = ['{', 'this is not json'];
    const claim = await claimJsonDocument(toLines(input), 1024);

    expect(claim.doc).toBeUndefined();
    expect(await collect(claim.replay)).toEqual(input);
  });
});

describe('compressJsonReport', () => {
  it('rewrites duplicate and embedded sibling string fields as references', () => {
    const message =
      'Expected status code <400> but was <500> for the request under test';
    const result = compressJsonReport({
      message,
      assertionMessage: message,
      traceSnippet: `AssertionFailedError: ${message}\n\tat fail()`,
    });
    const parsed = JSON.parse(result.text) as Record<string, string>;

    expect(parsed.assertionMessage).toBe('[logstrip:= message]');
    expect(parsed.traceSnippet).toBe(
      'AssertionFailedError: [logstrip:= message]\n\tat fail()',
    );
    expect(result.fieldReferences).toBe(2);
    expect(parsed[JSON_META_MARKER]).toBeDefined();
  });

  it('does not reference short or unrelated sibling fields', () => {
    const result = compressJsonReport({
      a: 'short text',
      b: 'short text',
      c: 'a completely different and much longer string value here',
    });
    const parsed = JSON.parse(result.text) as Record<string, string>;

    expect(parsed.b).toBe('short text');
    expect(result.fieldReferences).toBe(0);
    expect(parsed[JSON_META_MARKER]).toBeUndefined();
  });

  it('prunes empty fields but keeps zero and false', () => {
    const result = compressJsonReport({
      empty: '',
      list: [],
      obj: {},
      nothing: null,
      zero: 0,
      off: false,
      keep: 'x',
    });
    const parsed = JSON.parse(result.text) as Record<string, unknown>;

    expect(Object.keys(parsed)).toEqual([JSON_META_MARKER, 'zero', 'off', 'keep']);
    expect(result.prunedFields).toBe(4);
  });

  it('groups repeated entries with a single identity field as a flat variant list', () => {
    const result = compressJsonReport({
      entries: [
        { name: 'one', msg: 'same failure' },
        { name: 'two', msg: 'same failure' },
        { name: 'three', msg: 'same failure' },
      ],
    });
    const parsed = JSON.parse(result.text) as {
      entries: Record<string, unknown>[];
    };
    const group = parsed.entries[0][JSON_GROUP_MARKER] as {
      count: number;
      variants: string[];
    };

    expect(parsed.entries).toHaveLength(1);
    expect(group.count).toBe(3);
    expect(group.variants).toEqual(['one', 'two', 'three']);
    expect(parsed.entries[0].msg).toBe('same failure');
    expect(result.duplicateEntries).toBe(2);
  });

  it('groups entries with multiple identity fields as per-entry variant objects', () => {
    const result = compressJsonReport({
      entries: [
        { name: 'one', id: 1, msg: 'same failure' },
        { name: 'two', id: 2, msg: 'same failure' },
      ],
    });
    const parsed = JSON.parse(result.text) as {
      entries: Record<string, unknown>[];
    };
    const group = parsed.entries[0][JSON_GROUP_MARKER] as {
      variants: Record<string, unknown>[];
    };

    expect(group.variants).toEqual([
      { name: 'one', id: 1 },
      { name: 'two', id: 2 },
    ]);
  });

  it('groups fully identical entries with a bare count', () => {
    const result = compressJsonReport({ entries: [{ a: 1 }, { a: 1 }] });
    const parsed = JSON.parse(result.text) as {
      entries: Record<string, unknown>[];
    };

    expect(parsed.entries[0][JSON_GROUP_MARKER]).toEqual({ count: 2 });
    expect(parsed.entries[0].a).toBe(1);
  });

  it('leaves arrays of fully unique entries ungrouped', () => {
    const entries = [{ a: 1 }, { a: 2 }];
    const result = compressJsonReport({ entries });
    const parsed = JSON.parse(result.text) as { entries: unknown[] };

    expect(parsed.entries).toEqual(entries);
  });

  it('leaves arrays ungrouped when every signature is distinct', () => {
    const entries = [{ a: 1 }, { a: 1, b: 2 }, { a: 1, b: 3 }];
    const result = compressJsonReport({ entries });
    const parsed = JSON.parse(result.text) as { entries: unknown[] };

    expect(parsed.entries).toEqual(entries);
    expect(result.duplicateEntries).toBe(0);
  });

  it('keeps groups of one alongside larger groups', () => {
    const result = compressJsonReport({
      entries: [
        { name: 'one', msg: 'shared' },
        { name: 'two', msg: 'shared' },
        { name: 'three', msg: 'unique' },
      ],
    });
    const parsed = JSON.parse(result.text) as {
      entries: Record<string, unknown>[];
    };

    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[1]).toEqual({ name: 'three', msg: 'unique' });
  });

  it('does not group arrays with non-object elements or fewer than two items', () => {
    const result = compressJsonReport({
      mixed: [{ a: 1 }, 'scalar'],
      single: [{ a: 1 }],
    });
    const parsed = JSON.parse(result.text) as {
      mixed: unknown[];
      single: unknown[];
    };

    expect(parsed.mixed).toEqual([{ a: 1 }, 'scalar']);
    expect(parsed.single).toEqual([{ a: 1 }]);
  });

  it('caps enumerated variants and summarizes the tail', () => {
    const entries = Array.from({ length: 52 }, (_, index) => ({
      name: `case-${index}`,
      msg: 'same failure',
    }));
    const result = compressJsonReport({ entries });
    const parsed = JSON.parse(result.text) as {
      entries: Record<string, unknown>[];
    };
    const group = parsed.entries[0][JSON_GROUP_MARKER] as {
      count: number;
      variants: string[];
    };

    expect(group.count).toBe(52);
    expect(group.variants).toHaveLength(JSON_REPORT_MAX_VARIANT_VALUES + 1);
    expect(group.variants.at(-1)).toBe('… +2 more');
    expect(result.duplicateEntries).toBe(51);
  });

  it('omits the meta note for transformed top-level arrays', () => {
    const result = compressJsonReport([{ a: 1 }, { a: 1 }]);

    expect(result.text.startsWith('[')).toBe(true);
    expect(result.text).not.toContain(JSON_META_MARKER);
    expect(result.duplicateEntries).toBe(1);
  });

  it('sanitizes string values per line including stack frame normalization', () => {
    const result = compressJsonReport({
      msg:
        'user 123e4567-e89b-12d3-a456-426614174000 at 2026-01-01T10:00:00Z\n' +
        '\tat com.example.Foo.bar(Foo.java:42)',
    });
    const parsed = JSON.parse(result.text) as { msg: string };

    expect(parsed.msg).toContain('[ID]');
    expect(parsed.msg).toContain('[TIME]');
    expect(parsed.msg).toContain('Foo.java:[NN])');
    expect(parsed.msg).not.toContain(':[NN]))');
  });

  it('passes through untransformed documents without a meta note', () => {
    const result = compressJsonReport({ count: 5, ok: true, nested: { n: 1 } });

    expect(JSON.parse(result.text)).toEqual({
      count: 5,
      ok: true,
      nested: { n: 1 },
    });
    expect(result.text).not.toContain(JSON_META_MARKER);
  });
});

describe('processLogStream JSON document integration', () => {
  const failureMessage =
    'Failed assertions: expected status code 200 but received 500 from the ' +
    'upstream payment service while processing the checkout request';
  const prettyDoc = JSON.stringify(
    {
      summary: { failed: 4 },
      failures: Array.from({ length: 4 }, (_, index) => ({
        name: `case-${index}`,
        message: failureMessage,
        assertionMessage: failureMessage,
        sourceFile: '',
      })),
    },
    null,
    2,
  );

  it('compresses a detected JSON document into valid JSON', async () => {
    const result = await processLogString(prettyDoc);
    const parsed = JSON.parse(result.output) as Record<string, unknown>;

    expect(result.detectedFormat).toBe('json');
    expect(parsed[JSON_META_MARKER]).toBeDefined();
    expect(result.stats.duplicateLines).toBe(3);
    expect(result.stats.droppedLines).toBe(
      Math.max(0, result.stats.inputLines - result.stats.outputLines),
    );
    expect(result.savingsPercent).toBeGreaterThan(0);
  });

  it('respects jsonReport: false and falls back to the line pipeline', async () => {
    const result = await processLogString(prettyDoc, { jsonReport: false });

    expect(result.output).not.toContain(JSON_META_MARKER);
  });

  it('falls back to the line pipeline when jsonReportMaxBytes is exceeded', async () => {
    const result = await processLogString(prettyDoc, { jsonReportMaxBytes: 8 });

    expect(result.output).not.toContain(JSON_META_MARKER);
  });

  it('uses a custom token estimator for both sides of the JSON path', async () => {
    const result = await processLogString(prettyDoc, { tokenEstimator: () => 2 });

    expect(result.inputTokens).toBe(prettyDoc.split('\n').length * 2);
    expect(result.outputTokens).toBeGreaterThan(0);
  });

  it('reports zero savings when the token estimator returns zero', async () => {
    const result = await processLogString(prettyDoc, { tokenEstimator: () => 0 });

    expect(result.inputTokens).toBe(0);
    expect(result.savingsPercent).toBe(0);
  });

  it('leaves JSONL streams on the line pipeline', async () => {
    const jsonl =
      '{"level":"error","msg":"db timeout"}\n{"level":"error","msg":"db down"}';
    const result = await processLogString(jsonl);

    expect(result.output).toContain('db timeout');
    expect(result.output).toContain('db down');
    expect(result.output).not.toContain(JSON_META_MARKER);
  });
});
