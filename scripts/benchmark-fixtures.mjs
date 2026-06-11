#!/usr/bin/env node
// Per-fixture compression benchmark for data-driven threshold tuning.
//
// Runs the built parser over every tests/fixtures/*.log and prints one row
// per fixture: line counts, token savings and the per-reason drop histogram.
// Use it before changing scoring weights, regex tables or smoke-case
// thresholds (minSavingsPercent) so the numbers are grounded, not guessed.
//
//   npm run build && npm run bench
//   npm run bench -- nginx          # only fixtures whose name contains "nginx"

import { readdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.resolve(here, '../tests/fixtures');
const require = createRequire(import.meta.url);

let parser;
try {
  parser = require('../dist/core/logstrip-parser.js');
} catch {
  process.stderr.write('benchmark: dist/ not found - run `npm run build` first\n');
  process.exit(1);
}

const filter = process.argv[2];
const entries = (await readdir(fixturesDir))
  .filter((name) => name.endsWith('.log'))
  .filter((name) => (filter === undefined ? true : name.includes(filter)))
  .sort();

if (entries.length === 0) {
  process.stderr.write('benchmark: no fixtures matched\n');
  process.exit(1);
}

const rows = [];
for (const name of entries) {
  const text = await readFile(path.join(fixturesDir, name), 'utf8');
  const reasons = new Map();
  const started = process.hrtime.bigint();
  const result = await parser.processLogString(text, {
    onDecision: (decision) => {
      if (decision.dropped) {
        reasons.set(decision.reason, (reasons.get(decision.reason) ?? 0) + 1);
      }
    },
  });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  const topReasons = [...reasons.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([reason, count]) => `${reason}:${count}`)
    .join(' ');

  rows.push({
    fixture: name,
    in: result.stats.inputLines,
    out: result.stats.outputLines,
    savings: `${result.savingsPercent.toFixed(1)}%`,
    ms: elapsedMs.toFixed(1),
    topReasons,
  });
}

const headers = ['fixture', 'in', 'out', 'savings', 'ms', 'top drop reasons'];
const widths = [
  Math.max(...rows.map((r) => r.fixture.length), headers[0].length),
  Math.max(...rows.map((r) => String(r.in).length), headers[1].length),
  Math.max(...rows.map((r) => String(r.out).length), headers[2].length),
  Math.max(...rows.map((r) => r.savings.length), headers[3].length),
  Math.max(...rows.map((r) => r.ms.length), headers[4].length),
];

const pad = (value, width) => String(value).padEnd(width);
const padNum = (value, width) => String(value).padStart(width);

process.stdout.write(
  `${pad(headers[0], widths[0])}  ${padNum(headers[1], widths[1])}  ${padNum(headers[2], widths[2])}  ${padNum(headers[3], widths[3])}  ${padNum(headers[4], widths[4])}  ${headers[5]}\n`,
);
for (const row of rows) {
  process.stdout.write(
    `${pad(row.fixture, widths[0])}  ${padNum(row.in, widths[1])}  ${padNum(row.out, widths[2])}  ${padNum(row.savings, widths[3])}  ${padNum(row.ms, widths[4])}  ${row.topReasons}\n`,
  );
}

const totalIn = rows.reduce((sum, row) => sum + row.in, 0);
const totalOut = rows.reduce((sum, row) => sum + row.out, 0);
process.stdout.write(
  `\n${rows.length} fixtures, ${totalIn} lines in, ${totalOut} lines out (${(100 - (totalOut / totalIn) * 100).toFixed(1)}% line reduction)\n`,
);
