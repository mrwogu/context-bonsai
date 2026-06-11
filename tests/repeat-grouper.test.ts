import { describe, expect, it } from 'vitest';
import {
  addRepeatGroupLine,
  createRepeatGroup,
  createRepeatSignature,
  renderRepeatGroup,
} from '../src/core/dedupe/repeat-grouper';

describe('repeat-grouper score tracking', () => {
  it('defaults the group score to zero', () => {
    const group = createRepeatGroup('worker idle');
    expect(group.score).toBe(0);
  });

  it('carries the score supplied at creation', () => {
    const group = createRepeatGroup('worker idle', 40);
    expect(group.score).toBe(40);
  });

  it('raises the group score when a later line scores higher', () => {
    const group = createRepeatGroup('worker idle', 10);
    addRepeatGroupLine(group, 'worker idle', 75);
    expect(group.score).toBe(75);
    expect(group.count).toBe(2);
  });

  it('keeps the higher score when a later line scores lower', () => {
    const group = createRepeatGroup('worker idle', 90);
    addRepeatGroupLine(group, 'worker idle', 5);
    expect(group.score).toBe(90);
  });
});

describe('template mining signatures', () => {
  it('wildcards numbers after generic word labels in template mode', () => {
    expect(createRepeatSignature('Retrying upload 17 for tenant acme', true)).toBe(
      'Retrying upload [VALUE] for tenant acme',
    );
    expect(createRepeatSignature('Retrying upload 18 for tenant acme', true)).toBe(
      createRepeatSignature('Retrying upload 17 for tenant acme', true),
    );
  });

  it('keeps the allowlist-only behavior without template mode', () => {
    expect(createRepeatSignature('Retrying upload 17 for tenant acme')).toBe(
      'Retrying upload 17 for tenant acme',
    );
    // "worker" is on the classic allowlist, so both modes wildcard it.
    expect(createRepeatSignature('restarting worker 4')).toBe('restarting worker [VALUE]');
  });

  it('never merges numbers after blocklisted diagnostic labels', () => {
    expect(createRepeatSignature('process exited with code 1', true)).toBe(
      'process exited with code 1',
    );
    expect(createRepeatSignature('terminated by signal 9', true)).toBe(
      'terminated by signal 9',
    );
    expect(createRepeatSignature('failed at line 42', true)).toBe('failed at line 42');
  });

  it('accepts labels with a trailing colon and rejects non-word labels', () => {
    expect(createRepeatSignature('attempt: 3 of upload', true)).toBe(
      'attempt: [VALUE] of upload',
    );
    expect(createRepeatSignature('[2026] 17 widgets', true)).toBe('[2026] 17 widgets');
  });

  it('collects template deltas when merging lines', () => {
    const group = createRepeatGroup(
      'Retrying upload 17 for tenant acme',
      0,
      createRepeatSignature('Retrying upload 17 for tenant acme', true),
    );
    addRepeatGroupLine(group, 'Retrying upload 18 for tenant acme', 0, true);
    addRepeatGroupLine(group, 'Retrying upload 19 for tenant acme', 0, true);

    expect(group.count).toBe(3);
    expect(renderRepeatGroup(group)).toBe('Retrying upload [17 | 18 | 19] for tenant acme');
  });
});
