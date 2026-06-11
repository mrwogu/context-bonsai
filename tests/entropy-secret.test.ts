import { describe, expect, it } from 'vitest';
import {
  ENTROPY_SECRET_THRESHOLD,
  maskHighEntropyTokens,
  shannonEntropy,
} from '../src/core/sanitize/entropy-secret';

describe('shannonEntropy', () => {
  it('returns 0 for an empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });

  it('returns 0 for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
  });

  it('scores random-looking strings above the masking threshold', () => {
    expect(shannonEntropy('3kF9mQ2xY7LpR4wZ8tN1cV5bH0jD6s')).toBeGreaterThan(
      ENTROPY_SECRET_THRESHOLD,
    );
  });

  it('scores repetitive mixed-case strings far below the threshold', () => {
    expect(shannonEntropy('AaAaAaAaAaAaAaAaAaAa1')).toBeLessThan(2);
  });
});

describe('maskHighEntropyTokens', () => {
  it('masks mixed-case high-entropy keys missed by vendor patterns', () => {
    expect(
      maskHighEntropyTokens('api key 3kF9mQ2xY7LpR4wZ8tN1cV5bH0jD6s leaked'),
    ).toBe('api key [REDACTED] leaked');
  });

  it('masks base64-flavored material via + punctuation without mixed case', () => {
    expect(maskHighEntropyTokens('blob abc123def456+ghi789jkl end')).toBe(
      'blob [REDACTED] end',
    );
  });

  it('leaves kebab-case pod names untouched', () => {
    const line = 'liveness probe succeeded instance=checkout-api-7d9f8c7d4f-r8z2p';
    expect(maskHighEntropyTokens(line)).toBe(line);
  });

  it('leaves slash-bearing file paths untouched', () => {
    const line = 'at resolveLedger /srv/app/src/refunds/resolve-ledger-v2.ts';
    expect(maskHighEntropyTokens(line)).toBe(line);
  });

  it('leaves digit-only and letter-only runs untouched', () => {
    const line = 'count 123456789012345678901234 name abcdefghijklmnopqrstuvwxyz';
    expect(maskHighEntropyTokens(line)).toBe(line);
  });

  it('leaves repetitive mixed-case tokens untouched (low entropy)', () => {
    const line = 'pattern AaAaAaAaAaAaAaAaAaAa1 repeated';
    expect(maskHighEntropyTokens(line)).toBe(line);
  });

  it('short-circuits lines without a 20-char candidate run', () => {
    const line = 'hello world short tokens only';
    expect(maskHighEntropyTokens(line)).toBe(line);
  });
});
