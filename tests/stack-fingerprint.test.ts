import { describe, expect, it } from 'vitest';
import {
  normalizeStackFrameLineCol,
  stackWindowSignature,
} from '../src/core/dedupe/stack-fingerprint';

describe('stackWindowSignature', () => {
  it('returns null for lines that are not stack windows', () => {
    expect(stackWindowSignature('[ERROR] database connection refused')).toBeNull();
    expect(stackWindowSignature('plain log line')).toBeNull();
  });

  it('detects a JS stack frame window', () => {
    const sig = stackWindowSignature('    at Payments.charge (/repo/src/pay.ts:42:18)');
    expect(sig).not.toBeNull();
    expect(sig).toContain(':[NN]:[NN]');
  });

  it('normalizes Go offsets, goroutine ids and hex addresses', () => {
    const a = stackWindowSignature(
      'goroutine 1 [running]:\n\tmain.crash(0x1, 0x2)\n\t/app/main.go:10 +0x1a3',
    );
    const b = stackWindowSignature(
      'goroutine 7 [running]:\n\tmain.crash(0x9, 0xabcd)\n\t/app/main.go:10 +0x9ff',
    );
    expect(a).not.toBeNull();
    expect(a).toBe(b);
    expect(a).toContain('goroutine [NN]');
    expect(a).toContain('+0x[NN]');
    expect(a).toContain('0x[NN]');
  });

  it('detects a Python traceback window', () => {
    expect(
      stackWindowSignature('Traceback (most recent call last):'),
    ).not.toBeNull();
    expect(
      stackWindowSignature('  File "/repo/app.py", line 5, in main'),
    ).not.toBeNull();
  });

  it('leaves normalizeStackFrameLineCol behaviour intact', () => {
    expect(
      normalizeStackFrameLineCol('    at fn (/a/b.ts:42:18)'),
    ).toContain(':[NN]:[NN])');
  });

  it('normalizes Java frames without doubling the closing paren', () => {
    expect(
      normalizeStackFrameLineCol('    at com.example.Foo.bar(Foo.java:42)'),
    ).toBe('    at com.example.Foo.bar(Foo.java:[NN])');
  });
});
