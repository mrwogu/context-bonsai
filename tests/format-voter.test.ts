import { describe, expect, it } from 'vitest';
import {
  FORMAT_DRIFT_THRESHOLD,
  type FormatVoter,
  createFormatVoter,
  decideFormat,
  observeFormatDrift,
  voteFormat,
} from '../src/core/formats/format-voter';

describe('format-voter', () => {
  it('returns the majority format after the sample size is reached', () => {
    const voter = createFormatVoter(3);
    expect(voteFormat(voter, '{"a":1}')).toBeUndefined();
    expect(voteFormat(voter, '{"b":2}')).toBeUndefined();
    expect(voteFormat(voter, 'level=info msg=hi')).toBe('json');
  });

  it('breaks ties by first appearance', () => {
    const voter = createFormatVoter(2);
    expect(voteFormat(voter, '{"a":1}')).toBeUndefined();
    expect(voteFormat(voter, '<13> service up')).toBe('json');
  });

  it('ignores unknown lines and decides undefined when no format wins', () => {
    const voter = createFormatVoter(2);
    expect(voteFormat(voter, 'plain narrative text')).toBeUndefined();
    expect(voteFormat(voter, 'more plain narrative')).toBeUndefined();
    // Already decided (undefined): further votes short-circuit.
    expect(voteFormat(voter, '{"a":1}')).toBeUndefined();
  });

  it('forces a decision on a short stream via decideFormat', () => {
    const voter = createFormatVoter(5);
    expect(voteFormat(voter, '{"a":1}')).toBeUndefined();
    expect(decideFormat(voter)).toBe('json');
    // Calling again returns the cached decision.
    expect(decideFormat(voter)).toBe('json');
  });

  it('clamps the sample size to a minimum of 2', () => {
    const voter = createFormatVoter(1);
    expect(voter.sampleSize).toBe(2);
  });
});

describe('observeFormatDrift', () => {
  function decidedJsonVoter(): FormatVoter {
    const voter = createFormatVoter(2);
    voteFormat(voter, '{"a":1}');
    voteFormat(voter, '{"b":2}');
    expect(voter.decided).toBe(true);
    expect(voter.result).toBe('json');
    return voter;
  }

  it('ignores lines that agree with the elected format', () => {
    const voter = decidedJsonVoter();
    expect(observeFormatDrift(voter, '{"c":3}')).toBeUndefined();
    expect(voter.driftMismatches).toBe(0);
  });

  it('ignores unrecognizable lines and resets the mismatch run', () => {
    const voter = decidedJsonVoter();
    expect(observeFormatDrift(voter, 'level=info msg=hi')).toBeUndefined();
    expect(voter.driftMismatches).toBe(1);
    expect(observeFormatDrift(voter, 'plain narrative text')).toBeUndefined();
    expect(voter.driftMismatches).toBe(0);
  });

  it('re-elects the format after a sustained run of mismatches', () => {
    const voter = decidedJsonVoter();
    for (let i = 0; i < FORMAT_DRIFT_THRESHOLD - 1; i += 1) {
      expect(observeFormatDrift(voter, 'level=info msg=hi')).toBeUndefined();
    }
    expect(observeFormatDrift(voter, 'level=info msg=hi')).toBe('logfmt');
    expect(voter.result).toBe('logfmt');
    expect(voter.driftMismatches).toBe(0);
  });

  it('an agreeing line interrupts an almost-complete drift run', () => {
    const voter = decidedJsonVoter();
    for (let i = 0; i < FORMAT_DRIFT_THRESHOLD - 1; i += 1) {
      observeFormatDrift(voter, 'level=info msg=hi');
    }
    observeFormatDrift(voter, '{"agree":true}');
    expect(observeFormatDrift(voter, 'level=info msg=hi')).toBeUndefined();
    expect(voter.result).toBe('json');
  });
});
