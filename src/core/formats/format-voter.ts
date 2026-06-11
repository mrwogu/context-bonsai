import { detectFormat, type DetectedFormat } from './format-detector.js';

/**
 * Majority-vote format detection.
 *
 * Instead of locking onto the first recognizable line, the voter tallies the
 * detected format across the first N non-blank lines and picks the most common
 * one (ties broken by first appearance). This is robust to mixed-format logs
 * such as a JSON application stream interleaved with plaintext runtime output.
 */
export interface FormatVoter {
  votes: Map<DetectedFormat, number>;
  order: DetectedFormat[];
  samples: number;
  sampleSize: number;
  decided: boolean;
  result: DetectedFormat | undefined;
  /** Consecutive post-decision lines recognized as a different format. */
  driftMismatches: number;
}

/**
 * Number of consecutive recognizable lines in a *different* format that a
 * decided voter tolerates before re-electing. Catches mid-stream format
 * drift (e.g. plaintext boot output followed by a JSON application log).
 */
export const FORMAT_DRIFT_THRESHOLD = 20;

export function createFormatVoter(sampleSize: number): FormatVoter {
  return {
    votes: new Map<DetectedFormat, number>(),
    order: [],
    samples: 0,
    sampleSize: Math.max(2, Math.floor(sampleSize)),
    decided: false,
    result: undefined,
    driftMismatches: 0,
  };
}

/**
 * Feed a non-blank line. Returns the decided format once enough samples have
 * been seen, otherwise `undefined` (keep sampling).
 */
export function voteFormat(voter: FormatVoter, line: string): DetectedFormat | undefined {
  if (voter.decided) {
    return voter.result;
  }

  const fmt = detectFormat(line);
  if (fmt !== 'unknown') {
    if (!voter.votes.has(fmt)) {
      voter.order.push(fmt);
      voter.votes.set(fmt, 1);
    } else {
      voter.votes.set(fmt, voter.votes.get(fmt)! + 1);
    }
  }

  voter.samples += 1;
  if (voter.samples >= voter.sampleSize) {
    return finalize(voter);
  }
  return undefined;
}

/**
 * Watch a decided voter for sustained format drift. Returns the new format
 * once FORMAT_DRIFT_THRESHOLD consecutive recognizable lines disagree with
 * the elected result; any agreeing (or unrecognizable) line resets the run.
 */
export function observeFormatDrift(
  voter: FormatVoter,
  line: string,
): DetectedFormat | undefined {
  const fmt = detectFormat(line);
  if (fmt === 'unknown' || fmt === voter.result) {
    voter.driftMismatches = 0;
    return undefined;
  }

  voter.driftMismatches += 1;
  if (voter.driftMismatches < FORMAT_DRIFT_THRESHOLD) {
    return undefined;
  }

  voter.result = fmt;
  voter.driftMismatches = 0;
  return fmt;
}

/** Force a decision (e.g. at end of stream when fewer than N lines were seen). */
export function decideFormat(voter: FormatVoter): DetectedFormat | undefined {
  if (voter.decided) {
    return voter.result;
  }
  return finalize(voter);
}

function finalize(voter: FormatVoter): DetectedFormat | undefined {
  voter.decided = true;

  let best: DetectedFormat | undefined;
  let bestCount = 0;
  for (const fmt of voter.order) {
    const count = voter.votes.get(fmt)!;
    if (count > bestCount) {
      best = fmt;
      bestCount = count;
    }
  }

  voter.result = best;
  return best;
}
