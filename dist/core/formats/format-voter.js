"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FORMAT_DRIFT_THRESHOLD = void 0;
exports.createFormatVoter = createFormatVoter;
exports.voteFormat = voteFormat;
exports.observeFormatDrift = observeFormatDrift;
exports.decideFormat = decideFormat;
const format_detector_js_1 = require("./format-detector.js");
/**
 * Number of consecutive recognizable lines in a *different* format that a
 * decided voter tolerates before re-electing. Catches mid-stream format
 * drift (e.g. plaintext boot output followed by a JSON application log).
 */
exports.FORMAT_DRIFT_THRESHOLD = 20;
function createFormatVoter(sampleSize) {
    return {
        votes: new Map(),
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
function voteFormat(voter, line) {
    if (voter.decided) {
        return voter.result;
    }
    const fmt = (0, format_detector_js_1.detectFormat)(line);
    if (fmt !== 'unknown') {
        if (!voter.votes.has(fmt)) {
            voter.order.push(fmt);
            voter.votes.set(fmt, 1);
        }
        else {
            voter.votes.set(fmt, voter.votes.get(fmt) + 1);
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
function observeFormatDrift(voter, line) {
    const fmt = (0, format_detector_js_1.detectFormat)(line);
    if (fmt === 'unknown' || fmt === voter.result) {
        voter.driftMismatches = 0;
        return undefined;
    }
    voter.driftMismatches += 1;
    if (voter.driftMismatches < exports.FORMAT_DRIFT_THRESHOLD) {
        return undefined;
    }
    voter.result = fmt;
    voter.driftMismatches = 0;
    return fmt;
}
/** Force a decision (e.g. at end of stream when fewer than N lines were seen). */
function decideFormat(voter) {
    if (voter.decided) {
        return voter.result;
    }
    return finalize(voter);
}
function finalize(voter) {
    voter.decided = true;
    let best;
    let bestCount = 0;
    for (const fmt of voter.order) {
        const count = voter.votes.get(fmt);
        if (count > bestCount) {
            best = fmt;
            bestCount = count;
        }
    }
    voter.result = best;
    return best;
}
