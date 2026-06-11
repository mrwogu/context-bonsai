"use strict";
// High-entropy secret fallback: vendor-specific token patterns can never
// keep up with new credential formats, so any sufficiently long, random-
// looking token is masked as a last line of defense. Runs after the
// dedicated patterns in sanitize-line.ts, which already handle hex hashes
// and long alphanumeric blobs; this catches base64-flavored material
// (+ / = _ -) and short mixed-case keys those patterns miss.
Object.defineProperty(exports, "__esModule", { value: true });
exports.ENTROPY_SECRET_THRESHOLD = exports.ENTROPY_MIN_TOKEN_LENGTH = void 0;
exports.shannonEntropy = shannonEntropy;
exports.maskHighEntropyTokens = maskHighEntropyTokens;
/** Minimum candidate length; shorter tokens are too ambiguous to judge. */
exports.ENTROPY_MIN_TOKEN_LENGTH = 20;
/** Shannon entropy (bits/char) above which a candidate is masked. */
exports.ENTROPY_SECRET_THRESHOLD = 4.2;
// '/' and '=' are deliberately excluded from candidates: long slash-bearing
// runs are almost always file paths, and '=' would glue key=value pairs into
// one token (masking the key along with the value). A base64 secret
// containing either still yields maskable 20+ char segments between them.
const ENTROPY_CANDIDATE_PATTERN = /[A-Za-z0-9+_-]{20,}/gu;
const BASE64_SPECIAL_PATTERN = /\+/u;
/** Shannon entropy of a string in bits per character. */
function shannonEntropy(value) {
    if (value.length === 0) {
        return 0;
    }
    const counts = new Map();
    for (const char of value) {
        counts.set(char, (counts.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of counts.values()) {
        const p = count / value.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}
function looksLikeSecret(token) {
    // Placeholder-free, already-masked output never reaches here (candidates
    // cannot contain '[' or ']'). Require both letters and digits plus either
    // base64 punctuation or mixed case, so kebab-case identifiers, plain
    // words, and decimal blobs are never masked.
    if (!/\d/u.test(token) || !/[a-zA-Z]/u.test(token)) {
        return false;
    }
    const mixedCase = /[a-z]/u.test(token) && /[A-Z]/u.test(token);
    if (!mixedCase && !BASE64_SPECIAL_PATTERN.test(token)) {
        return false;
    }
    return shannonEntropy(token) >= exports.ENTROPY_SECRET_THRESHOLD;
}
/**
 * Mask random-looking tokens (length >= 20, entropy >= 4.2 bits/char) that
 * survived the vendor-specific secret patterns. Conservative on purpose:
 * false negatives are recoverable, masked source code identifiers are not.
 */
function maskHighEntropyTokens(line) {
    ENTROPY_CANDIDATE_PATTERN.lastIndex = 0;
    if (!ENTROPY_CANDIDATE_PATTERN.test(line)) {
        return line;
    }
    ENTROPY_CANDIDATE_PATTERN.lastIndex = 0;
    return line.replace(ENTROPY_CANDIDATE_PATTERN, (token) => looksLikeSecret(token) ? '[REDACTED]' : token);
}
