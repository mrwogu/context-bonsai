export const INTERNAL_STACK_MARKER = '[... hidden internal library frames ...]';

export const CONTEXT_WINDOW_BEFORE = 3;
export const CONTEXT_WINDOW_AFTER = 2;
export const SCORE_KEEP_THRESHOLD = 40;
export const TFIDF_REPEAT_THRESHOLD = 3;
export const TFIDF_PENALTY = 8;
// IDF-side rarity boost: a positively-scored line seen exactly once in a
// stream of at least RARITY_MIN_INPUT_LINES gains RARITY_BOOST so unique
// diagnostics outrank repeated ones under a token budget.
export const RARITY_BOOST = 5;
export const RARITY_MIN_INPUT_LINES = 1000;
export const TFIDF_MAP_LIMIT = 50_000;
export const MAX_REPEAT_DELTA_VALUES = 3;
// Auto format detection: number of leading non-blank lines a majority vote
// samples before it may correct the first-line format guess.
export const DEFAULT_FORMAT_SAMPLE = 50;

// App-stack truncation: a trace keeps at most this many consecutive
// application stack frames before the remainder collapses into a single
// "[... K more application stack frames ...]" marker.
export const DEFAULT_MAX_STACK_FRAMES = 10;

// Adaptive context window (auto mode): the context window around a kept error
// scales with how densely errors cluster. Errors within DENSE_GAP scored lines
// of the previous one are self-contextualizing and get a tighter window;
// errors isolated by SPARSE_GAP or more scored lines get a wider after-window.
export const ADAPTIVE_CONTEXT_DENSE_GAP = 2;
export const ADAPTIVE_CONTEXT_SPARSE_GAP = 12;
// Extra after-context lines granted to an isolated error (on top of the base).
export const ADAPTIVE_CONTEXT_AFTER_EXPANSION = 2;
