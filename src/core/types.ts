import type { SeverityLevel } from './severity/severity-filter.js';
import type { LogStripCustomConfig } from './logstrip-config.js';

export type StaticAggressiveness = 'low' | 'medium' | 'high' | 'aggressive';
export type Aggressiveness = StaticAggressiveness | 'auto';
export type MultilineMode = 'auto' | 'auto-source' | 'python' | 'node' | 'java' | 'go' | 'rust' | 'off';
export type LogStripOutputFormat = 'text' | 'jsonl-preserve';
export type LogStripErrorCode =
  | 'ABORTED'
  | 'INVALID_CONFIG'
  | 'SAME_INPUT_OUTPUT'
  | 'TIMEOUT';
export type LogStripDecisionReason =
  | 'after-context'
  | 'cascade'
  | 'ci-noise'
  | 'context-buffered'
  | 'context-disabled'
  | 'custom-ignore'
  | 'empty'
  | 'exclude-filter'
  | 'hard-keep'
  | 'ignored-tag'
  | 'include-filter'
  | 'internal-stack'
  | 'low-score'
  | 'progress'
  | 'sample-limit'
  | 'severity'
  | 'stack-truncated';

export interface LogStripLineDecision {
  line: string;
  sanitizedLine?: string;
  kept: boolean;
  dropped: boolean;
  hardKeep: boolean;
  repeated: boolean;
  reason: LogStripDecisionReason;
  score?: number;
}

export interface LogStripStringResult extends LogStripResult {
  output: string;
}

export interface LogStripFileJob {
  inputPath: string;
  outputPath: string;
  options?: LogStripOptions;
}

export interface LogStripOptions {
  aggressiveness?: Aggressiveness;
  config?: LogStripCustomConfig;
  configPath?: string;
  multiline?: MultilineMode;
  severity?: SeverityLevel;
  maxLineLength?: number;
  include?: RegExp;
  exclude?: RegExp;
  sampleSize?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  onDecision?: (decision: LogStripLineDecision) => void;
  outputFormat?: LogStripOutputFormat;
  contextBefore?: number;
  contextAfter?: number;
  dedupe?: boolean;
  tokenEstimator?: (line: string) => number;
  preserveIdSuffix?: number;
  maxTokens?: number;
  collapseRepeatedStacks?: boolean;
  dedupeWindow?: number;
  rootCause?: boolean;
  formatDetectionSampleSize?: number;
  multilingual?: boolean;
  collapseBlocks?: number;
  adaptiveContext?: boolean;
  /**
   * Merge near-identical lines whose only difference is a number after a
   * generic word label (template mining). Default: on; set false to require
   * exact post-sanitization matches for [xN] folding.
   */
  templateMining?: boolean;
  /**
   * Keep at most N consecutive application stack frames per trace; the rest
   * collapse into a single "[... K more application stack frames ...]"
   * marker. Default: 10. Set 0 to keep every frame.
   */
  maxStackFrames?: number;
  /**
   * Auto-detect a structured JSON document (test report, scanner export) at
   * the head of the stream and compress it semantically instead of running
   * the line pipeline, which would drop structural lines and emit invalid
   * JSON. Default: on; set false to force line-oriented processing.
   */
  jsonReport?: boolean;
  /**
   * Buffering cap for JSON document detection. A candidate document larger
   * than this falls back to the streaming line pipeline. Default: 8 MiB.
   */
  jsonReportMaxBytes?: number;
}

export interface LogStripStats {
  inputLines: number;
  outputLines: number;
  inputWords: number;
  outputWords: number;
  inputBytes: number;
  outputBytes: number;
  droppedLines: number;
  duplicateLines: number;
  hiddenInternalStackLines: number;
  truncatedLines?: number;
}

export interface LogStripResult {
  stats: LogStripStats;
  inputTokens: number;
  outputTokens: number;
  savedTokens: number;
  savingsPercent: number;
  detectedSources?: readonly string[];
  outputPath?: string;
  detectedFormat?: string;
  timedOut?: boolean;
}
