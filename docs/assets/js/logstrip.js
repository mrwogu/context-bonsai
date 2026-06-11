(function () {
  'use strict';

  document.documentElement.classList.add('js');

  function ready(fn) {
    if (document.readyState !== 'loading') {
      fn();
    } else {
      document.addEventListener('DOMContentLoaded', fn);
    }
  }

  // ----- Hybrid browser-side parser (ports the real scoring engine) ----- //

  // --- Scoring constants (mirror src/core/logstrip-parser.ts) ---
  const CONTEXT_WINDOW_BEFORE = 3;
  const CONTEXT_WINDOW_AFTER = 2;
  const SCORE_KEEP_THRESHOLD = 40;
  const TFIDF_REPEAT_THRESHOLD = 3;
  const TFIDF_PENALTY = 8;
  const TFIDF_MAP_LIMIT = 50000;

  // --- Regex tables (mirror the real parser) ---
  const IGNORED_TAG =
    /\[(?:INFO|DEBUG|TRACE|VERBOSE)\]|"level"\s*:\s*"(?:info|debug|trace|verbose)"/i;
  const IMPORTANT_TAG = /\[(?:ERROR|WARN|FATAL|CRITICAL|FAIL)\]/i;
  const DIAGNOSTIC_KW =
    /\b(?:Error|Exception|AssertionError|TypeError|ReferenceError|SyntaxError|RangeError|NullPointerException|Unhandled|failed|failure|fatal|panic|refused|timeout|timed\s+out|unreachable|unavailable|disconnected|killed|aborted|crashed|terminated|unauthorized)\b/i;
  const JSON_SEVERITY =
    /"(?:level|severity)"\s*:\s*"(?:fatal|error|critical|warn|warning)"/i;
  const NPM_ERR = /\b(?:npm|pnpm)\s+ERR!/i;
  const YARN_ERR = /\byarn\s+error\b/i;
  const SCANNER_FINDING =
    /\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|vulnerabilit(?:y|ies)|severity:\s*(?:critical|high|medium)|(?:critical|high)\s+severity)\b/i;
  const CONTAINER_FAIL =
    /\b(?:CrashLoopBackOff|ImagePullBackOff|ErrImagePull|OOMKilled|Back[- ]off restarting failed container|failed to pull image|rpc error: code = Unknown desc = failed to resolve reference)\b/i;
  const STACK_FRAME = /^\s*at\s+.*(?:\(|\s).+:\d+:\d+\)?$/;
  const PYTHON_TRACEBACK = /^Traceback \(most recent call last\):$/;
  const GO_GOROUTINE = /^\s*goroutine\s+\d+\s+\[.+\]:$/i;
  const STACK_MORE = /^\s*\.\.\. \d+ more$/;
  const INTERNAL_STACK =
    /(?:node_modules[\\/]|node:internal|internal[\\/]modules|bootstrap_node|[\\/]usr[\\/]lib[\\/]|[\\/]usr[\\/]local[\\/]lib[\\/]|[\\/]usr[\\/]local[\\/]go[\\/]src[\\/]runtime[\\/]|site-packages[\\/]|dist-packages[\\/]|\.venv[\\/]|java\.base[\\/]|jdk\.internal|org\.springframework\.|[\\/]pkg[\\/]mod[\\/]|\.cargo[\\/]registry[\\/])/i;

  // --- Sanitization patterns (mirror the real parser) ---
  const UUID_PAT =
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
  const UTC_TIME_PAT =
    /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC)\b/gi;
  const COMMON_LOG_TIME_PAT =
    /\b\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\b/gi;
  const NGINX_TIME_PAT = /\b\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\b/g;
  const ISO_TIME_PAT =
    /\b\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)?\b/g;
  const IPV4_PORT_PAT =
    /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}:(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4})\b/g;
  const IPV4_PAT =
    /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
  const HEX_HASH_PAT = /\b(?=[a-f0-9]*\d)(?=[a-f0-9]*[a-f])[a-f0-9]{16,}\b/gi;
  const ALPHANUM_HASH_PAT =
    /\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{24,}\b/g;
  const STRIPE_KEY_PAT = /\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b/g;
  const AWS_KEY_PAT = /\b(?:AKIA|ABIA|ASIA)[0-9A-Z]{16}\b/g;
  const GITHUB_TOKEN_PAT = /\bgh[opuars]_[A-Za-z0-9]{36,255}\b/g;
  const NPM_TOKEN_PAT = /\bnpm_[A-Za-z0-9]{36,80}\b/g;
  const AUTH_HEADER_PAT = /\bAuthorization\s*:\s*\S+(?:\s+\S+)*/gi;
  const SECRET_FIELD_PAT =
    /\b(?:password|secret|token|api[_-]?key|api[_-]?secret|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s"',;]+)/gi;
  const MAX_REPEAT_DELTA_VALUES = 3;

  // --- Simplified source signatures (top 30 ecosystems) ---
  const SOURCE_SIGS = [
    ['github-actions', ['github actions', '##[error]', '::error::']],
    ['gitlab-ci', ['gitlab-ci', 'running with gitlab-runner']],
    ['jenkins', ['jenkins', '[pipeline]']],
    ['docker', ['docker', 'dockerfile']],
    ['kubernetes', ['kubernetes', 'kubectl', 'k8s']],
    ['helm', ['helm']],
    ['terraform', ['terraform']],
    ['npm', ['npm err!', 'npm warn']],
    ['pnpm', ['pnpm err!', 'pnpm']],
    ['yarn', ['yarn error', 'yarn run']],
    ['vitest', ['vitest']],
    ['jest', ['jest']],
    ['pytest', ['pytest', 'assertionerror: assert']],
    ['maven', ['maven', 'mvn ']],
    ['gradle', ['gradle', 'task :', 'build failed']],
    ['go-test', ['go test', '--- fail:']],
    ['cargo', ['cargo build', 'cargo test']],
    ['webpack', ['webpack']],
    ['typescript', ['typescript', 'tsc', 'ts2322']],
    ['trivy', ['trivy', 'cve-']],
    ['snyk', ['snyk']],
    ['nginx', ['nginx']],
    ['postgresql', ['postgres', 'postgresql']],
    ['redis', ['redis']],
    ['kafka', ['kafka']],
    ['spring-boot', ['spring', 'springboot']],
    ['datadog', ['datadog']],
    ['sentry', ['sentry']],
    ['opentelemetry', ['opentelemetry', 'otel']],
    ['aws-lambda', ['aws lambda', 'lambda']],
  ];

  const INTERNAL_STACK_MARKER = '[... hidden internal stack frames ...]';

  function sanitizeLine(line) {
    return line
      .replace(STRIPE_KEY_PAT, '[REDACTED]')
      .replace(AWS_KEY_PAT, '[REDACTED]')
      .replace(GITHUB_TOKEN_PAT, '[REDACTED]')
      .replace(NPM_TOKEN_PAT, '[REDACTED]')
      .replace(AUTH_HEADER_PAT, 'Authorization: [REDACTED]')
      .replace(SECRET_FIELD_PAT, (match) =>
        match.replace(/([:=]\s*)(?:"[^"]*"|'[^']*'|[^\s"',;]+)$/, '$1[REDACTED]'),
      )
      .replace(UUID_PAT, '[ID]')
      .replace(UTC_TIME_PAT, '[TIME]')
      .replace(COMMON_LOG_TIME_PAT, '[TIME]')
      .replace(NGINX_TIME_PAT, '[TIME]')
      .replace(ISO_TIME_PAT, '[TIME]')
      .replace(IPV4_PORT_PAT, '[IP]:[PORT]')
      .replace(IPV4_PAT, '[IP]')
      .replace(HEX_HASH_PAT, '[HASH]')
      .replace(ALPHANUM_HASH_PAT, '[HASH]')
      .replace(/[ \t]+$/, '');
  }

  function createRepeatSignature(line) {
    return tokenizeRepeatLine(line)
      .map((token) => {
        const tokenValue = splitRepeatToken(token);
        return tokenValue === undefined ? token : `${tokenValue.prefix}[VALUE]`;
      })
      .join(' ');
  }

  function tokenizeRepeatLine(line) {
    return line.trim().split(/\s+/);
  }

  function splitRepeatToken(token) {
    const separator = token.indexOf('=');
    if (separator <= 0 || separator === token.length - 1) return undefined;
    return {
      prefix: token.slice(0, separator + 1),
      value: token.slice(separator + 1),
    };
  }

  function createRepeatGroup(line) {
    return {
      firstLine: line,
      firstTokens: tokenizeRepeatLine(line),
      signature: createRepeatSignature(line),
      deltas: new Map(),
      count: 1,
    };
  }

  function addRepeatGroupLine(group, line) {
    const tokens = tokenizeRepeatLine(line);
    group.firstTokens.forEach((firstToken, index) => {
      const firstValue = splitRepeatToken(firstToken);
      const nextValue = splitRepeatToken(tokens[index] || '');
      if (
        firstValue === undefined ||
        nextValue === undefined ||
        firstValue.prefix !== nextValue.prefix ||
        firstValue.value === nextValue.value
      ) {
        return;
      }
      const delta = group.deltas.get(index) || {
        prefix: firstValue.prefix,
        values: [firstValue.value],
        hasMoreValues: false,
      };
      if (!group.deltas.has(index)) group.deltas.set(index, delta);
      if (delta.values.includes(nextValue.value)) return;
      if (delta.values.length < MAX_REPEAT_DELTA_VALUES) {
        delta.values.push(nextValue.value);
      } else {
        delta.hasMoreValues = true;
      }
    });
    group.count += 1;
  }

  function renderRepeatGroup(group) {
    if (group.deltas.size === 0) return group.firstLine;
    const tokens = [...group.firstTokens];
    for (const [index, delta] of group.deltas) {
      const values = delta.hasMoreValues ? [...delta.values, '…'] : delta.values;
      tokens[index] = `${delta.prefix}[${values.join(' | ')}]`;
    }
    return tokens.join(' ');
  }

  function isInternalStackLine(line) {
    return (
      (STACK_FRAME.test(line) ||
        PYTHON_TRACEBACK.test(line) ||
        GO_GOROUTINE.test(line) ||
        STACK_MORE.test(line) ||
        DIAGNOSTIC_KW.test(line)) &&
      INTERNAL_STACK.test(line)
    );
  }

  function scoreLine(line, seenCount) {
    if (line.trim().length === 0) return -Infinity;
    if (IGNORED_TAG.test(line)) return -Infinity;

    let score = 0;
    if (IMPORTANT_TAG.test(line)) score += 100;
    if (JSON_SEVERITY.test(line)) score += 80;
    if (SCANNER_FINDING.test(line)) score += 70;
    if (CONTAINER_FAIL.test(line)) score += 70;
    if (NPM_ERR.test(line) || YARN_ERR.test(line)) score += 60;
    if (DIAGNOSTIC_KW.test(line)) score += 50;
    if (
      STACK_FRAME.test(line) ||
      PYTHON_TRACEBACK.test(line) ||
      GO_GOROUTINE.test(line) ||
      STACK_MORE.test(line)
    ) {
      score += 40;
    }

    if (seenCount >= TFIDF_REPEAT_THRESHOLD) {
      score -= TFIDF_PENALTY * (seenCount - TFIDF_REPEAT_THRESHOLD + 1);
    }

    return score;
  }

  function detectSources(lines, limit) {
    const hits = new Map();
    for (const line of lines) {
      const low = line.toLowerCase();
      for (const [src, markers] of SOURCE_SIGS) {
        for (const m of markers) {
          if (low.includes(m)) {
            hits.set(src, (hits.get(src) ?? 0) + 1);
            break;
          }
        }
      }
    }
    return [...hits.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, limit || 5)
      .map(([s]) => s);
  }

  function estimateTokens(wordCount) {
    return Math.ceil(wordCount * 1.3);
  }

  function countWords(line) {
    return line.trim().match(/\S+/g)?.length ?? 0;
  }

  function compress(raw) {
    const lines = raw.split(/\r?\n/);
    const out = [];
    let dropped = 0;
    let duplicates = 0;
    let hidden = 0;

    // Source detection
    const sources = detectSources(lines, 5);

    // TF-IDF frequency map (bounded)
    const seenLines = new Map();

    // Context window
    const contextBefore = [];
    let afterContextRemaining = 0;

    // Deduplication state
    let previousGroup;
    let hidingInternalStack = false;

    // Stats accumulators
    let inputWords = 0;
    let outputWords = 0;

    function emit(line) {
      const signature = createRepeatSignature(line);
      if (previousGroup?.signature === signature) {
        addRepeatGroupLine(previousGroup, line);
        return;
      }
      flushPrev();
      previousGroup = createRepeatGroup(line);
    }

    function flushPrev() {
      if (previousGroup === undefined) return;
      const rendered =
        previousGroup.count > 1
          ? `[x${previousGroup.count}] ${renderRepeatGroup(previousGroup)}`
          : previousGroup.firstLine;
      if (previousGroup.count > 1) duplicates += previousGroup.count - 1;
      out.push(rendered);
      outputWords += countWords(rendered);
      previousGroup = undefined;
    }

    function flushContextBefore() {
      for (const b of contextBefore) emit(b);
      contextBefore.length = 0;
    }

    for (const original of lines) {
      inputWords += countWords(original);

      if (original.trim().length === 0) {
        dropped += 1;
        continue;
      }

      // Noise tags silently dropped (don't disturb afterContext)
      if (IGNORED_TAG.test(original)) {
        dropped += 1;
        hidingInternalStack = false;
        continue;
      }

      const sanitized = sanitizeLine(original);

      // Internal stack collapsing
      if (isInternalStackLine(sanitized)) {
        hidden += 1;
        if (!hidingInternalStack) {
          flushContextBefore();
          emit(INTERNAL_STACK_MARKER);
          hidingInternalStack = true;
          afterContextRemaining = 0;
        }
        continue;
      }

      hidingInternalStack = false;

      // TF-IDF tracking
      let seenCount = (seenLines.get(sanitized) ?? 0) + 1;
      if (seenCount === 1 && seenLines.size >= TFIDF_MAP_LIMIT) {
        seenLines.clear();
        seenCount = 1;
      }
      seenLines.set(sanitized, seenCount);

      const score = scoreLine(sanitized, seenCount);

      if (score >= SCORE_KEEP_THRESHOLD) {
        flushContextBefore();
        emit(sanitized);
        afterContextRemaining = CONTEXT_WINDOW_AFTER;
      } else if (afterContextRemaining > 0) {
        emit(sanitized);
        afterContextRemaining -= 1;
      } else if (score >= 0) {
        if (contextBefore.length >= CONTEXT_WINDOW_BEFORE) {
          contextBefore.shift();
          dropped += 1;
        }
        contextBefore.push(sanitized);
      } else {
        dropped += 1;
        afterContextRemaining = 0;
      }
    }

    // Unpromoted context lines are discarded
    dropped += contextBefore.length;
    flushPrev();

    const inputTokens = estimateTokens(inputWords);
    const outputTokens = estimateTokens(outputWords);
    const savedTokens = Math.max(0, inputTokens - outputTokens);
    const savingsPercent =
      inputTokens === 0
        ? 0
        : Math.round((savedTokens / inputTokens) * 10000) / 100;

    return {
      output: out.join('\n'),
      inputTokens,
      outputTokens,
      savedTokens,
      savingsPercent,
      droppedLines: dropped,
      duplicateLines: duplicates,
      hiddenInternalStackLines: hidden,
      detectedSources: sources,
    };
  }

  function setupPlayground() {
    const root = document.querySelector('[data-logstrip-playground]');
    if (!root) return;
    const input = root.querySelector('[data-logstrip-input]');
    const output = root.querySelector('[data-logstrip-output]');
    const stats = root.querySelector('[data-logstrip-stats]');
    const runBtn = root.querySelector('[data-logstrip-run]');
    const resetBtn = root.querySelector('[data-logstrip-reset]');
    const demoBtn = root.querySelector('[data-logstrip-demo-btn]');
    if (!input || !output || !stats) return;

    const initial = input.value;

    function fmt(n) {
      return n.toLocaleString('en-US');
    }

    function setStat(key, value) {
      const el = stats.querySelector(`[data-stat="${key}"]`);
      if (el) el.textContent = value;
    }

    function run() {
      const result = compress(input.value);
      const sourceTag =
        result.detectedSources && result.detectedSources.length
          ? `detected: ${result.detectedSources.join(' · ')}\n\n`
          : '';
      output.textContent = sourceTag + result.output;
      setStat('input-tokens', fmt(result.inputTokens));
      setStat('output-tokens', fmt(result.outputTokens));
      setStat('savings', `${result.savingsPercent}%`);
      setStat('dropped', fmt(result.droppedLines));
      setStat('duplicates', fmt(result.duplicateLines));
      setStat('hidden', fmt(result.hiddenInternalStackLines));
    }

    if (runBtn) runBtn.addEventListener('click', run);
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        input.value = initial;
        run();
      });
    }
    if (demoBtn) {
      demoBtn.addEventListener('click', () => {
        input.value = DEMO_LOG;
        run();
      });
    }

    run();
  }

  // Hero demo scenarios. Every clean output and every metric below was
  // produced by running the real CLI (node dist/cli/index.js) against the
  // raw log shown - nothing is hand-written. `fates` maps each raw line to
  // its destiny during the morph animation: ['k', cleanIdx] survives as
  // clean[cleanIdx], ['g', leaderIdx] collapses into the raw leader line,
  // ['d'] is dropped. The final state is always the exact CLI output
  // (cleanPre), so the morph is presentation only. Regenerate with the
  // commands recorded in each scenario's `cmd` field if parser output changes.
  const HERO_SCENARIOS = [
    {
      "id": "incident",
      "label": "incident",
      "title": "raw.log → logstrip.log",
      "cmd": "logstrip raw.log --stats",
      "agent": [
        [
          "likely root cause",
          "payments charge failed across 3 requests"
        ],
        [
          "leaked credential",
          "api_key masked to [REDACTED]"
        ],
        [
          "app frame",
          "ChargeService.process:42"
        ],
        [
          "noise removed",
          "36 low-value lines · internal frames collapsed"
        ]
      ],
      "metrics": [
        [
          "80.48%",
          "token savings"
        ],
        [
          "36",
          "lines dropped"
        ],
        [
          "2",
          "duplicates folded"
        ],
        [
          "1",
          "internal frames hidden"
        ]
      ],
      "raw": [
        "[INFO] 2026-05-15T08:01:12.001Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 12ms",
        "[INFO] 2026-05-15T08:01:12.018Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[DEBUG] 2026-05-15T08:01:12.034Z spring-boot [Actuator] health UP diskSpace 42.3GB/100GB",
        "[INFO] 2026-05-15T08:01:12.051Z i-0a1b2c3d4e5f6g7h8 [nginx] POST /api/v1/orders 201 10.0.1.15:443 → 10.42.7.18:8080 23ms",
        "[DEBUG] 2026-05-15T08:01:12.067Z spring-boot [HikariPool-1] Pool stats: active=3 idle=7 wait=0",
        "[INFO] 2026-05-15T08:01:12.084Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users/018f23ab-7c1d-7f44-8bfe-0acddaf33456 200 5ms",
        "[INFO] 2026-05-15T08:01:12.101Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /static/app.js 304 2ms",
        "[INFO] 2026-05-15T08:01:12.118Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /static/vendor.js 304 2ms",
        "[DEBUG] 2026-05-15T08:01:12.134Z spring-boot [Tomcat] thread pool: current=12 max=200",
        "[INFO] 2026-05-15T08:01:12.151Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/cart 200 10.0.1.15:443 → 10.42.7.18:8080 7ms",
        "[INFO] 2026-05-15T08:01:12.168Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /favicon.ico 200 1ms",
        "[INFO] 2026-05-15T08:01:12.185Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/recommendations 200 10.0.1.15:443 → 10.42.7.18:8080 45ms",
        "[DEBUG] 2026-05-15T08:01:12.201Z spring-boot [Redis] GET cache:session:018f23ab-7c1d-7f44-8bfe-0acddaf33499 hit TTL=1800",
        "[INFO] 2026-05-15T08:01:12.218Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[INFO] 2026-05-15T08:01:12.235Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products?page=2 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[INFO] 2026-05-15T08:01:12.251Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 13ms",
        "[DEBUG] 2026-05-15T08:01:12.268Z spring-boot [Kafka] consumer orders-group offset=184741 lag=0",
        "[INFO] 2026-05-15T08:01:12.285Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 10ms",
        "[INFO] 2026-05-15T08:01:12.302Z i-0a1b2c3d4e5f6g7h8 [nginx] PUT /api/v1/users/018f23ab-7c1d-7f44-8bfe-0acddaf33456 200 18ms",
        "[INFO] 2026-05-15T08:01:12.318Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/notifications 200 10.0.1.15:443 → 10.42.7.18:8080 6ms",
        "[DEBUG] 2026-05-15T08:01:12.335Z spring-boot [Actuator] prometheus scrape 42 metrics exported",
        "[INFO] 2026-05-15T08:01:12.352Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 14ms",
        "[INFO] 2026-05-15T08:01:12.369Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 7ms",
        "[INFO] 2026-05-15T08:01:12.385Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[DEBUG] 2026-05-15T08:01:12.402Z spring-boot [HikariPool-1] getConnection 3ms total=10",
        "[INFO] 2026-05-15T08:01:12.419Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] gateway auth rejected api_key=2qy81FdkchesO1HxzS3v9XmQ7TgL5BnA",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33456 amount=99.99",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33457 amount=49.50",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33458 amount=12.00",
        "java.lang.NullPointerException: Cannot read \"userId\" of null",
        "    at com.shop.payments.ChargeService.process(ChargeService.java:42)",
        "    at com.shop.payments.ChargeController.post(ChargeController.java:88)",
        "    at javax.servlet.http.HttpServlet.service(HttpServlet.java:623)",
        "    at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:227)",
        "    at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)",
        "    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)",
        "[INFO] 2026-05-15T08:01:12.502Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[WARN] 2026-05-15T08:01:12.519Z spring-boot [circuit-breaker] payments-service OPEN failures=3/5",
        "[INFO] 2026-05-15T08:01:12.536Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 6ms",
        "CRITICAL CVE-2026-12345 openssl 3.0.13-r0 fixed=3.0.15-r2",
        "HIGH GHSA-ab12-cd34-ef56 axios 1.7.0 fixed=1.8.2",
        "[INFO] 2026-05-15T08:01:12.586Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 10ms",
        "[INFO] 2026-05-15T08:01:12.603Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/cart 200 10.0.1.15:443 → 10.42.7.18:8080 5ms",
        "Warning BackOff restarting failed container checkout-api in pod checkout-api-84b7c46f8b-r9x2n",
        "Warning Failed Error: ErrImagePull image=registry.example.com/checkout@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "[INFO] 2026-05-15T08:01:12.653Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 12ms",
        "panic: runtime error: invalid memory address or nil pointer dereference",
        "    at main (main.go:88:13)",
        "[INFO] 2026-05-15T08:01:12.703Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[INFO] 2026-05-15T08:01:12.720Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[INFO] 2026-05-15T08:01:12.736Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[INFO] 2026-05-15T08:01:12.753Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /health 200 1ms",
        "[INFO] 2026-05-15T08:01:12.770Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 7ms"
      ],
      "clean": [
        "❯ logstrip raw.log --stats",
        "✓ detected: nginx · spring-boot · kafka · tomcat · trivy",
        "[ERROR] [TIME] spring-boot [payments] gateway auth rejected api_key=[REDACTED]",
        "[x3] [ERROR] [TIME] spring-boot [payments] charge failed requestId=[ID] amount=[99.99 | 49.50 | 12.00]",
        "java.lang.NullPointerException: Cannot read \"userId\" of null",
        "    at com.shop.payments.ChargeService.process(ChargeService.java:[NN])",
        "    at com.shop.payments.ChargeController.post(ChargeController.java:[NN])",
        "    at javax.servlet.http.HttpServlet.service(HttpServlet.java:[NN])",
        "    at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:[NN])",
        "[... hidden internal library frames ...]",
        "    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)",
        "[WARN] [TIME] spring-boot [circuit-breaker] payments-service OPEN failures=3/5",
        "CRITICAL CVE-2026-12345 openssl 3.0.13-r0 fixed=3.0.15-r2",
        "HIGH GHSA-ab12-cd34-ef56 axios 1.7.0 fixed=1.8.2",
        "Warning BackOff restarting failed container checkout-api in pod checkout-api-84b7c46f8b-r9x2n",
        "Warning Failed Error: ErrImagePull image=registry.example.com/checkout@sha256:[HASH]",
        "panic: runtime error: invalid memory address or nil pointer dereference",
        "    at main (main.go:[NN]:[NN])"
      ],
      "fates": [
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          2
        ],
        [
          "k",
          3
        ],
        [
          "g",
          27
        ],
        [
          "g",
          27
        ],
        [
          "k",
          4
        ],
        [
          "k",
          5
        ],
        [
          "k",
          6
        ],
        [
          "k",
          7
        ],
        [
          "k",
          8
        ],
        [
          "d"
        ],
        [
          "k",
          10
        ],
        [
          "d"
        ],
        [
          "k",
          11
        ],
        [
          "d"
        ],
        [
          "k",
          12
        ],
        [
          "k",
          13
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          14
        ],
        [
          "k",
          15
        ],
        [
          "d"
        ],
        [
          "k",
          16
        ],
        [
          "k",
          17
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ]
      ]
    },
    {
      "id": "ci-build",
      "label": "ci build",
      "title": "build.log → logstrip.log",
      "cmd": "logstrip build.log --stats",
      "agent": [
        [
          "failing test",
          "ChargeService > retries declined cards once"
        ],
        [
          "assertion",
          "expected 2 to be 1 (charge.test.ts:88)"
        ],
        [
          "flaky retries",
          "folded into [x3] attempt [1 | 2 | 3]"
        ],
        [
          "noise removed",
          "25 low-value lines (npm warns, compile chunks)"
        ]
      ],
      "metrics": [
        [
          "56.29%",
          "token savings"
        ],
        [
          "25",
          "lines dropped"
        ],
        [
          "x3",
          "flaky retries folded"
        ],
        [
          "51",
          "tests summarized"
        ]
      ],
      "raw": [
        "[command]/usr/bin/git checkout --progress --force refs/remotes/origin/main",
        "2026-06-09T14:21:02.114Z ##[group]Run npm ci",
        "npm warn deprecated inflight@1.0.6: This module is not supported",
        "npm warn deprecated glob@7.2.3: Glob versions prior to v9 are no longer supported",
        "npm warn deprecated rimraf@3.0.2: Rimraf versions prior to v4 are no longer supported",
        "added 412 packages, and audited 413 packages in 9s",
        "2026-06-09T14:21:13.882Z ##[endgroup]",
        "> checkout-api@2.3.1 build",
        "> tsc -p tsconfig.build.json",
        "Compiling chunk 1 of 8",
        "Compiling chunk 2 of 8",
        "Compiling chunk 3 of 8",
        "Compiling chunk 4 of 8",
        "Compiling chunk 5 of 8",
        "Compiling chunk 6 of 8",
        "Compiling chunk 7 of 8",
        "Compiling chunk 8 of 8",
        "> checkout-api@2.3.1 test",
        "> vitest run --coverage",
        " RUN  v3.1.4 /home/runner/work/checkout-api",
        " ✓ tests/cart.test.ts (14 tests) 213ms",
        " ✓ tests/inventory.test.ts (9 tests) 102ms",
        " ✓ tests/pricing.test.ts (22 tests) 187ms",
        " ❯ tests/charge.test.ts (6 tests | 1 failed) 154ms",
        "FAIL tests/charge.test.ts > ChargeService > retries declined cards once",
        "AssertionError: expected 2 to be 1 // Object.is equality",
        "- Expected: 1",
        "+ Received: 2",
        "    at tests/charge.test.ts:88:31",
        "    at file:///home/runner/work/checkout-api/node_modules/@vitest/runner/dist/index.js:135:14",
        "    at file:///home/runner/work/checkout-api/node_modules/@vitest/runner/dist/index.js:60:26",
        "Retrying flaky test charge.test.ts attempt 1",
        "Retrying flaky test charge.test.ts attempt 2",
        "Retrying flaky test charge.test.ts attempt 3",
        " Test Files  1 failed | 3 passed (4)",
        "      Tests  1 failed | 50 passed (51)",
        "   Duration  4216ms",
        "npm ERR! Lifecycle script `test` failed with error:",
        "npm ERR! code 1",
        "npm ERR! workspace checkout-api@2.3.1",
        "2026-06-09T14:22:41.005Z ##[error]Process completed with exit code 1.",
        "Uploading artifact coverage-report (size: 1.2 MB)",
        "Artifact upload finished"
      ],
      "clean": [
        "❯ logstrip build.log --stats",
        "✓ detected: github-actions · npm · vitest · typescript",
        " ✓ tests/cart.test.ts (14 tests) 213ms",
        " ✓ tests/inventory.test.ts (9 tests) 102ms",
        " ✓ tests/pricing.test.ts (22 tests) 187ms",
        " ❯ tests/charge.test.ts (6 tests | 1 failed) 154ms",
        "FAIL tests/charge.test.ts > ChargeService > retries declined cards once",
        "AssertionError: expected 2 to be 1 // Object.is equality",
        "- Expected: 1",
        "[x3] Retrying flaky test charge.test.ts attempt [1 | 2 | 3]",
        " Test Files  1 failed | 3 passed (4)",
        "      Tests  1 failed | 50 passed (51)",
        "   Duration  4216ms",
        "npm ERR! Lifecycle script `test` failed with error:",
        "npm ERR! code 1",
        "npm ERR! workspace checkout-api@2.3.1",
        "[TIME] ##[error]Process completed with exit code 1.",
        "Uploading artifact coverage-report (size: 1.2 MB)"
      ],
      "fates": [
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          2
        ],
        [
          "k",
          3
        ],
        [
          "k",
          4
        ],
        [
          "k",
          5
        ],
        [
          "k",
          6
        ],
        [
          "k",
          7
        ],
        [
          "k",
          8
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          9
        ],
        [
          "g",
          31
        ],
        [
          "g",
          31
        ],
        [
          "k",
          10
        ],
        [
          "k",
          11
        ],
        [
          "k",
          12
        ],
        [
          "k",
          13
        ],
        [
          "k",
          14
        ],
        [
          "k",
          15
        ],
        [
          "k",
          16
        ],
        [
          "k",
          17
        ],
        [
          "d"
        ]
      ]
    },
    {
      "id": "security-scan",
      "label": "security scan",
      "title": "trivy.json → logstrip.json",
      "cmd": "logstrip trivy.json --stats",
      "agent": [
        [
          "ship blocker",
          "CVE-2026-12345 openssl CRITICAL 9.8 → fix 3.0.15-r2"
        ],
        [
          "grouped",
          "5 LOW busybox CVEs → one [logstrip:group] entry"
        ],
        [
          "pruned",
          "empty fields and 68 boilerplate lines"
        ],
        [
          "still valid JSON",
          "downstream tools can keep parsing it"
        ]
      ],
      "metrics": [
        [
          "38.22%",
          "token savings"
        ],
        [
          "68",
          "lines pruned"
        ],
        [
          "x5",
          "CVEs grouped"
        ],
        [
          "valid",
          "JSON preserved"
        ]
      ],
      "raw": [
        "{",
        "  \"SchemaVersion\": 2,",
        "  \"CreatedAt\": \"2026-06-10T07:12:44.118Z\",",
        "  \"ArtifactName\": \"registry.example.com/checkout:1.4.2\",",
        "  \"ArtifactType\": \"container_image\",",
        "  \"Metadata\": {",
        "    \"OS\": {",
        "      \"Family\": \"alpine\",",
        "      \"Name\": \"3.19.1\"",
        "    },",
        "    \"ImageID\": \"sha256:7b2f3a9c1d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f\",",
        "    \"RepoTags\": [",
        "      \"registry.example.com/checkout:1.4.2\"",
        "    ]",
        "  },",
        "  \"Results\": [",
        "    {",
        "      \"Target\": \"registry.example.com/checkout:1.4.2 (alpine 3.19.1)\",",
        "      \"Class\": \"os-pkgs\",",
        "      \"Type\": \"alpine\",",
        "      \"Vulnerabilities\": [",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-12345\",",
        "          \"PkgName\": \"openssl\",",
        "          \"InstalledVersion\": \"3.0.13-r0\",",
        "          \"FixedVersion\": \"3.0.15-r2\",",
        "          \"Status\": \"fixed\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-12345\",",
        "          \"Title\": \"openssl: buffer overflow in TLS handshake parsing\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"CRITICAL\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 9.8",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-12345\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-12345\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        },",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-20001\",",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"FixedVersion\": \"\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20001\",",
        "          \"Title\": \"busybox: awk integer overflow\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-20001\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-20001\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        },",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-20002\",",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"FixedVersion\": \"\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20002\",",
        "          \"Title\": \"busybox: wget header injection\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-20002\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-20002\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        },",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-20003\",",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"FixedVersion\": \"\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20003\",",
        "          \"Title\": \"busybox: ash heredoc parsing crash\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-20003\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-20003\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        },",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-20004\",",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"FixedVersion\": \"\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20004\",",
        "          \"Title\": \"busybox: tar path traversal\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-20004\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-20004\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        },",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-20005\",",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"FixedVersion\": \"\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20005\",",
        "          \"Title\": \"busybox: sed out-of-bounds read\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-20005\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-20005\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        }",
        "      ]",
        "    },",
        "    {",
        "      \"Target\": \"app/package-lock.json\",",
        "      \"Class\": \"lang-pkgs\",",
        "      \"Type\": \"npm\",",
        "      \"Vulnerabilities\": [",
        "        {",
        "          \"VulnerabilityID\": \"GHSA-ab12-cd34-ef56\",",
        "          \"PkgName\": \"axios\",",
        "          \"InstalledVersion\": \"1.7.0\",",
        "          \"FixedVersion\": \"1.8.2\",",
        "          \"Status\": \"fixed\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:9a4f0e3b2c1d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/ghsa-ab12-cd34-ef56\",",
        "          \"Title\": \"axios: SSRF via absolute URL in redirect handling\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"HIGH\",",
        "          \"CweIDs\": [],",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 7.7",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/GHSA-ab12-cd34-ef56\",",
        "            \"https://security.alpinelinux.org/vuln/GHSA-ab12-cd34-ef56\"",
        "          ],",
        "          \"PublishedDate\": \"2026-04-02T14:00:00Z\",",
        "          \"LastModifiedDate\": \"2026-05-29T09:30:00Z\"",
        "        }",
        "      ]",
        "    }",
        "  ]",
        "}"
      ],
      "clean": [
        "❯ logstrip trivy.json --stats",
        "✓ detected: trivy · docker · format: json report",
        "{",
        "  \"[logstrip:meta]\": \"\\\"[logstrip:= f]\\\" repeats the text of sibling field f; empty fields pruned; \\\"[logstrip:group]\\\" collapses entries identical except for the listed variant fields\",",
        "  \"SchemaVersion\": 2,",
        "  \"CreatedAt\": \"[TIME]\",",
        "  \"ArtifactName\": \"registry.example.com/checkout:1.4.2\",",
        "  \"ArtifactType\": \"container_image\",",
        "  \"Metadata\": {",
        "    \"OS\": {",
        "      \"Family\": \"alpine\",",
        "      \"Name\": \"3.19.1\"",
        "    },",
        "    \"ImageID\": \"sha256:[HASH]\",",
        "    \"RepoTags\": [",
        "      \"registry.example.com/checkout:1.4.2\"",
        "    ]",
        "  },",
        "  \"Results\": [",
        "    {",
        "      \"Target\": \"registry.example.com/checkout:1.4.2 (alpine 3.19.1)\",",
        "      \"Class\": \"os-pkgs\",",
        "      \"Type\": \"alpine\",",
        "      \"Vulnerabilities\": [",
        "        {",
        "          \"VulnerabilityID\": \"CVE-2026-12345\",",
        "          \"PkgName\": \"openssl\",",
        "          \"InstalledVersion\": \"3.0.13-r0\",",
        "          \"FixedVersion\": \"3.0.15-r2\",",
        "          \"Status\": \"fixed\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:[HASH]\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-12345\",",
        "          \"Title\": \"openssl: buffer overflow in TLS handshake parsing\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"CRITICAL\",",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 9.8",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/CVE-2026-12345\",",
        "            \"https://security.alpinelinux.org/vuln/CVE-2026-12345\"",
        "          ],",
        "          \"PublishedDate\": \"[TIME]\",",
        "          \"LastModifiedDate\": \"[TIME]\"",
        "        },",
        "        {",
        "          \"[logstrip:group]\": {",
        "            \"count\": 5,",
        "            \"variants\": [",
        "              {",
        "                \"VulnerabilityID\": \"CVE-2026-20001\",",
        "                \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20001\",",
        "                \"Title\": \"busybox: awk integer overflow\",",
        "                \"References\": [",
        "                  \"https://nvd.nist.gov/vuln/detail/CVE-2026-20001\",",
        "                  \"https://security.alpinelinux.org/vuln/CVE-2026-20001\"",
        "                ]",
        "              },",
        "              {",
        "                \"VulnerabilityID\": \"CVE-2026-20002\",",
        "                \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20002\",",
        "                \"Title\": \"busybox: wget header injection\",",
        "                \"References\": [",
        "                  \"https://nvd.nist.gov/vuln/detail/CVE-2026-20002\",",
        "                  \"https://security.alpinelinux.org/vuln/CVE-2026-20002\"",
        "                ]",
        "              },",
        "              {",
        "                \"VulnerabilityID\": \"CVE-2026-20003\",",
        "                \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20003\",",
        "                \"Title\": \"busybox: ash heredoc parsing crash\",",
        "                \"References\": [",
        "                  \"https://nvd.nist.gov/vuln/detail/CVE-2026-20003\",",
        "                  \"https://security.alpinelinux.org/vuln/CVE-2026-20003\"",
        "                ]",
        "              },",
        "              {",
        "                \"VulnerabilityID\": \"CVE-2026-20004\",",
        "                \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20004\",",
        "                \"Title\": \"busybox: tar path traversal\",",
        "                \"References\": [",
        "                  \"https://nvd.nist.gov/vuln/detail/CVE-2026-20004\",",
        "                  \"https://security.alpinelinux.org/vuln/CVE-2026-20004\"",
        "                ]",
        "              },",
        "              {",
        "                \"VulnerabilityID\": \"CVE-2026-20005\",",
        "                \"PrimaryURL\": \"https://avd.aquasec.com/nvd/cve-2026-20005\",",
        "                \"Title\": \"busybox: sed out-of-bounds read\",",
        "                \"References\": [",
        "                  \"https://nvd.nist.gov/vuln/detail/CVE-2026-20005\",",
        "                  \"https://security.alpinelinux.org/vuln/CVE-2026-20005\"",
        "                ]",
        "              }",
        "            ]",
        "          },",
        "          \"PkgName\": \"busybox\",",
        "          \"InstalledVersion\": \"1.36.1-r15\",",
        "          \"Status\": \"affected\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:[HASH]\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"LOW\",",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 3.3",
        "            }",
        "          },",
        "          \"PublishedDate\": \"[TIME]\",",
        "          \"LastModifiedDate\": \"[TIME]\"",
        "        }",
        "      ]",
        "    },",
        "    {",
        "      \"Target\": \"app/package-lock.json\",",
        "      \"Class\": \"lang-pkgs\",",
        "      \"Type\": \"npm\",",
        "      \"Vulnerabilities\": [",
        "        {",
        "          \"VulnerabilityID\": \"GHSA-ab12-cd34-ef56\",",
        "          \"PkgName\": \"axios\",",
        "          \"InstalledVersion\": \"1.7.0\",",
        "          \"FixedVersion\": \"1.8.2\",",
        "          \"Status\": \"fixed\",",
        "          \"Layer\": {",
        "            \"Digest\": \"sha256:[HASH]\"",
        "          },",
        "          \"SeveritySource\": \"nvd\",",
        "          \"PrimaryURL\": \"https://avd.aquasec.com/nvd/ghsa-ab12-cd34-ef56\",",
        "          \"Title\": \"axios: SSRF via absolute URL in redirect handling\",",
        "          \"Description\": \"A flaw was found in the affected package. A remote attacker able to supply crafted input may trigger memory corruption, leading to denial of service or potential remote code execution. Upgrade to the fixed version where available.\",",
        "          \"Severity\": \"HIGH\",",
        "          \"CVSS\": {",
        "            \"nvd\": {",
        "              \"V3Score\": 7.7",
        "            }",
        "          },",
        "          \"References\": [",
        "            \"https://nvd.nist.gov/vuln/detail/GHSA-ab12-cd34-ef56\",",
        "            \"https://security.alpinelinux.org/vuln/GHSA-ab12-cd34-ef56\"",
        "          ],",
        "          \"PublishedDate\": \"[TIME]\",",
        "          \"LastModifiedDate\": \"[TIME]\"",
        "        }",
        "      ]",
        "    }",
        "  ]",
        "}"
      ],
      "fates": [
        [
          "k",
          2
        ],
        [
          "k",
          4
        ],
        [
          "k",
          5
        ],
        [
          "k",
          6
        ],
        [
          "k",
          7
        ],
        [
          "k",
          8
        ],
        [
          "k",
          9
        ],
        [
          "k",
          10
        ],
        [
          "k",
          11
        ],
        [
          "k",
          12
        ],
        [
          "k",
          13
        ],
        [
          "k",
          14
        ],
        [
          "k",
          15
        ],
        [
          "k",
          16
        ],
        [
          "k",
          17
        ],
        [
          "k",
          18
        ],
        [
          "k",
          19
        ],
        [
          "k",
          20
        ],
        [
          "k",
          21
        ],
        [
          "k",
          22
        ],
        [
          "k",
          23
        ],
        [
          "k",
          24
        ],
        [
          "k",
          25
        ],
        [
          "k",
          26
        ],
        [
          "k",
          27
        ],
        [
          "k",
          28
        ],
        [
          "k",
          29
        ],
        [
          "k",
          30
        ],
        [
          "k",
          31
        ],
        [
          "k",
          32
        ],
        [
          "k",
          33
        ],
        [
          "k",
          34
        ],
        [
          "k",
          35
        ],
        [
          "k",
          36
        ],
        [
          "k",
          37
        ],
        [
          "d"
        ],
        [
          "k",
          38
        ],
        [
          "k",
          39
        ],
        [
          "k",
          40
        ],
        [
          "k",
          41
        ],
        [
          "k",
          42
        ],
        [
          "k",
          43
        ],
        [
          "k",
          44
        ],
        [
          "k",
          45
        ],
        [
          "k",
          46
        ],
        [
          "k",
          47
        ],
        [
          "k",
          48
        ],
        [
          "k",
          49
        ],
        [
          "k",
          50
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          100
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          101
        ],
        [
          "k",
          102
        ],
        [
          "d"
        ],
        [
          "k",
          103
        ],
        [
          "k",
          104
        ],
        [
          "k",
          105
        ],
        [
          "k",
          106
        ],
        [
          "k",
          107
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          108
        ],
        [
          "k",
          109
        ],
        [
          "d"
        ],
        [
          "k",
          110
        ],
        [
          "k",
          111
        ],
        [
          "k",
          112
        ],
        [
          "k",
          113
        ],
        [
          "k",
          114
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          115
        ],
        [
          "k",
          116
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          117
        ],
        [
          "k",
          118
        ],
        [
          "k",
          119
        ],
        [
          "k",
          120
        ],
        [
          "k",
          121
        ],
        [
          "k",
          122
        ],
        [
          "k",
          123
        ],
        [
          "k",
          124
        ],
        [
          "k",
          125
        ],
        [
          "k",
          126
        ],
        [
          "k",
          127
        ],
        [
          "k",
          128
        ],
        [
          "k",
          129
        ],
        [
          "k",
          130
        ],
        [
          "k",
          131
        ],
        [
          "k",
          132
        ],
        [
          "k",
          133
        ],
        [
          "k",
          134
        ],
        [
          "k",
          135
        ],
        [
          "k",
          136
        ],
        [
          "k",
          137
        ],
        [
          "k",
          138
        ],
        [
          "d"
        ],
        [
          "k",
          139
        ],
        [
          "k",
          140
        ],
        [
          "k",
          141
        ],
        [
          "k",
          142
        ],
        [
          "k",
          143
        ],
        [
          "k",
          144
        ],
        [
          "k",
          145
        ],
        [
          "k",
          146
        ],
        [
          "k",
          147
        ],
        [
          "k",
          148
        ],
        [
          "k",
          149
        ],
        [
          "k",
          150
        ],
        [
          "k",
          151
        ],
        [
          "k",
          152
        ],
        [
          "k",
          153
        ],
        [
          "k",
          154
        ]
      ]
    },
    {
      "id": "token-budget",
      "label": "token budget",
      "title": "raw.log → 60-token budget",
      "cmd": "logstrip raw.log --max-tokens 60 --stats",
      "agent": [
        [
          "token budget",
          "--max-tokens 60 → output is 58 tokens"
        ],
        [
          "kept",
          "only the highest-scoring diagnostic lines"
        ],
        [
          "root cause survives",
          "charge failures + NullPointerException intact"
        ],
        [
          "fits",
          "any model context window, however small"
        ]
      ],
      "metrics": [
        [
          "58 / 60",
          "tokens used"
        ],
        [
          "90.15%",
          "token savings"
        ],
        [
          "46",
          "lines dropped"
        ],
        [
          "6",
          "lines kept"
        ]
      ],
      "raw": [
        "[INFO] 2026-05-15T08:01:12.001Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 12ms",
        "[INFO] 2026-05-15T08:01:12.018Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[DEBUG] 2026-05-15T08:01:12.034Z spring-boot [Actuator] health UP diskSpace 42.3GB/100GB",
        "[INFO] 2026-05-15T08:01:12.051Z i-0a1b2c3d4e5f6g7h8 [nginx] POST /api/v1/orders 201 10.0.1.15:443 → 10.42.7.18:8080 23ms",
        "[DEBUG] 2026-05-15T08:01:12.067Z spring-boot [HikariPool-1] Pool stats: active=3 idle=7 wait=0",
        "[INFO] 2026-05-15T08:01:12.084Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users/018f23ab-7c1d-7f44-8bfe-0acddaf33456 200 5ms",
        "[INFO] 2026-05-15T08:01:12.101Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /static/app.js 304 2ms",
        "[INFO] 2026-05-15T08:01:12.118Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /static/vendor.js 304 2ms",
        "[DEBUG] 2026-05-15T08:01:12.134Z spring-boot [Tomcat] thread pool: current=12 max=200",
        "[INFO] 2026-05-15T08:01:12.151Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/cart 200 10.0.1.15:443 → 10.42.7.18:8080 7ms",
        "[INFO] 2026-05-15T08:01:12.168Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /favicon.ico 200 1ms",
        "[INFO] 2026-05-15T08:01:12.185Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/recommendations 200 10.0.1.15:443 → 10.42.7.18:8080 45ms",
        "[DEBUG] 2026-05-15T08:01:12.201Z spring-boot [Redis] GET cache:session:018f23ab-7c1d-7f44-8bfe-0acddaf33499 hit TTL=1800",
        "[INFO] 2026-05-15T08:01:12.218Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[INFO] 2026-05-15T08:01:12.235Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products?page=2 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[INFO] 2026-05-15T08:01:12.251Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 13ms",
        "[DEBUG] 2026-05-15T08:01:12.268Z spring-boot [Kafka] consumer orders-group offset=184741 lag=0",
        "[INFO] 2026-05-15T08:01:12.285Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 10ms",
        "[INFO] 2026-05-15T08:01:12.302Z i-0a1b2c3d4e5f6g7h8 [nginx] PUT /api/v1/users/018f23ab-7c1d-7f44-8bfe-0acddaf33456 200 18ms",
        "[INFO] 2026-05-15T08:01:12.318Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/notifications 200 10.0.1.15:443 → 10.42.7.18:8080 6ms",
        "[DEBUG] 2026-05-15T08:01:12.335Z spring-boot [Actuator] prometheus scrape 42 metrics exported",
        "[INFO] 2026-05-15T08:01:12.352Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 14ms",
        "[INFO] 2026-05-15T08:01:12.369Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 7ms",
        "[INFO] 2026-05-15T08:01:12.385Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[DEBUG] 2026-05-15T08:01:12.402Z spring-boot [HikariPool-1] getConnection 3ms total=10",
        "[INFO] 2026-05-15T08:01:12.419Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] gateway auth rejected api_key=2qy81FdkchesO1HxzS3v9XmQ7TgL5BnA",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33456 amount=99.99",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33457 amount=49.50",
        "[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33458 amount=12.00",
        "java.lang.NullPointerException: Cannot read \"userId\" of null",
        "    at com.shop.payments.ChargeService.process(ChargeService.java:42)",
        "    at com.shop.payments.ChargeController.post(ChargeController.java:88)",
        "    at javax.servlet.http.HttpServlet.service(HttpServlet.java:623)",
        "    at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:227)",
        "    at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)",
        "    at java.base/jdk.internal.reflect.NativeMethodAccessorImpl.invoke0(Native Method)",
        "[INFO] 2026-05-15T08:01:12.502Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[WARN] 2026-05-15T08:01:12.519Z spring-boot [circuit-breaker] payments-service OPEN failures=3/5",
        "[INFO] 2026-05-15T08:01:12.536Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 6ms",
        "CRITICAL CVE-2026-12345 openssl 3.0.13-r0 fixed=3.0.15-r2",
        "HIGH GHSA-ab12-cd34-ef56 axios 1.7.0 fixed=1.8.2",
        "[INFO] 2026-05-15T08:01:12.586Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 10ms",
        "[INFO] 2026-05-15T08:01:12.603Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/cart 200 10.0.1.15:443 → 10.42.7.18:8080 5ms",
        "Warning BackOff restarting failed container checkout-api in pod checkout-api-84b7c46f8b-r9x2n",
        "Warning Failed Error: ErrImagePull image=registry.example.com/checkout@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "[INFO] 2026-05-15T08:01:12.653Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 12ms",
        "panic: runtime error: invalid memory address or nil pointer dereference",
        "    at main (main.go:88:13)",
        "[INFO] 2026-05-15T08:01:12.703Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 11ms",
        "[INFO] 2026-05-15T08:01:12.720Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/products 200 10.0.1.15:443 → 10.42.7.18:8080 8ms",
        "[INFO] 2026-05-15T08:01:12.736Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 9ms",
        "[INFO] 2026-05-15T08:01:12.753Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /health 200 1ms",
        "[INFO] 2026-05-15T08:01:12.770Z i-0a1b2c3d4e5f6g7h8 [nginx] GET /api/v1/users 200 10.0.1.15:443 → 10.42.7.18:8080 7ms"
      ],
      "clean": [
        "❯ logstrip raw.log --max-tokens 60 --stats",
        "✓ detected: nginx · spring-boot · kafka · tomcat · trivy",
        "[ERROR] [TIME] spring-boot [payments] gateway auth rejected api_key=[REDACTED]",
        "[x3] [ERROR] [TIME] spring-boot [payments] charge failed requestId=[ID] amount=[99.99 | 49.50 | 12.00]",
        "java.lang.NullPointerException: Cannot read \"userId\" of null",
        "[WARN] [TIME] spring-boot [circuit-breaker] payments-service OPEN failures=3/5",
        "CRITICAL CVE-2026-12345 openssl 3.0.13-r0 fixed=3.0.15-r2",
        "Warning Failed Error: ErrImagePull image=registry.example.com/checkout@sha256:[HASH]"
      ],
      "fates": [
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          2
        ],
        [
          "k",
          3
        ],
        [
          "g",
          27
        ],
        [
          "g",
          27
        ],
        [
          "k",
          4
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          5
        ],
        [
          "d"
        ],
        [
          "k",
          6
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "k",
          7
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ],
        [
          "d"
        ]
      ]
    }
  ];

  function setupCompareDemo() {
    document.querySelectorAll('[data-logstrip-compare]').forEach((root) => {
      if (root.dataset.logstripCompareReady === 'true') return;
      root.dataset.logstripCompareReady = 'true';

      const prefersReduced =
        window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

      function esc(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      }

      function highlightLine(l) {
        if (/^❯ /.test(l)) return `<span class="det">${esc(l)}</span>`;
        if (/^✓ detected:/i.test(l)) return `<span class="det">${esc(l)}</span>`;
        if (/^\[x\d+\]/.test(l)) return `<span class="x">${esc(l).replace(/^(\[x\d+\])/, '<span class="dup">$1</span>')}</span>`;
        if (/\[logstrip:(?:meta|group|=)/.test(l)) return `<span class="dup">${esc(l)}</span>`;
        if (/hidden internal (?:library|stack) frames/i.test(l)) return `<span class="stk">${esc(l)}</span>`;
        if (/\[(?:ERROR|FATAL|CRITICAL)\]|^FAIL\s|AssertionError|npm ERR!|##\[error\]|panic|BackOff|ErrImagePull/i.test(l)) return `<span class="err">${esc(l)}</span>`;
        if (/"Severity":\s*"(?:CRITICAL|HIGH)"|CVE-|GHSA-|^CRITICAL\s|^HIGH\s/.test(l)) return `<span class="scan">${esc(l)}</span>`;
        if (/\[(?:WARN)\]|^\s*❯\s/i.test(l)) return `<span class="warn">${esc(l)}</span>`;
        if (/^\s*at\s|^\s*✓\s/.test(l)) return `<span class="mark">${esc(l)}</span>`;
        if (/\[ID\]|\[HASH\]|\[IP\]|\[TIME\]|\[REDACTED\]|\[NN\]|\[[^\]]+\s\|\s[^\]]+\]/.test(l)) return `<span class="san">${esc(l)}</span>`;
        return esc(l);
      }

      root.innerHTML = `
        <div class="logstrip-demo__bar">
          <span class="logstrip-demo__dot"></span>
          <span class="logstrip-demo__dot"></span>
          <span class="logstrip-demo__dot"></span>
          <span class="logstrip-demo__title" data-logstrip-title></span>
        </div>
        <div class="logstrip-demo__tabs" role="tablist" aria-label="Demo scenarios">
          ${HERO_SCENARIOS.map((s, i) => `<button class="logstrip-demo__tab${i === 0 ? ' is-active' : ''}" type="button" role="tab" aria-selected="${i === 0}" data-logstrip-tab="${s.id}">${esc(s.label)}</button>`).join('')}
        </div>
        <div class="logstrip-demo__toggle" data-logstrip-toggle>
          <span class="logstrip-toggle__hint" data-logstrip-hint>try me <span class="logstrip-toggle__arrow">↓</span></span>
          <div class="logstrip-toggle__row">
            <button class="logstrip-toggle__side logstrip-toggle__side--raw is-active" data-logstrip-raw-btn type="button">raw</button>
            <button class="logstrip-toggle__pill" data-logstrip-pill type="button" aria-label="Switch between raw and LogStrip output">
              <span class="logstrip-toggle__knob"></span>
            </button>
            <button class="logstrip-toggle__side logstrip-toggle__side--clean" data-logstrip-clean-btn type="button"><img class="logstrip-toggle__icon logstrip-toggle__icon--logo" src="assets/images/logo2-256.webp" alt="" width="235" height="256">logstrip</button>
          </div>
        </div>
        <div class="logstrip-demo__screen" data-logstrip-screen>
          <pre class="logstrip-demo__pre logstrip-demo__pre--raw" data-logstrip-raw-pre></pre>
          <pre class="logstrip-demo__pre logstrip-demo__pre--clean" data-logstrip-clean-pre></pre>
          <div class="logstrip-demo__agent-card" data-logstrip-agent aria-label="Agent-ready summary"></div>
        </div>
        <div class="logstrip-demo__metrics" data-logstrip-metrics></div>`;

      const title = root.querySelector('[data-logstrip-title]');
      const tabs = Array.from(root.querySelectorAll('[data-logstrip-tab]'));
      const rawBtn = root.querySelector('[data-logstrip-raw-btn]');
      const cleanBtn = root.querySelector('[data-logstrip-clean-btn]');
      const pill = root.querySelector('[data-logstrip-pill]');
      const hint = root.querySelector('[data-logstrip-hint]');
      const screen = root.querySelector('[data-logstrip-screen]');
      const metrics = root.querySelector('[data-logstrip-metrics]');
      const rawPre = root.querySelector('[data-logstrip-raw-pre]');
      const cleanPre = root.querySelector('[data-logstrip-clean-pre]');
      const agentCard = root.querySelector('[data-logstrip-agent]');

      if (!rawBtn || !cleanBtn || !pill || !screen || !rawPre || !cleanPre) return;

      let mode = 'raw';
      let current = HERO_SCENARIOS[0];
      let morphTimers = [];

      function clearMorph() {
        morphTimers.forEach(clearTimeout);
        morphTimers = [];
      }

      function schedule(fn, t) {
        morphTimers.push(setTimeout(fn, t));
      }

      function renderRaw(scenario) {
        rawPre.innerHTML = scenario.raw
          .map((l) => `<span class="logstrip-demo__ln">${esc(l) || ' '}</span>`)
          .join('');
      }

      function setControls(clean) {
        rawBtn.classList.toggle('is-active', !clean);
        cleanBtn.classList.toggle('is-active', clean);
        pill.classList.toggle('is-clean', clean);
        if (hint) hint.classList.toggle('is-hidden', clean);
      }

      function animateMetric(el) {
        const finalText = el.dataset.logstripFinal || '';
        const m = finalText.match(/-?\d+(?:\.\d+)?/);
        if (!m || prefersReduced) {
          el.textContent = finalText;
          return;
        }
        const target = parseFloat(m[0]);
        const decimals = (m[0].split('.')[1] || '').length;
        const prefix = finalText.slice(0, m.index);
        const suffix = finalText.slice(m.index + m[0].length);
        const startTime = performance.now();
        const duration = 900;
        function frame(now) {
          const p = Math.min(1, (now - startTime) / duration);
          const eased = 1 - Math.pow(1 - p, 3);
          el.textContent = prefix + (target * eased).toFixed(decimals) + suffix;
          if (p < 1) requestAnimationFrame(frame);
          else el.textContent = finalText;
        }
        requestAnimationFrame(frame);
      }

      function finishClean() {
        mode = 'clean';
        screen.dataset.logstripMode = 'clean';
        if (metrics) {
          metrics.classList.add('is-visible');
          metrics.querySelectorAll('strong').forEach(animateMetric);
        }
      }

      function startMorph() {
        mode = 'morphing';
        setControls(true);
        if (metrics) metrics.classList.remove('is-visible');
        const fates = current.fates || [];
        const clean = current.clean;
        const spans = rawPre.children;
        for (let i = 0; i < spans.length; i++) {
          const span = spans[i];
          const fate = fates[i] || ['d'];
          if (fate[0] === 'd') {
            schedule(() => span.classList.add('is-dropping'), 120 + (i % 40) * 16);
          } else if (fate[0] === 'g') {
            schedule(() => span.classList.add('is-merging'), 360 + (i % 40) * 16);
          } else {
            schedule(() => {
              span.innerHTML = highlightLine(clean[fate[1]]);
              span.classList.add('is-swapped');
            }, 650 + (i % 40) * 22);
          }
        }
        schedule(finishClean, 1800);
      }

      function setMode(m) {
        if (m === 'clean') {
          if (mode !== 'raw') return;
          if (prefersReduced) {
            setControls(true);
            finishClean();
          } else {
            startMorph();
          }
        } else {
          clearMorph();
          mode = 'raw';
          renderRaw(current);
          screen.dataset.logstripMode = 'raw';
          setControls(false);
          if (metrics) metrics.classList.remove('is-visible');
        }
      }

      function setScenario(scenario) {
        clearMorph();
        current = scenario;
        if (title) title.textContent = scenario.title;
        cleanPre.innerHTML = scenario.clean.map(highlightLine).join('\n');
        if (agentCard) {
          agentCard.innerHTML =
            '<span class="logstrip-demo__agent-kicker">what the agent sees</span>' +
            scenario.agent.map(([label, value]) => `<div class="logstrip-demo__agent-row"><b>${esc(label)}</b><span>${esc(value)}</span></div>`).join('');
        }
        if (metrics) {
          metrics.innerHTML = scenario.metrics
            .map(([value, label]) => `<span><strong data-logstrip-final="${esc(value)}">${esc(value)}</strong> ${esc(label)}</span>`)
            .join('');
        }
        tabs.forEach((tab) => {
          const active = tab.dataset.logstripTab === scenario.id;
          tab.classList.toggle('is-active', active);
          tab.setAttribute('aria-selected', String(active));
        });
        mode = 'morphing'; // force setMode('raw') to do a full reset
        setMode('raw');
      }

      tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
          const scenario = HERO_SCENARIOS.find((s) => s.id === tab.dataset.logstripTab);
          if (scenario) setScenario(scenario);
        });
      });

      rawBtn.addEventListener('click', () => setMode('raw'));
      cleanBtn.addEventListener('click', () => setMode('clean'));
      pill.addEventListener('click', () => setMode(mode === 'raw' ? 'clean' : 'raw'));

      setScenario(HERO_SCENARIOS[0]);

      // Auto-pulse the pill to invite interaction
      let pulseCount = 0;
      const pulseInterval = setInterval(() => {
        pulseCount++;
        if (pulseCount > 6 || mode !== 'raw') {
          clearInterval(pulseInterval);
          return;
        }
        pill.classList.add('is-pulsing');
        setTimeout(() => pill.classList.remove('is-pulsing'), 600);
      }, 2400);
    });
  }
  const DEMO_LOG = [
    '[INFO] Starting build pipeline',
    '[DEBUG] Loading config from /home/runner/work/project/repo/config.json',
    '[INFO] Installing dependencies',
    '[INFO] npm install completed in 23.4s',
    '2026-05-14T11:22:33.512Z [ERROR] Request 018f23ab-7c1d-7f44-8bfe-0acddaf33456 failed: ECONNREFUSED 10.0.0.42:5432',
    '2026-05-14T11:22:33.514Z [ERROR] Request 018f23ab-7c1d-7f44-8bfe-0acddaf33457 failed: ECONNREFUSED 10.0.0.42:5432',
    '2026-05-14T11:22:33.516Z [ERROR] Request 018f23ab-7c1d-7f44-8bfe-0acddaf33458 failed: ECONNREFUSED 10.0.0.42:5432',
    '[ERROR] payment gateway rejected api_key=2qy81FdkchesO1HxzS3v9XmQ7TgL5BnA',
    'TypeError: Cannot read properties of undefined (reading "userId")',
    '    at processUser (/srv/app/src/services/user.ts:42:18)',
    '    at /srv/app/node_modules/express/lib/router/route.js:144:13',
    '    at next (/srv/app/node_modules/express/lib/router/route.js:140:14)',
    '    at Layer.handle (node:internal/handler.js:33:7)',
    '    at processTicksAndRejections (node:internal/process/task_queues.js:95:5)',
    '[INFO] Retrying request a1b2c3d4-e5f6-7a8b-9c0d-e1f2a3b4c5d6 (attempt 2/3)',
    '[ERROR] Sha256 mismatch: expected 5d41402abc4b2a76b9719d911017c592 got 7d793037a0760186574b0282f2f435e7',
    '[INFO] Build finished with errors',
  ].join('\n');

  function setupSourceMarquee() {
    var container = document.querySelector('.logstrip-ecosystem-marquee');
    if (!container) return;
    var pool = container.querySelector('.logstrip-ecosystem-marquee__pool');
    var rowsTarget = container.querySelector('[data-logstrip-marquee-rows]');
    if (!pool || !rowsTarget) return;

    var pills = Array.from(pool.querySelectorAll('.logstrip-tool-pill'));
    if (pills.length === 0) return;

    // Distribute pills into 3 rows, reverse the middle row for visual contrast
    var perRow = Math.ceil(pills.length / 3);
    var rowDefs = [
      { pills: pills.slice(0, perRow), reverse: false, speed: 50 },
      { pills: pills.slice(perRow, perRow * 2), reverse: true, speed: 58 },
      { pills: pills.slice(perRow * 2), reverse: false, speed: 46 },
    ];

    rowDefs.forEach(function (def) {
      if (def.pills.length === 0) return;
      var row = document.createElement('div');
      row.className = 'logstrip-ecosystem-marquee__row' + (def.reverse ? ' logstrip-ecosystem-marquee__row--reverse' : '');
      row.setAttribute('aria-hidden', 'true');

      var track = document.createElement('div');
      track.className = 'logstrip-ecosystem-marquee__track';
      track.style.animationDuration = def.speed + 's';

      // Duplicate pills twice for seamless loop
      for (var dup = 0; dup < 2; dup++) {
        def.pills.forEach(function (pill) {
          track.appendChild(pill.cloneNode(true));
        });
      }

      row.appendChild(track);
      rowsTarget.appendChild(row);
    });

    // Remove pool from DOM after building rows
    pool.remove();
  }

  function bootstrap() {
    setupSourceMarquee();
    setupCompareDemo();
  }

  if (
    typeof window.document$ !== 'undefined' &&
    typeof window.document$.subscribe === 'function'
  ) {
    window.document$.subscribe(bootstrap);
  }

  ready(bootstrap);
})();
