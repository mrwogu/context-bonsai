---
title: Log Compression CLI for AI Agents
description: Free, zero-dependency CLI that compresses noisy logs into high-signal AI context. 705+ detected ecosystems, stream-safe, deterministic output. Install with npm.
---

<section class="logstrip-hero" markdown="1">
<div class="logstrip-hero__inner" markdown="1">
<div class="logstrip-hero__copy" markdown="1">
<p class="logstrip-kicker">cli compression for agentic pipelines</p>

# smaller logs. cleaner agents.
<span class="logstrip-sr-only">LogStrip - log compression CLI for AI agents.</span>

<p class="logstrip-lede">A zero-dependency CLI that turns chaotic server logs, build pipelines, scanner reports, and container workloads into compact, high-signal context that AI agents can actually reason about - secrets masked, JSON kept valid, output trimmed to your token budget.</p>

<div class="logstrip-actions">
  <a class="logstrip-button" href="getting-started/">install the cli</a>
  <a class="logstrip-button logstrip-button--ghost" href="guides/plugins/">agent plugins</a>
</div>
</div>

<div class="logstrip-demo logstrip-demo--toggle" data-logstrip-compare aria-label="Interactive raw-to-LogStrip terminal comparison">
  <div class="logstrip-demo__bar">
    <span class="logstrip-demo__dot"></span>
    <span class="logstrip-demo__dot"></span>
    <span class="logstrip-demo__dot"></span>
    <span class="logstrip-demo__title">raw.log → logstrip.log</span>
  </div>
  <div class="logstrip-demo__fallback">
    <pre>[INFO] boot ok
[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed
[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed</pre>
    <pre>[x2] [ERROR] request [ID] failed</pre>
  </div>
</div>
</div>
</section>

<div class="logstrip-ecosystem-marquee" data-logstrip-reveal markdown="1">
<span class="logstrip-kicker">705+ detected ecosystems</span>

## your stack, covered

<div class="logstrip-ecosystem-marquee__pool" markdown="1">
<span class="logstrip-tool-pill">:simple-trivy: Trivy</span>
<span class="logstrip-tool-pill">:simple-snyk: Snyk</span>
<span class="logstrip-tool-pill">:material-shield-search: Semgrep</span>
<span class="logstrip-tool-pill">:simple-nginx: nginx</span>
<span class="logstrip-tool-pill">:simple-postgresql: PostgreSQL</span>
<span class="logstrip-tool-pill">:simple-redis: Redis</span>
<span class="logstrip-tool-pill">:fontawesome-brands-aws: AWS Lambda</span>
<span class="logstrip-tool-pill">:simple-datadog: Datadog</span>
<span class="logstrip-tool-pill">:simple-sentry: Sentry</span>
<span class="logstrip-tool-pill">:fontawesome-brands-docker: Docker</span>
<span class="logstrip-tool-pill">:simple-kubernetes: Kubernetes</span>
<span class="logstrip-tool-pill">:simple-terraform: Terraform</span>
<span class="logstrip-tool-pill">:simple-apachekafka: Kafka</span>
<span class="logstrip-tool-pill">:simple-elasticsearch: Elasticsearch</span>
<span class="logstrip-tool-pill">:simple-opentelemetry: OpenTelemetry</span>
<span class="logstrip-tool-pill">:simple-prometheus: Prometheus</span>
<span class="logstrip-tool-pill">:simple-grafana: Grafana</span>
<span class="logstrip-tool-pill">:simple-githubactions: GitHub Actions</span>
<span class="logstrip-tool-pill">:fontawesome-brands-gitlab: GitLab CI</span>
<span class="logstrip-tool-pill">:simple-cloudflare: Cloudflare</span>
<span class="logstrip-tool-pill">:simple-springboot: Spring Boot</span>
<span class="logstrip-tool-pill">:simple-django: Django</span>
<span class="logstrip-tool-pill">:simple-express: Express</span>
<span class="logstrip-tool-pill">:simple-nextdotjs: Next.js</span>
<span class="logstrip-tool-pill">:fontawesome-brands-jenkins: Jenkins</span>
<span class="logstrip-tool-pill">:simple-helm: Helm</span>
<span class="logstrip-tool-pill">:simple-mongodb: MongoDB</span>
<span class="logstrip-tool-pill">:simple-vitest: Vitest</span>
<span class="logstrip-tool-pill">:simple-jest: Jest</span>
<span class="logstrip-tool-pill">:simple-pytest: Pytest</span>
<span class="logstrip-tool-pill">:material-test-tube: Playwright</span>
<span class="logstrip-tool-pill">:fontawesome-brands-npm: npm</span>
<span class="logstrip-tool-pill">:fontawesome-brands-rust: Cargo</span>
<span class="logstrip-tool-pill">:simple-gradle: Gradle</span>
<span class="logstrip-tool-pill">:simple-webpack: Webpack</span>
<span class="logstrip-tool-pill">:simple-fastify: Fastify</span>
<span class="logstrip-tool-pill">:simple-nestjs: NestJS</span>
<span class="logstrip-tool-pill">:simple-react: React Native</span>
<span class="logstrip-tool-pill">:simple-flutter: Flutter</span>
<span class="logstrip-tool-pill">:simple-vercel: Vercel</span>
<span class="logstrip-tool-pill">:simple-argo: Argo</span>
<span class="logstrip-tool-pill">:fontawesome-brands-golang: Go test</span>
<span class="logstrip-tool-pill">:simple-pnpm: pnpm</span>
<span class="logstrip-tool-pill">:simple-cypress: Cypress</span>
<span class="logstrip-tool-pill">:simple-bun: Bun</span>
<span class="logstrip-tool-pill">:simple-apachemaven: Maven</span>
<span class="logstrip-tool-pill">:simple-electron: Electron</span>
<span class="logstrip-tool-pill">:simple-bazel: Bazel</span>
<span class="logstrip-tool-pill">:simple-tekton: Tekton</span>
<span class="logstrip-tool-pill">:fontawesome-brands-yarn: yarn</span>
</div>

<div class="logstrip-ecosystem-marquee__rows" data-logstrip-marquee-rows></div>

<p class="logstrip-sources-banner__more"><a href="reference/sources/">view all 705+ sources →</a> · <a href="reference/cli/#custom-configuration-logstripyml">add your own</a></p>
</div>

<div class="logstrip-grid" markdown="1">
<div class="logstrip-card" data-logstrip-reveal data-delay="1" markdown="1">
<span class="logstrip-metric">npm i -g logstrip</span>

### one install away

Installs one CLI: `logstrip`. Zero runtime dependencies on the hot path.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="2" markdown="1">
<span class="logstrip-metric">stream</span>

### gigabyte-safe

Built on Node streams and `readline`, so multi-gigabyte logs never have to fit in memory.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="3" markdown="1">
<span class="logstrip-metric">100/100</span>

### coverage gate

Statement, branch, function, and line coverage are pinned to 100% across the parser, CLI, and Action.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="4" markdown="1">
<span class="logstrip-metric">unix</span>

### pipe-native

`cat raw.log | logstrip > clean.log`. Stats on stderr, JSON on stdout (with `--output`), exit codes 0/1/2.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="5" markdown="1">
<span class="logstrip-metric">--max-tokens</span>

### fits any context window

Budget mode keeps the highest-scoring lines under a hard token cap, so output always fits the context you have left.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="6" markdown="1">
<span class="logstrip-metric">[REDACTED]</span>

### safe to paste

Stripe, AWS, GitHub, JWT and PEM credentials are masked - with a Shannon-entropy fallback for tokens no vendor pattern knows.
</div>
</div>

<section class="logstrip-engine" data-logstrip-reveal markdown="1">
<p class="logstrip-kicker">hybrid context engine</p>

## advanced detection, not regex-only filtering

LogStrip scores each sanitized line, keeps nearby context, dampens repeated spam, folds near-identical diagnostics with volatile values, prunes downstream cascades, and hides internal framework frames: compact incident narrative, not a noisy transcript. In the default `auto` mode every booster below runs automatically - no flags required.

<div class="logstrip-engine__grid" markdown="1">
<div class="logstrip-engine__step" markdown="1"><span>01</span>**Score signals** from log level, JSON severity, container failures, scanner findings, package managers, diagnostic keywords (including non-English and CJK terms), and stack frames.</div>
<div class="logstrip-engine__step" markdown="1"><span>02</span>**Promote context** with a before/after window so setup lines near the failure survive even when they are not errors themselves - sized adaptively by error density in `auto` mode (wider for isolated errors, tighter for clustered ones).</div>
<div class="logstrip-engine__step" markdown="1"><span>03</span>**Dampen repeats** with TF-IDF-style frequency tracking, then fold adjacent diagnostic variants - and repeated multi-line stack windows - into `[xN]` summaries.</div>
<div class="logstrip-engine__step" markdown="1"><span>04</span>**Summarize deltas** by listing only differing `key=value` values when repeated events share the same shape, including enumerated instance counters like `worker [1 | 2 | 3]`.</div>
<div class="logstrip-engine__step" markdown="1"><span>05</span>**Prune cascades** by dropping downstream restatements (`aborting due to previous errors`, `skipped because the upstream job failed`) so the originating failure stands out.</div>
<div class="logstrip-engine__step" markdown="1"><span>06</span>**Collapse internals** by replacing low-value framework/runtime stack frames with one marker while preserving app frames.</div>
<div class="logstrip-engine__step" markdown="1"><span>07</span>**Detect sources and format** across 700+ ecosystems with a single-pass Aho-Corasick automaton, majority-vote the dominant format over the first 50 lines, and re-elect it when the stream drifts mid-log so agents always know what they are reading.</div>
<div class="logstrip-engine__step" markdown="1"><span>08</span>**Mask secrets** with vendor patterns (Stripe, AWS, GitHub, npm, JWT, PEM blocks) plus a Shannon-entropy fallback, so unknown credentials still leave as `[REDACTED]` before the log ever reaches an LLM.</div>
<div class="logstrip-engine__step" markdown="1"><span>09</span>**Compress JSON reports** by detecting structured documents (test reports, scanner exports) and re-shaping them semantically - repeated entries grouped, duplicate fields referenced, empty fields pruned - while the output stays valid JSON.</div>
<div class="logstrip-engine__step" markdown="1"><span>10</span>**Fit the token budget** with `--max-tokens N`: output is trimmed to the highest-scoring lines, so even a multi-gigabyte incident log fits whatever context window is left.</div>
</div>
</section>

## why LogStrip exists

DevOps, SysOps, and GitOps teams often paste entire raw logs into AI agents during incident response. LLMs are bad at high-noise dumps. <span class="logstrip-accent-shift">LogStrip eases that pain and reduces token costs.</span>

<div class="logstrip-grid" markdown="1">
<div class="logstrip-card" data-logstrip-reveal data-delay="1" markdown="1">
<span class="logstrip-metric">problem</span>

### too much noise

Raw logs mix signal with thousands of low-value lines and repeated frames.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="2" markdown="1">
<span class="logstrip-metric">impact</span>

### weaker ai answers

Large noisy prompts dilute root-cause context and inflate LLM spend.
</div>

<div class="logstrip-card" data-logstrip-reveal data-delay="3" markdown="1">
<span class="logstrip-metric">outcome</span>

### compact signal

LogStrip produces deterministic, AI-ready logs that are cheaper to analyze.
</div>
</div>


### why teams keep it in every pipeline

<div class="logstrip-grid" markdown="1">
<div class="logstrip-card" data-logstrip-reveal data-delay="1" markdown="1"><span class="logstrip-metric">ops-first</span>Built for incident workflows where raw logs hit AI assistants under pressure.</div>
<div class="logstrip-card" data-logstrip-reveal data-delay="2" markdown="1"><span class="logstrip-metric">700+</span>Automatic source awareness across CI, runtimes, scanners, infra, and cloud logs.</div>
<div class="logstrip-card" data-logstrip-reveal data-delay="3" markdown="1"><span class="logstrip-metric">deterministic</span>Snapshot-tested output, fixtures spanning CI, runtimes, scanners and crashes, locked behind a **100/100/100/100** coverage gate.</div>
<div class="logstrip-card" data-logstrip-reveal data-delay="4" markdown="1"><span class="logstrip-metric">cheaper prompts</span>Lower token usage per incident while keeping root-cause context intact.</div>
</div>

<div class="logstrip-agents-strip" data-logstrip-reveal>
  <span class="logstrip-agents-strip__label">plugins that auto-intercept raw log pastes in every listed agent</span>
  <div class="logstrip-agents-strip__logos">
    <a class="logstrip-agent-logo" title="Claude Code" href="guides/plugins/#claude-code"><img src="assets/images/logo-claude-code.svg" alt="Claude Code"></a>
    <a class="logstrip-agent-logo" title="Droid" href="guides/plugins/#factory-droid"><img src="assets/images/logo-droid.png" alt="Droid"></a>
    <a class="logstrip-agent-logo" title="Copilot" href="guides/plugins/#github-copilot"><img src="assets/images/logo-copilot.svg" alt="Copilot"></a>
    <a class="logstrip-agent-logo" title="Cursor" href="guides/plugins/#cursor"><img src="assets/images/logo-cursor.svg" alt="Cursor"></a>
    <a class="logstrip-agent-logo" title="Codex" href="guides/plugins/#codex"><img src="assets/images/logo-codex.png" alt="Codex"></a>
    <a class="logstrip-agent-logo" title="OpenCode" href="guides/plugins/#opencode"><img src="assets/images/logo-opencode.png" alt="OpenCode"></a>
  </div>
  <a class="logstrip-button" href="guides/plugins/">install for your agent</a>
</div>

## cli in one line

```bash
npx -y logstrip raw.log -o clean.log --stats
```

Writes the compressed log to `clean.log` and a stats block to `stderr`.
Stdin/stdout, file I/O, JSON reports and a GitHub Action wrapper are all
covered in [Getting Started](getting-started.md).

## next steps

- [Getting Started](getting-started.md) - install, pipe, script
- [CLI Reference](reference/cli.md) - every flag and exit code
- [Core TypeScript API](reference/core.md) - embed the parser
- [GitHub Action](reference/action.md) - optional workflow wrapper
- [Plugin Installation](guides/plugins.md) - Claude, Copilot, Cursor, Codex, Droid, OpenCode
- [Workflow Examples](examples/index.md) - real CI recipes
