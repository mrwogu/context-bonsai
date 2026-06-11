# Changelog

## [1.11.0](https://github.com/mrwogu/logstrip/compare/v1.10.0...v1.11.0) (2026-06-11)


### Features

* **cli:** add --max-stack-frames and --no-template-mining ([ac733dd](https://github.com/mrwogu/logstrip/commit/ac733dda2ee0d56c28bdf3f81ea9e49d8283ff37))
* **dedupe:** template mining for near-identical lines ([40678ac](https://github.com/mrwogu/logstrip/commit/40678ac6438d9260c0823c59255b4d2a0e4fe2e3))
* **formats:** re-elect detected format on mid-stream drift ([f6f900a](https://github.com/mrwogu/logstrip/commit/f6f900af07e347d96aaf8ce0462830c8ec43281d))
* **parser:** truncate long app stacks, wire new pipeline options ([2f9c569](https://github.com/mrwogu/logstrip/commit/2f9c569e1f539c8a0340084ab58f74b21c06900c))
* **sanitize:** mask high-entropy tokens as secret fallback ([658bf98](https://github.com/mrwogu/logstrip/commit/658bf98da71da1a81c0322454962e4ace3e1a108))
* **scoring:** compound exceptions, polyglot frames, rarity boost ([b3b896c](https://github.com/mrwogu/logstrip/commit/b3b896cb75f9c73a1fc52862fcf0db227f01bff9))


### Performance Improvements

* **dedupe:** conservative update in Count-Min Sketch ([34f4249](https://github.com/mrwogu/logstrip/commit/34f424931b762f23751d8f5c1247f00beee1bb88))

## [1.10.0](https://github.com/mrwogu/logstrip/compare/v1.9.0...v1.10.0) (2026-06-08)


### Features

* **cli:** block raw log pastes in UserPromptSubmit hook ([b3c1f33](https://github.com/mrwogu/logstrip/commit/b3c1f33e02d1fba69f60690f72fd93435333b180))


### Bug Fixes

* **hook:** support every targeted agent dialect ([a4c3297](https://github.com/mrwogu/logstrip/commit/a4c3297ec9dff517fc6d0b60436e7c9646d0c3a6))

## [1.9.0](https://github.com/mrwogu/logstrip/compare/v1.8.0...v1.9.0) (2026-05-30)


### Features

* adaptive context window in auto mode ([922b29e](https://github.com/mrwogu/logstrip/commit/922b29e3b34f9238d79c786c9dbfc5e079b4af00))
* **cli:** add --max-tokens budget mode for LLM context limits ([5b21bcd](https://github.com/mrwogu/logstrip/commit/5b21bcd65b6039b7ce5781537d88a6a6ada86848))
* **cli:** notify when a newer logstrip release is on npm ([aa7f9c9](https://github.com/mrwogu/logstrip/commit/aa7f9c926f34a6a2c645a1c0c755f3af0f8bc161))
* comprehensive sanitize, scoring, multiline, and perf enhancements ([3e41bba](https://github.com/mrwogu/logstrip/commit/3e41bba4431aa6752649bac6a3810397aecb25bc))
* **core:** enable detection/compression boosters by default in auto mode ([71dae82](https://github.com/mrwogu/logstrip/commit/71dae82d0d8cf875efd326edb55df9b5ff71beb8))
* **dedupe:** add --collapse-blocks for repeated multiline blocks ([21ed869](https://github.com/mrwogu/logstrip/commit/21ed8690fca045b80bbdb20e0e3e27b13a1758d1))
* **dedupe:** add --dedupe-window for non-adjacent duplicate collapsing ([d6a8ae2](https://github.com/mrwogu/logstrip/commit/d6a8ae292d4aabb8ff9bad0bd0f9c92731191c73))
* **dedupe:** collapse repeated stack-trace windows via --collapse-stacks ([b1e66eb](https://github.com/mrwogu/logstrip/commit/b1e66eb6d99e73fb9ba87da908102c96b0ea8ef9))
* **dedupe:** fold enumerated instance counters into the repeat signature ([a6e5934](https://github.com/mrwogu/logstrip/commit/a6e5934aadd07c93c65eacc70b836a8f18183b21))
* **formats:** add --format-sample majority-vote format detection ([d97ae13](https://github.com/mrwogu/logstrip/commit/d97ae133615090d75dadd15ba420c740aa168898))
* **scoring:** add --multilingual diagnostic keyword detection ([c852425](https://github.com/mrwogu/logstrip/commit/c852425bad5750c8b2e7a6f22d8b5651c6ca7e70))
* **scoring:** add --root-cause cascade pruning ([1eef9d0](https://github.com/mrwogu/logstrip/commit/1eef9d0f46e5fb68420d8dceedd49d570248f652))


### Performance Improvements

* **detection:** match source markers with an Aho-Corasick automaton ([bc744f8](https://github.com/mrwogu/logstrip/commit/bc744f8febb89f9045dede2d0f6a7484e54588f7))

## [1.8.0](https://github.com/mrwogu/logstrip/compare/v1.7.0...v1.8.0) (2026-05-28)


### Features

* **cli:** --preserve-id-suffix=N keeps last N chars of UUIDs and hashes for trace correlation ([f3a05cb](https://github.com/mrwogu/logstrip/commit/f3a05cbe454a511e7013206576a07dd7ffe40772))
* **dedupe:** collapse repeated stack-trace windows by error fingerprint ([896b957](https://github.com/mrwogu/logstrip/commit/896b95774a76bc87ff72cefc3b5954417086aa01))
* **detection:** lower source-active confidence threshold for short logs (&lt;200 lines) ([9302b90](https://github.com/mrwogu/logstrip/commit/9302b90101a8b1eb09e4260d2f76056d83cfb68b))
* **parser:** auto-multiline mode infers from detected sources ([91d2340](https://github.com/mrwogu/logstrip/commit/91d23405ca1c67aaf46e5332f179c0a007f065d9))
* **parser:** collapse 2xx access-log bursts in context window ([5a74d17](https://github.com/mrwogu/logstrip/commit/5a74d1774d8f664d9cd940e63e46d75481b8fe50))
* **parser:** structured JSON-line scoring uses level field for pino/winston/bunyan logs ([9f12825](https://github.com/mrwogu/logstrip/commit/9f12825c5c47f02e705fa2fff6f4a66e63880aa3))
* **parser:** track timestamp spread within repeat groups ([0940633](https://github.com/mrwogu/logstrip/commit/09406337e25c70a4acb9680072f708e5e78a6704))
* **sanitize:** normalize Kubernetes-style relative durations (2m34s) to [AGO] ([572f52c](https://github.com/mrwogu/logstrip/commit/572f52c0d0de1e91c107c1436e694a3961304c3c))
* **sanitize:** redact IPv6, emails, Stripe/npm/Google/Twilio/SendGrid tokens and PEM private key blocks ([6d03fea](https://github.com/mrwogu/logstrip/commit/6d03fea65db7c6dea8df3ca7e38a3427a1d62549))


### Performance Improvements

* **tfidf:** switch frequency map to Count-Min Sketch for memory-stable counting ([676de5b](https://github.com/mrwogu/logstrip/commit/676de5b0cc532b7d8d4f1438e3e35e772be275f1))

## [1.7.0](https://github.com/mrwogu/logstrip/compare/v1.6.1...v1.7.0) (2026-05-28)


### Features

* add format-aware access log compression and extend diagnostic boost patterns ([866f27f](https://github.com/mrwogu/logstrip/commit/866f27fa877f3014436bb923e12c3a43eaa7e494))
* format-aware access log compression + expanded diagnostic boost patterns ([d4bb6a8](https://github.com/mrwogu/logstrip/commit/d4bb6a88232bd84901e30eed1aeaee7674525b71))

## [1.6.1](https://github.com/mrwogu/logstrip/compare/v1.6.0...v1.6.1) (2026-05-27)


### Bug Fixes

* restore hook loading and release workflow ([b968cbf](https://github.com/mrwogu/logstrip/commit/b968cbfa82e87936bd56a5e67414dda38e63a6bd))
* switch plugin hooks to logstrip hook subcommand ([d340252](https://github.com/mrwogu/logstrip/commit/d34025269a70a6945286e7d76323d2eea6f76022))

## [1.6.0](https://github.com/mrwogu/logstrip/compare/v1.5.0...v1.6.0) (2026-05-27)


### Features

* improve apache httpd log compression ([31fae8d](https://github.com/mrwogu/logstrip/commit/31fae8de5cbf63a394155e788662e4da671f7462))


### Bug Fixes

* harden hook loader path quoting ([a7d5336](https://github.com/mrwogu/logstrip/commit/a7d5336b5d764d0f6107c75f0d236fa181f052a1))
* harden hook loader path quoting ([9884e01](https://github.com/mrwogu/logstrip/commit/9884e0126e8fe7c10f310e71a0861e3e7b19a8b7))
* make plugin hooks work on Windows ([f8436b0](https://github.com/mrwogu/logstrip/commit/f8436b0af442a0e23669dd2331a14a693a9516ac))
* make plugin hooks work on Windows ([8bbe97a](https://github.com/mrwogu/logstrip/commit/8bbe97a59bbfd7ba9dccdd7a4c5483432c31fb13))

## [1.5.0](https://github.com/mrwogu/logstrip/compare/v1.4.0...v1.5.0) (2026-05-21)


### Features

* expand log processing APIs ([be5b673](https://github.com/mrwogu/logstrip/commit/be5b673fae89c598c5eab7c072c55832b1490fc3))

## [1.4.0](https://github.com/mrwogu/logstrip/compare/v1.3.0...v1.4.0) (2026-05-21)


### Features

* wire telemetry into CLI, add --telemetry flag, export from library, add docs ([4eabc64](https://github.com/mrwogu/logstrip/commit/4eabc64c0307c15e340eeff609c6249cd8c3418f))


### Bug Fixes

* add .js extension to dynamic import in cli test for node16 moduleResolution ([c01cd46](https://github.com/mrwogu/logstrip/commit/c01cd468af3168c8a8e7a0284ea01526c51378fa))
* use vi.hoisted for telemetry env var in CLI tests ([d09f482](https://github.com/mrwogu/logstrip/commit/d09f4827f26cc5d6c74094dcd56c139cda008e70))


### Documentation

* remove fictitious dual-binary alias, document single logstrip CLI entry point ([8f75068](https://github.com/mrwogu/logstrip/commit/8f75068292ac5cb9b38e9e4b4c2dc7bc0bca6a5a))
* replace all em/en dashes with hyphens across docs, plugins, fixtures, and tests ([cc2178b](https://github.com/mrwogu/logstrip/commit/cc2178bdedc9c7ad38f34e0b1f4aef2a7c9aab9f))
* update CLI, core API, and README for v1.3.0 features ([569f21b](https://github.com/mrwogu/logstrip/commit/569f21b2c6df2d3cc8e1c0c9c6b2e9d2f06e7eb4))

## [1.3.0](https://github.com/mrwogu/logstrip/compare/v1.2.0...v1.3.0) (2026-05-21)


### Features

* add CI noise filters for progress bars, timestamp-only, K8s Normal, rate-limited ([16dc859](https://github.com/mrwogu/logstrip/commit/16dc8592ae06b536720b84f4c77d9aced9ad04ba))
* add CLI flags --include, --exclude, --sample, --max-line-length, --timeout, --progress ([5d24036](https://github.com/mrwogu/logstrip/commit/5d2403663eeeff17b3f4169b33e276e54ea6f46f))
* add Copilot marketplace plugin and fix agent descriptions in README ([7a85535](https://github.com/mrwogu/logstrip/commit/7a85535c50524768e3254efedb40ce04655f351c))
* add enhanced secret masking for GitHub, JWT, Slack, connection strings ([754af87](https://github.com/mrwogu/logstrip/commit/754af8731a2a2bc0bfc18eee6b074c544c371d54))
* add local telemetry tracking for cumulative token savings ([7d658ba](https://github.com/mrwogu/logstrip/commit/7d658ba4b3aa6cda7a21c8bc7bfea2a6fe69f88c))
* add log format detection and HTTP status code grouping ([d26b7e6](https://github.com/mrwogu/logstrip/commit/d26b7e638baf8778860d8901ccaba7b14f371e5d))
* add multiline log handling (-m flag) ([078922f](https://github.com/mrwogu/logstrip/commit/078922f6e7dc3904595077d5fc72fc2b07b7da79))
* add severity filtering (--severity flag) ([f1da1ad](https://github.com/mrwogu/logstrip/commit/f1da1adf14ecebfcb350db0a90ee49084d005ee2))


### Bug Fixes

* correct secret masking test inputs and regex patterns for CI ([d0b71a5](https://github.com/mrwogu/logstrip/commit/d0b71a57aedc8c43d729aea4f37c3f78e5760d08))
* harden regexes against ReDoS with bounded quantifiers and unicode flags ([e0d3fdc](https://github.com/mrwogu/logstrip/commit/e0d3fdc58db9a4bd6f5d32a62bac855b8732d555))

## [1.2.0](https://github.com/mrwogu/logstrip/compare/v1.1.0...v1.2.0) (2026-05-20)


### Features

* add 'auto' aggressiveness to CLI and action, update tests and snapshots ([0ce8265](https://github.com/mrwogu/logstrip/commit/0ce8265309cb463bc00ae8e2abb6810a0a775335))
* change default aggressiveness from 'high' to 'auto' across all surfaces ([08654f4](https://github.com/mrwogu/logstrip/commit/08654f481dc88e980533de64a028a55ba781dc67))

## [1.1.0](https://github.com/mrwogu/logstrip/compare/v1.0.0...v1.1.0) (2026-05-19)


### Features

* add PreToolUse/UserPromptSubmit hooks for auto-activating LogStrip on log content ([16b8c7c](https://github.com/mrwogu/logstrip/commit/16b8c7c5d1b22affbe8b32dee87d90b4996d309a))

## 1.0.0 (2026-05-19)

Initial release: streaming log compressor CLI, TypeScript library, and GitHub Action.

### Features

* Streaming log parser with line scoring, deduplication, sanitization, and internal stack collapsing
* CLI (`logstrip`) with stdin/stdout pipe support, `--aggressiveness`, `--stats`, `--json` flags
* GitHub Action wrapper (`mrwogu/logstrip@v1`) with `log-path` and `aggressiveness` inputs
* Custom config engine (`.logstrip.yml`) for extending built-in log sources and patterns
* MkDocs documentation site with CLI reference, guides, and contributing guide
* Brand assets, agent logos, and stat badges
