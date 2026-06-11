"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DIAGNOSTIC_BOOSTERS = void 0;
exports.buildSourceBoosterPatterns = buildSourceBoosterPatterns;
/**
 * Consolidated diagnostic booster table.
 *
 * Boosters without a `source` field apply globally in `scoreLineRelevance`.
 * Those with a `source` field are used by `source-profile.ts` for per-source
 * diagnostic boosts that only fire when the source is confidently detected.
 */
exports.DIAGNOSTIC_BOOSTERS = [
    // ── Severity tags ────────────────────────────────────────────────
    { pattern: /\[(?:ERROR|WARN|FATAL|CRITICAL|FAIL)\]/iu, score: 100, label: 'severity-tag' },
    // ── JSON severity ────────────────────────────────────────────────
    { pattern: /"(?:level|severity)"\s*:\s*"(?:fatal|error|critical|warn|warning)"/iu, score: 80, label: 'json-severity' },
    // ── Security / scanners ──────────────────────────────────────────
    { pattern: /\b(?:CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|vulnerabilit(?:y|ies)|severity:\s*(?:critical|high|medium)|(?:critical|high)\s+severity)\b/iu, score: 70, label: 'scanner-finding' },
    // ── Container failures ───────────────────────────────────────────
    { pattern: /\b(?:CrashLoopBackOff|ImagePullBackOff|ErrImagePull|OOMKilled|Back[- ]off restarting failed container|failed to pull image|(?:containerd|runc).*?(?:failed|error|panic|timeout|refused)|(?:failed|error|panic|timeout|refused).*?(?:containerd|runc)|rpc error: code = Unknown desc = failed to resolve reference)\b/iu, score: 70, label: 'container-failure' },
    // ── GitHub Actions annotations ───────────────────────────────────
    { pattern: /^::(?:error|warning|notice)\b/u, score: 70, label: 'github-actions' },
    // ── Gradle failures ──────────────────────────────────────────────
    { pattern: /\b(?:Execution failed|What went wrong|BUILD FAILED|Task failed with an exception)\b/iu, score: 60, label: 'gradle-failure' },
    // ── npm / pnpm errors ────────────────────────────────────────────
    { pattern: /\b(?:npm|pnpm)\s+ERR!/iu, score: 60, label: 'npm-error' },
    // ── yarn errors ──────────────────────────────────────────────────
    { pattern: /\byarn\s+error\b/iu, score: 60, label: 'yarn-error' },
    // ── Generic diagnostic keywords ──────────────────────────────────
    { pattern: /\b(?:Error|Exception|AssertionError|TypeError|ReferenceError|SyntaxError|RangeError|NullPointerException|Unhandled|failed|failure|fatal|panic|refused|timeout|timed\s+out|unreachable|unavailable|disconnected|killed|aborted|crashed|terminated|unauthorized)\b/iu, score: 50, label: 'diagnostic' },
    // ── Compound exception class names (FooBarException, AcmeError) ──
    { pattern: /\b[A-Z]\w+(?:Exception|Error|Fault)\b/u, score: 50, label: 'compound-exception' },
    // ── Rust panics ──────────────────────────────────────────────────
    { pattern: /^thread '[^']*' panicked at\b/u, score: 60, label: 'rust-panic' },
    // ── Go test failures ─────────────────────────────────────────────
    { pattern: /---\s*FAIL:/u, score: 50, label: 'go-test-fail' },
    // ── Make errors ──────────────────────────────────────────────────
    { pattern: /^make[:\s*]+/u, score: 50, label: 'make-error' },
    // ── Systemd status failures ──────────────────────────────────────
    { pattern: /\b(?:Failed to start|Failed to load|Failed to listen|Failed to mount|Failed to open|Failed to connect|status=\d+\s+\w+)\b/iu, score: 50, label: 'systemd-status' },
    // ── CircleCI step failures ───────────────────────────────────────
    { pattern: /\b(?:Spin Cancelled|Step failed|job was not approved)\b/u, score: 50, label: 'circleci-step' },
    // ── Jenkins markers ──────────────────────────────────────────────
    { pattern: /\[(?:Pipeline|Checks|FCMaker)\]/u, score: 40, label: 'jenkins-marker' },
    // ── Azure Pipelines markers ──────────────────────────────────────
    { pattern: /^##vso\[task\.(?:LogIssue|Complete)\b/u, score: 40, label: 'azure-pipeline' },
    // ── TeamCity markers ─────────────────────────────────────────────
    { pattern: /^##teamcity\[(?:buildProblem|compilationFinished|message)\b/u, score: 40, label: 'teamcity-marker' },
    // ── HTTP 5xx / 4xx in access-logs ────────────────────────────────
    { pattern: /\bHTTP\/\d\.\d"\s+5\d{2}\b/u, score: 50, label: 'http-5xx' },
    { pattern: /\bHTTP\/\d\.\d"\s+4\d{2}\b/u, score: 20, label: 'http-4xx' },
    // ── Stack frame patterns ─────────────────────────────────────────
    { pattern: /^\s*at\s+.*(?:\(|\s).+:(?:\d+|\[NN\]):(?:\d+|\[NN\])\)?$/, score: 40, label: 'js-stack-frame' },
    { pattern: /^\s*at\s+[\w$_.<>/]+\([^)]+:(?:\d+|\[NN\])\)$/, score: 40, label: 'java-stack-frame' },
    { pattern: /^\s*File\s+"[^"]+",\s+line\s+(?:\d+|\[NN\]),\s+in\s+.+$/, score: 40, label: 'python-stack-frame' },
    { pattern: /^\s*(?:(?:[\w.-]+\/)+[\w./-]+|[\w.-]+\.\(\*?[\w.]+\)\.[\w.]+|[\w.-]+\.[A-Z]\w*)\(.*\)$/, score: 40, label: 'go-stack-frame' },
    { pattern: /^\s*(?:\/[^\s]+|[A-Za-z]:[\\/][^\s]+):(?:\d+|\[NN\])(?:\s+\+\S+)?$/, score: 40, label: 'go-file-frame' },
    { pattern: /^\s*goroutine\s+\d+\s+\[.+\]:$/iu, score: 40, label: 'go-goroutine' },
    { pattern: /^Traceback \(most recent call last\):$/, score: 40, label: 'python-traceback' },
    { pattern: /^\s*from\s+\S+:\d+:in\s+[`'].+$/u, score: 40, label: 'ruby-stack-frame' },
    { pattern: /^\s*\d+:\s+(?:0x[0-9a-f]+\s+-\s+)?\S*(?:::|[<>])\S*$/u, score: 40, label: 'rust-backtrace-frame' },
    { pattern: /^\s*at\s+\S+\.rs:\d+:\d+:?$/u, score: 40, label: 'rust-file-frame' },
    { pattern: /^\s*at\s+[\w.<>`+\[\],$]+\([^)]*\)(?:\s+in\s+\S+:line\s+\d+)?$/u, score: 40, label: 'csharp-stack-frame' },
    { pattern: /^\s*#\d+\s+(?:\{main\}|\S+\(\d+\):\s+\S+.*)$/u, score: 40, label: 'php-stack-frame' },
    { pattern: /^\s*\.\.\. \d+ more$/, score: 40, label: 'stack-more' },
];
/**
 * Extract just the patterns keyed by source name, for use in
 * `source-profile.ts` (each source has its own diagnostic boost patterns).
 */
function buildSourceBoosterPatterns() {
    const map = new Map();
    // Source-specific boosters from the original SOURCE_DIAGNOSTIC_BOOST_PATTERNS map.
    // These are only used in source-profile.ts — they are NOT part of the global
    // scoring table because they're gated by source detection confidence.
    const sourceBoosters = {
        // ── Original 6 ──────────────────────────────────────────────────
        typescript: [/\bTS\d{4}\b/u],
        pytest: [/^E\s+/u, /\bFAILED\b/u],
        nginx: [/\[(?:error|crit|alert|emerg)\]/iu],
        'apache-httpd': [
            /\[(?:error|crit|alert|emerg)\]/iu,
            /\bAH\d{5}\b/u,
            /\b(?:Directory index forbidden|client denied|mod_jk)\b/iu,
        ],
        kubernetes: [/\b(?:BackOff|Failed|ErrImagePull|CrashLoopBackOff)\b/u],
        'github-actions': [/^::(?:error|warning)\b/u],
        // ── Build Tools ──────────────────────────────────────────────────
        gradle: [/\b(?:Execution failed|What went wrong|BUILD FAILED)\b/iu],
        maven: [/\b(?:BUILD FAILURE|Failed to execute goal|Compilation failure)\b/iu],
        bazel: [/\b(?:BUILD FAILED|build did not complete successfully)\b/iu],
        webpack: [/\b(?:Module not found|Can't resolve|Module build failed|BUILD FAILED)\b/iu],
        vite: [/\b(?:Build failed|Transform failed|Internal server error)\b/iu],
        esbuild: [/\b(?:Build failed|error:\s|ERROR:)\b/u],
        rollup: [/\b(?:!\s|Circular dependency|Could not resolve)\b/u],
        cargo: [/\b(?:error\[E\d{4}\]|error: could not compile|could not compile `)/u],
        rustc: [/\berror\[E\d{4}\]\b/u],
        cmake: [/\b(?:CMake Error|CMakeFiles|cmake failed)\b/iu],
        msbuild: [/\b(?:error MSB\d{4}|Build FAILED)\b/iu],
        make: [/\b(?:make: \*\*\*|make\[|Error \d+\])\b/u],
        'go-build': [/\b(?:go: |build failed|cannot find package)\b/iu],
        // ── Package Managers ─────────────────────────────────────────────
        npm: [/\bnpm\s+ERR!/iu],
        pnpm: [/\bpnpm\s+ERR!/iu],
        yarn: [/\byarn\s+error\b/iu],
        pip: [/\b(?:ERROR: Could not find a version|ERROR: No matching distribution)\b/u],
        bundler: [/\b(?:Could not find gem|Bundler::|Gem::ConflictError)\b/u],
        composer: [/\b(?:Composer\\|Installation failed|Root package)\b/u],
        // ── Test Runners ──────────────────────────────────────────────────
        jest: [/\b(?:●\s|Tests:\s+\d+\s+failed|AssertionError:)\b/u],
        vitest: [/\b(?:FAIL\s+|AssertionError:|Test Files\s+\d+\s+failed)\b/u],
        mocha: [/\b(?:AssertionError|Error:) \d+ (?:failing|passing)\b/u],
        'go-test': [/\b---\s*FAIL:/u],
        junit: [/\b(?:Tests run: \d+.*Failures: [1-9]|FAILED)\b/u],
        rspec: [/\b(?:Failures:|expected:|got:)\b/u],
        phpunit: [/\b(?:FAILURES!|Tests: \d+|Assertions: \d+)\b/u],
        // ── Container / Orchestration ────────────────────────────────────
        docker: [/\b(?:Error response from daemon|failed to build|failed to push|manifest.*not found)\b/iu],
        buildkit: [/\b(?:error:|failed to solve|canceled)\b/u],
        containerd: [/\b(?:failed to start container|OCI runtime|runc)\b/iu],
        helm: [/\b(?:Error: UPGRADE FAILED|Error: INSTALLATION FAILED|Error: uninstall|Error: release.*failed)\b/iu],
        // ── IaC ──────────────────────────────────────────────────────────
        terraform: [/\b(?:Error: |Error applying|Terraform.*failed)\b/iu],
        terragrunt: [/\b(?:Error: |Module.*error)\b/iu],
        ansible: [/\b(?:fatal: \[|FAILED!|UNREACHABLE!)\b/u],
        pulumi: [/\b(?:Pulumi\.error|error: update failed|Diagnostics:)\b/iu],
        'aws-cdk': [/\b(?:CdkSynthError|cdk deploy failed|ValidationError|No stack named)\b/iu],
        // ── Databases ────────────────────────────────────────────────────
        postgresql: [/\b(?:FATAL:|ERROR:|PG::|relation.*does not exist)\b/iu],
        mysql: [/\b(?:ERROR \d{4}|Can't connect|Access denied for user)\b/iu],
        redis: [/\b(?:DENIED|Connection refused|ERR |WRONGTYPE|READONLY)\b/u],
        mongodb: [/\b(?:MongoServerSelectionError|MongoNetworkError|not master|NotWritablePrimary)\b/iu],
        kafka: [/\b(?:Broker may not be available|Connection to node.*could not be established|UNKNOWN_TOPIC_OR_PARTITION)\b/iu],
        rabbitmq: [/\b(?:connection refused|broker unreachable|channel error|PRECONDITION_FAILED)\b/iu],
        cockroachdb: [/\b(?:SQLSTATE|restart transaction|RETRY_WRITE_TOO_OLD)\b/iu],
        // ── Web Frameworks (JS/TS) ──────────────────────────────────────
        express: [/\b(?:Error: Cannot find module|TypeError:.*Router|Error: EADDRINUSE|Error: listen EACCES)\b/u],
        fastify: [/\b(?:FST_ERR|fastify error|plugin initialization failed)\b/iu],
        nestjs: [/\b(?:NestError|Nest can't resolve dependencies|Circular dependency detected)\b/iu],
        nextjs: [/\b(?:Error: Cannot resolve dependency|Error: Build failed|Module not found|Error: > Build failed)\b/u],
        nuxt: [/\b(?:Nuxt Build Error|Cannot start nuxt|Fatal error)\b/iu],
        hono: [/\b(?:TypeError: Cannot read properties|HonoError)\b/u],
        // ── ORMs ──────────────────────────────────────────────────────────
        prisma: [/\b(?:P\d{4,5}|PrismaClientKnownRequestError|PrismaClientValidationError|PrismaClientInitializationError)\b/u],
        'drizzle-orm': [/\b(?:DrizzleKitError|drizzle.*error|MigrationError)\b/iu],
        typeorm: [/\b(?:QueryFailedError|EntityMetadataNotFound|ConnectionNotFoundError|DriverPackageNotInstalledError)\b/iu],
        sequelize: [/\b(?:SequelizeConnectionError|SequelizeDatabaseError|SequelizeValidationError)\b/iu],
        knex: [/\b(?:MigrationLockError|KnexTimeoutError|Knex:error)\b/iu],
        // ── Python Frameworks ───────────────────────────────────────────
        django: [/\b(?:django\.core\.exceptions|django\.db\.utils|OperationalError|ImproperlyConfigured)\b/iu],
        fastapi: [/\b(?:fastapi\.exceptions|HTTPException|ValidationError|RequestValidationError)\b/iu],
        flask: [/\b(?:werkzeug\.exceptions|flask\.abort|Internal Server Error)\b/iu],
        celery: [/\b(?:celery\.exceptions|Task.*raised unexpected|WorkerLostError)\b/iu],
        sqlalchemy: [/\b(?:sqlalchemy\.exc\.|OperationalError|IntegrityError|ProgrammingError)\b/iu],
        // ── Linters / Security Scanners ──────────────────────────────────
        eslint: [/\b\d+:\d+\s+error\s|\beslint.*error\b/ui],
        semgrep: [/\b(?:semgrep finding|severity:(?:ERROR|WARNING))\b/iu],
        gitleaks: [/\bsecret detected\b/iu],
        trivy: [/\b(?:CRITICAL|HIGH):\s|CVE-\d{4}-\d{4,7}\b/u],
        snyk: [/\b(?:High severity|Critical severity|introduced by)\b/iu],
        grype: [/\b(?:CRITICAL\s+CVE-|HIGH\s+CVE-|NAME\s+INSTALLED\s+FIXED-IN)\b/u],
        checkov: [/\b(?:CKV_|Checkov.*failed)\b/u],
        bandit: [/\b(?:Issue: \[B\d{3}|Test results:.*issues)\b/u],
        mypy: [/\b(?:mypy: error:|mypy: warning:|Incompatible types|has incompatible type)\b/u],
        ruff: [/\b(?:ruff\s+(?:check|format)|F\d{3,4}|E\d{3,4}|RUF\d{3})\b/u],
        pylint: [/\b(?:pylint\s+|E\d{4}:|W\d{4}:|C\d{4}:|R\d{4}:)\b/u],
        // ── CI/CD Platforms ─────────────────────────────────────────────
        circleci: [/\b(?:Spin Cancelled|Step failed|job was not approved)\b/u],
        jenkins: [/\b(?:\[Pipeline\]\s*\[ERROR\]|Stage .* failed|script returned exit code [1-9])\b/u],
        'gitlab-ci': [/\b(?:ERROR: Job failed|job failed|script returned exit code [1-9])\b/u],
        teamcity: [/\b##teamcity\[(?:buildProblem|compilationFinished)\b/u],
        'azure-pipelines': [/\b##vso\[task\.(?:LogIssue|Complete)\b/u],
        buildkite: [/\b(?:buildkite.*failed|command failed)\b/iu],
        // ── Cloud Providers ─────────────────────────────────────────────
        'aws-lambda': [/\b(?:Task timed out|ERROR Invoke Error|Runtime\.ExitError|Process exited before completing)\b/iu],
        'gcp-cloud-run': [/\b(?:Cloud Run.*failed|Revision.*failed|Container failed to start|Ready condition status)\b/iu],
        'azure-functions': [/\b(?:System\.TimeoutException|FunctionInvocationException|Host threshold exceeded)\b/iu],
        cloudformation: [/\b(?:ROLLBACK_COMPLETE|CREATE_FAILED|UPDATE_FAILED|DELETE_FAILED)\b/u],
        cloudwatch: [/\b(?:Alarm|INSUFFICIENT_DATA|State change)\b/u],
        'aws-ecs': [/\b(?:service.*failed|Task failed|unable to place a task)\b/iu],
        // ── Observability ────────────────────────────────────────────────
        datadog: [/\b(?:datadog ERROR|datadog CRITICAL|datadog WARN)\b/iu],
        sentry: [/\b(?:failed to send event|sentry\.captureException|Error exporting spans)\b/iu],
        prometheus: [/\b(?:target.*down|scrape.*failed|rule evaluation error|Alertmanager)\b/iu],
        grafana: [/\b(?:grafana.*alert|alerting evaluation error|Dashboard.*error|provisioning error)\b/iu],
        loki: [/\b(?:loki.*error|logql.*error|ingester.*failed)\b/iu],
        'newrelic': [/\b(?:NR-\d+|new relic.*error|NewRelic.*error)\b/iu],
        // ── Message Queues ───────────────────────────────────────────────
        'aws-sqs': [/\b(?:SQS.*error|QueueDoesNotExist|ReceiptHandleIsInvalid)\b/iu],
        'gcp-pubsub': [/\b(?:pubsub.*error|DeadlineExceeded|UNAVAILABLE)\b/iu],
        bullmq: [/\b(?:StalledJobError|job.*failed|BullMQ.*error|WaitingChildrenError)\b/iu],
        // ── AI / ML ──────────────────────────────────────────────────────
        'openai-api': [/\b(?:Rate limit exceeded|RateLimitError|context_length_exceeded|invalid_request_error|insufficient_quota)\b/iu],
        ollama: [/\b(?:model not found|Error: |CUDA error|Error: llama)\b/u],
        vllm: [/\b(?:CUDA out of memory|OOM|Error: Failed to load model|tensor parallel)\b/iu],
        langchain: [/\b(?:OutputParserError|LangChain.*error|Chain.*failed|Agent.*error)\b/iu],
        huggingface: [/\b(?:HubConnectionError|ModelNotFoundError|RepositoryNotFoundError|HFValidationError)\b/iu],
        // ── Auth / Identity ─────────────────────────────────────────────
        keycloak: [/\b(?:Failed to authenticate|invalid_grant|unauthorized_client|token_introspection_failed)\b/iu],
        vault: [/\b(?:permission denied|failed to seal|Error making API request|secret is missing)\b/iu],
        clerk: [/\b(?:ClerkAuthenticationError|ClerkAPIError|InvalidSessionError)\b/iu],
        auth0: [/\b(?:Auth0Error|Invalid token|access_denied|unauthorized)\b/iu],
        // ── Logging Libraries ───────────────────────────────────────────
        pino: [/\b(?:pino\.|"level":(?:50|60))\b/u],
        log4j: [/\b(?:org\.apache\.log4j|log4j:ERROR|log4j:WARN)\b/u],
        slf4j: [/\b(?:org\.slf4j|LoggerFactory|Failed to load class)\b/u],
        winston: [/\b(?:winston.*error|winston\.error)\b/iu],
        // ── Cloudflare / Edge ───────────────────────────────────────────
        cloudflare: [/\b(?:cloudflare.*error|cf-ray|Error \d{3,4})\b/iu],
        'cloudflare-workers': [/\b(?:Workers.*error|wrangler.*error|Service bindings error)\b/iu],
        vercel: [/\b(?:vercel.*error|Vercel.*failed|Deployment error)\b/iu],
        // ── Rust frameworks ─────────────────────────────────────────────
        rocket: [/\b(?:Rocket\.error|Rocket has crashed|launch fairing failed)\b/u],
        axum: [/\b(?:axum::|axum error|hyper::Error)\b/u],
        // ── Go frameworks ───────────────────────────────────────────────
        'echo-framework': [/\b(?:echo v4 handler panic|labstack\/echo|echo\.HTTPError)\b/u],
        fiber: [/\b(?:fiber\.Error|fiber\.RequestTimeoutError|fiber v2.*error)\b/u],
        // ── Mobile / Desktop ────────────────────────────────────────────
        'react-native': [/\b(?:Unable to resolve module|bundling failed|Metro error|ReactNativeFirebaseError)\b/u],
        flutter: [/\b(?:flutter.*error|Dart error|Unhandled Exception|FlutterError)\b/iu],
        electron: [/\b(?:electron-builder.*error|Cannot find module 'electron'|Error: electron)\b/u],
        // ── E-commerce / CMS ─────────────────────────────────────────────
        shopify: [/\b(?:ShopifyError|ShopifyAPIError|GraphQL.*error|ShopifyCLI.*error)\b/iu],
        wordpress: [/\b(?:PHP Fatal error:|PHP Parse error:|wp-db\.php|WPDB error)\b/iu],
        drupal: [/\b(?:Drupal\\|PluginNotFoundException|Uncaught PHP Exception)\b/u],
        strapi: [/\b(?:Strapi.*error|Error: Connection refused to database)\b/iu],
        // ── Backup / DR ─────────────────────────────────────────────────
        velero: [/\b(?:VeleroBackupError|BackupStorageLocation|backup failed)\b/iu],
        restic: [/\b(?:ResticRepositoryError|Fatal: unable to open repo|Fatal: |repo already locked)\b/u],
    };
    for (const [name, patterns] of Object.entries(sourceBoosters)) {
        map.set(name, [...patterns]);
    }
    return map;
}
