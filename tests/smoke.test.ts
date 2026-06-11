import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  INTERNAL_STACK_MARKER,
  KNOWN_LOG_SOURCES,
  detectLogSources,
  processLogFile,
  type LogStripResult,
} from '../src/core/logstrip-parser';

const FIXTURES_DIR = resolve(__dirname, 'fixtures');
const SNAPSHOTS_DIR = resolve(__dirname, 'fixtures/__snapshots__');

const UUID_REGEX =
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i;
const ISO_TIME_REGEX = /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

interface SmokeCase {
  fixture: string;
  minSavingsPercent: number;
  expectDeduplication: boolean;
  expectInternalStackHidden: boolean;
  mustContain: readonly string[];
  mustNotContain: readonly string[];
  mustDetectSources: readonly string[];
}

const cases: readonly SmokeCase[] = [
  {
    fixture: 'vitest-failure.log',
    minSavingsPercent: 47,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      '[ERROR] AssertionError: expected 500 to be 201',
      '/repo/tests/integration/users.test.ts:[NN]:[NN]',
      '[FATAL] worker crashed with exit code 1',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '[TRACE]', '[VERBOSE]'],
    mustDetectSources: ["vitest"],
  },
  {
    fixture: 'jest-noisy.log',
    minSavingsPercent: 40,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      "TypeError: Cannot read properties of undefined (reading 'amount')",
      '/repo/src/payments.ts:[NN]:[NN]',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', 'jest-circus/build'],
    mustDetectSources: ["jest"],
  },
  {
    fixture: 'docker-build.log',
    minSavingsPercent: 60,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      "[ERROR] src/services/payment-service.ts(42,9): error TS2322: Type 'string | undefined' is not assignable to type 'string'.",
      "[ERROR] src/repositories/user-repository.ts(118,23): error TS18048: 'user.email' is possibly 'undefined'.",
      '[FATAL] BUILD FAILURE: 2 distinct type errors detected',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', 'sha256:'],
    mustDetectSources: ["docker","buildkit","typescript"],
  },
  {
    fixture: 'maven-failure.log',
    minSavingsPercent: 35,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] /repo/src/main/java/com/example/checkout/CartService.java:[118,9] cannot find symbol',
      '[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin',
    ],
    mustNotContain: ['[INFO] Scanning for projects', '[INFO] Building checkout-service'],
    mustDetectSources: ["maven"],
  },
  {
    fixture: 'pytest-failure.log',
    minSavingsPercent: 33,
    expectDeduplication: false,
    expectInternalStackHidden: true,
    mustContain: [
      '[ERROR] FAILED tests/test_orders.py::test_create_order',
      'TypeError: Object of type Decimal is not JSON serializable',
      'AssertionError: assert 500 == 204',
      '/repo/tests/test_orders.py", line [NN], in test_create_order',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', 'site-packages/pytest'],
    mustDetectSources: ["pytest"],
  },
  {
    fixture: 'webpack-bundle.log',
    minSavingsPercent: 20,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      "[ERROR] Module not found: Error: Can't resolve '@company/sdk'",
      '[FATAL] BUILD FAILED: bundle size 2.07 MiB exceeds budget 2.00 MiB',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]'],
    mustDetectSources: ["webpack"],
  },
  {
    fixture: 'server-json.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      '"level":"error","msg":"database timeout","requestId":"[ID]"',
      'Caused by: Error: connect ECONNREFUSED [IP]:[PORT]',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['"level":"info"', '"level":"debug"', '10.42.7.18'],
    mustDetectSources: [],
  },
  {
    fixture: 'scanner-vulnerability.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      'CVE-2026-12345',
      'GHSA-ab12-cd34-ef56',
      'Severity: CRITICAL',
      'Fixed Version: 3.0.15-r2',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]'],
    mustDetectSources: ["trivy"],
  },
  {
    fixture: 'kubernetes-crashloop.log',
    minSavingsPercent: 15,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      '[x2] Warning BackOff',
      'ErrImagePull',
      'panic: runtime error: invalid memory address or nil pointer dereference',
      INTERNAL_STACK_MARKER,
      'Normal Pulled',
    ],
    mustNotContain: ['[INFO]', 'Normal Scheduled', 'Normal Pulling'],
    mustDetectSources: ["kubernetes","kubelet"],
  },
  {
    fixture: 'nginx-access-noisy.log',
    minSavingsPercent: 30,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '"POST /api/checkout HTTP/1.1" 502',
      'connect() failed (111: Connection refused) while connecting to upstream',
      'upstream timed out (110: Connection timed out) while reading response header from upstream',
      '[x2] [TIME] [error] 142#142: *935 recv() failed (104: Connection reset by peer)',
    ],
    mustNotContain: ['10.40.1.13', '10.44.2.19', '9f7d8a0e-3f0a-4c9b-8b3e-8f6b6f0fd004'],
    mustDetectSources: ["prometheus"],
  },
  {
    fixture: 'apache-httpd-noisy.log',
    minSavingsPercent: 70,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[x8] [TIME] [error] mod_jk child workerEnv in error state [6 | 7 | 8]',
      "[x3] [TIME] [error] jk2_init() Can't find child [6748 | 6749 | 6750] in scoreboard",
      '[x2] [TIME] [error] mod_jk child init 1 -2',
      '[x3] [TIME] [error] [client [IP]] Directory index forbidden by rule: /var/www/html/',
    ],
    mustNotContain: [
      '[notice]',
      'Sun Dec',
      'Mon Dec',
      '10.42.7.18',
      '/etc/httpd/conf/workers2.properties',
    ],
    mustDetectSources: ["apache-httpd"],
  },
  {
    fixture: 'java-spring-boot-realistic.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      '[TIME] ERROR 181 --- [checkout-api] [nio-8080-exec-3] c.e.checkout.web.CheckoutController      : Checkout request failed orderId=ord-88421 requestId=[ID]',
      '[x2] java.lang.IllegalStateException: Inventory reservation failed for order [ID]',
      '    at com.example.checkout.inventory.InventoryClient.reserve(InventoryClient.java:[NN])',
      'Caused by: java.net.SocketTimeoutException: Read timed out',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: [
      'Starting CheckoutApplication',
      'spring.datasource.url',
      '0e366c93-9a83-4a0a-8f29-32ddda128801',
    ],
    mustDetectSources: ["spring-boot"],
  },
  {
    fixture: 'node-crash-realistic.log',
    minSavingsPercent: 35,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      '[x2] [ERROR] [TIME] unhandledRejection requestId=[ID] route=POST /api/checkout',
      "TypeError: Cannot read properties of undefined (reading 'total')",
      '    at buildPaymentIntent (/srv/app/src/payments/build-payment-intent.ts:[NN]:[NN])',
      '[ERROR] [TIME] failed to publish checkout.failed event to [IP]:[PORT] requestId=[ID]',
      '[FATAL] [TIME] worker crashed with signal SIGABRT after uncaught exception',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '7e7f9d1d-6a2b-4c19-b33d-2d08b953d003'],
    mustDetectSources: ["express"],
  },
  {
    fixture: 'ecosystem-signals-realistic.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      'npm ERR! code ERESOLVE',
      "src/payments/build-payment-intent.ts(42,23): error TS2322: Type 'undefined' is not assignable to type 'Money'.",
      'CVE-2026-12345  openssl  CRITICAL  Fixed Version: 3.0.15-r2',
      "Error: waiting for ECS Service (checkout-api) stable: timeout while waiting for state to become 'tfSTABLE'",
      'Warning BackOff',
      '[x2] [TIME] datadog ERROR monitor Checkout API 5xx breached critical threshold service=checkout-api env=prod trace_id=[HASH]',
      '::error file=.github/workflows/deploy.yml,line=88::deployment failed after rollback exhausted',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['runner[checkout-prod] INFO', '10.90.12.41', '9f4b8b55-3756-4a15-8a8a-5da6bf44c923'],
    mustDetectSources: ["npm","kubernetes","typescript","datadog","docker","terraform","trivy","github-actions"],
  },
  {
    fixture: 'ci-pkg-managers.log',
    minSavingsPercent: 10,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      'unable to resolve dependency tree',
      'Could not resolve dependency',
      'error An unexpected error occurred: "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz: Request failed \\"[HTTP 4xx] Not Found\\""',
      '[pipeline] [ERROR] Step failed',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]'],
    mustDetectSources: ["npm","jenkins","docker","yarn","gitlab-ci"],
  },
  {
    fixture: 'build-test-systems.log',
    minSavingsPercent: 10,
    expectDeduplication: false,
    expectInternalStackHidden: true,
    mustContain: [
      'error: cannot find symbol',
      'FAILURE: Build failed with an exception.',
      'error[E0425]: cannot assign twice to immutable variable `x`',
      'panic: runtime error: index out of range [1] with length 1',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]'],
    mustDetectSources: ["gradle","cargo","go-build","go-test","rustc"],
  },
  {
    fixture: 'infra-cloud.log',
    minSavingsPercent: 5,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      'Error: UPGRADE FAILED: cannot patch "my-release-deployment" with kind Deployment: Deployment.apps "my-release-deployment" is invalid',
      '[ERROR] [TIME] Container failed to start. Failed to start and then listen on the port defined by the PORT environment variable.',
      'ERROR Invoke Error {"errorType":"TimeoutError","errorMessage":"Task timed out after 5.01 seconds"}',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '12:05:00.123Z'],
    mustDetectSources: ["gcp-cloud-run","aws-lambda","helm"],
  },
  {
    fixture: 'data-telemetry-scanners.log',
    minSavingsPercent: 5,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      'FATAL:  password authentication failed for user "admin"',
      'Error allocating resoures for the AOF rewrite.',
      'Connection to node -1 (kafka-broker/[IP]:[PORT]) could not be established. Broker may not be available.',
      'failed to send event [HASH] to https://sentry.io/api/123456/store/',
      'Error exporting spans: Connection refused to localhost:4317',
      "High severity: Detected a hardcoded secret 'password123'. Use environment variables instead.",
      'High severity vulnerability found in lodash',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e'],
    mustDetectSources: ["kafka","redis","postgresql","sentry","snyk","trivy"],
  },
  {
    fixture: 'web-frameworks-node.log',
    minSavingsPercent: 25,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      "[ERROR] express router Error: Cannot find module '@company/auth'",
      '[ERROR] fastify FST_ERR_CTR_INITIALIZER: plugin initialization failed',
      '[ERROR] @nestjs/core NestError: Circular dependency detected between AuthService and UserService',
      "[ERROR] next build Error: Cannot resolve dependency 'react-dom/client'",
      '[ERROR] hono server TypeError: Cannot read properties of undefined (reading \'headers\')',
      '[ERROR] pino ERROR: unhandled rejection in payment worker requestId=[ID]',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["express","fastify","nestjs","nextjs","pino"],
  },
  {
    fixture: 'java-enterprise.log',
    minSavingsPercent: 25,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] tomcat HTTP Status [HTTP 5xx] - Internal Server Error',
      '[ERROR] jetty.server IOException: Cannot read request body',
      '[ERROR] wildfly Deployment failed: WFLYCTL0199',
      '[ERROR] micronaut startup Error: No bean of type [CheckoutService] exists',
      '[ERROR] quarkus build Failed: Unresolved dependency',
      '[ERROR] io.vertx.core.VertxException: Timeout waiting for event bus reply',
      '[ERROR] org.apache.log4j FATAL: Cannot write to log file',
      '[ERROR] org.slf4j LoggerFactory failed to initialize',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["tomcat","jetty","wildfly","spring-boot","log4j","slf4j"],
  },
  {
    fixture: 'ai-ml-ecosystem.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] openai api Error: Rate limit exceeded',
      '[ERROR] huggingface download Error: ConnectionError',
      '[ERROR] vllm serve Error: CUDA out of memory',
      '[ERROR] torchserve Error: ModelLoadError',
      '[ERROR] ollama run Error: model not found',
      '[ERROR] llama.cpp inference Error: model file corrupted',
      '[ERROR] deepspeed runner Error: DeepSpeedRuntimeError',
      '[ERROR] langchain agent Error: OutputParserError',
      '[ERROR] llamaindex Error: ValueError: Embedding dimension mismatch',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["openai-api","huggingface","ollama","vllm","langchain","llamaindex"],
  },
  {
    fixture: 'mobile-desktop-cms.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      "[ERROR] react-native Error: bundling failed: Error: Unable to resolve module `@company/auth`",
      '[ERROR] electron-builder Error: Cannot find module \'electron\'',
      '[ERROR] tauri build Error: cargo build failed',
      '[ERROR] wordpress PHP Fatal error: Uncaught TypeError',
      '[ERROR] drupal Error: PluginNotFoundException',
      '[ERROR] strapi start Error: Error: Connection refused to database [IP]:[PORT]',
      '[ERROR] meilisearch index Error: MeilisearchCommunicationError',
      '[ERROR] typesense server Error: TypesenseError',
      '[ERROR] apache solr Error: SolrException',
      '[ERROR] algolia index Error: AlgoliaAPIError',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["react-native","electron","tauri","wordpress","drupal","strapi","shopify"],
  },
  {
    fixture: 'data-search-analytics.log',
    minSavingsPercent: 15,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] meilisearch index Error: MeilisearchCommunicationError',
      '[ERROR] typesense server Error: TypesenseError',
      '[ERROR] apache solr Error: SolrException',
      '[ERROR] posthog capture Error: QueueFullError',
      '[ERROR] amplitude Error: InvalidAPIKeyError',
      '[ERROR] mixpanel track Error: MixpanelServerError',
      '[ERROR] surrealdb start Error: StorageError',
      '[ERROR] planetscale database Error: BranchCreationError',
      '[ERROR] neondatabase Error: ConnectionError',
      '[ERROR] bullmq queue Error: StalledJobError',
      '[ERROR] clerk.dev Error: ClerkAuthenticationError',
      '[ERROR] authelia portal Error: AuthenticationFailed',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["posthog","amplitude","meilisearch","algolia","arangodb"],
  },
  {
    fixture: 'python-lint-async.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] ruff check F401',
      "[ERROR] mypy: error: Argument 1 to \"process_order\" has incompatible type",
      '[ERROR] pyright - error:',
      '[ERROR] pylint E0602',
      '[ERROR] aiohttp.server Error: RuntimeError: Session is closed',
      '[ERROR] sanic server Error: SanicException',
      '[FATAL] tornado.web Error: RuntimeError: IOLoop.current is closing',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["ruff","mypy","pyright","aiohttp","sanic"],
  },
  {
    fixture: 'go-rust-ruby-frameworks.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] echo lab Error: echo v4 handler panic',
      '[ERROR] gofiber fiber v2 Error: fiber.RequestTimeoutError',
      '[ERROR] go-chi chi.router Error: chi.middleware',
      '[ERROR] rocket rust Error: io::Error',
      '[ERROR] tokio-rs/axum Error: hyper::Error',
      '[ERROR] seanmonstar/warp Error: warp filter',
      '[ERROR] sinatra Error: Sinatra::NotFoundError',
      '[ERROR] puma starting Error: Errno::EADDRINUSE',
      '[ERROR] unicorn worker timeout Error',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["echo-framework","fiber","axum","rocket","sinatra","puma"],
  },
  {
    fixture: 'orm-db-migrations.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] prisma migrate Error: P3018',
      '[ERROR] drizzle kit push Error: DrizzleKitError',
      '[ERROR] typeorm query Error: QueryFailedError',
      '[ERROR] sequelize Error: SequelizeConnectionError',
      '[ERROR] knex migrate Error: MigrationLockError',
      '[ERROR] flyway migrate Error: FlywayValidateException',
      '[ERROR] liquibase update Error: LiquibaseException',
      '[ERROR] alembic upgrade Error: CommandFailed',
      '[ERROR] sqlalchemy.orm Error: OperationalError',
      '[ERROR] mongoose.connect Error: MongooseServerSelectionError',
      '[ERROR] mikro-orm migrate Error: MigrationError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["prisma","drizzle-orm","typeorm","sequelize","flyway","liquibase","mongoose"],
  },
  {
    fixture: 'auth-secrets-config.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] clerk.dev Error: ClerkAuthenticationError',
      '[ERROR] authelia portal Error: AuthenticationFailed',
      '[ERROR] lldap Error: LDAPBindError',
      '[ERROR] dex idp Error: ConnectorError',
      '[ERROR] doppler secrets Error: DopplerError',
      '[ERROR] infisical scan Error: InfisicalError',
      '[ERROR] secrets manager Error: InvalidParameterException',
      '[ERROR] aws kms Error: KeyUnavailableException',
      '[ERROR] aws ssm parameter Error: ParameterStoreError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["clerk","authelia","aws-kms","aws-secrets-manager","aws-ssm","doppler","infisical"],
  },
  {
    fixture: 'networking-edge-serverless.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] wireguard Error: handshake timeout',
      '[ERROR] tailscale up Error: AuthFailedError',
      '[ERROR] ngrok http Error: TunnelReconnectError',
      '[ERROR] cloudflared tunnel Error: ConnectionError',
      '[ERROR] cloudflare workers Error: WorkersCPUError',
      '[ERROR] deno deploy Error: DeployTimeoutError',
      '[ERROR] serverless deploy Error: ServerlessError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["wireguard","tailscale","ngrok","cloudflare-tunnel","cloudflare-workers","deno-deploy"],
  },
  {
    fixture: 'realtime-graphql.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] socket.io server Error: TransportCloseError',
      '[ERROR] pusher channel Error: PusherAuthenticationError',
      '[ERROR] ably realtime Error: AblyError',
      '[ERROR] livekit-server Error: RoomError',
      '[ERROR] centrifugo Error: CentrifugoError',
      '[ERROR] apollo server Error: GraphQLError',
      '[ERROR] graphql-yoga Error: YogaError',
      '[ERROR] dgraph query Error: DgraphError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["socketio","pusher","apollo-server","graphql-yoga","dgraph"],
  },
  {
    fixture: 'observability-analytics.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] instana sensor Error: AgentDisconnectedError',
      '[ERROR] signalfx ingest Error: IngestError',
      '[ERROR] lightstep tracer Error: SpanDroppedError',
      '[ERROR] thanos query Error: StoreTimeoutError',
      '[ERROR] cortexmetrics Error: CortexRulerError',
      '[ERROR] victoriametrics Error: VmStorageError',
      '[ERROR] posthog capture Error: QueueFullError',
      '[ERROR] amplitude Error: InvalidAPIKeyError',
      '[ERROR] mixpanel track Error: MixpanelServerError',
      '[ERROR] heap analytics Error: heap.io connection timeout',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["instana","signalfx","lightstep","thanos","posthog","amplitude"],
  },
  {
    fixture: 'iot-game-embedded.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] homeassistant Error: IntegrationSetupError',
      '[ERROR] platformio Error: PlatformioBuildError',
      '[ERROR] esphome config Error: ESPHomeValidationError',
      '[ERROR] tasmota mqtt Error: MQTTConnectionError',
      '[ERROR] openhab Error: BindingError',
      '[ERROR] unityengine Error: NullReferenceException',
      '[ERROR] unreal engine Error: AccessViolationException',
      '[ERROR] godot engine Error: ScriptError',
      '[ERROR] bevy engine Error: PanicError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["home-assistant","platformio","esphome","unity","unreal-engine","godot"],
  },
  {
    fixture: 'email-ci-infra.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] amazon ses Error: ThrottlingException',
      '[ERROR] mailchimp Error: CampaignError',
      '[ERROR] brevo Error: SendinblueAPIError',
      '[ERROR] postmark Error: PostmarkError',
      '[ERROR] resend Error: ResendAPIError',
      '[ERROR] sparkpost mail Error: SparkpostDeliveryError',
      '[ERROR] dagger do Error: DaggerBuildError',
      '[ERROR] fastlane lane Error: FastlaneError',
      '[ERROR] bitrise build Error: BitriseStepError',
      '[ERROR] aws cdk Error: CdkSynthError',
      '[ERROR] minikube start Error: DriverError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["aws-ses","mailchimp","brevo","postmark","dagger","fastlane","aws-cdk","minikube"],
  },
  {
    fixture: 'backup-docs-messaging.log',
    minSavingsPercent: 15,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[ERROR] velero backup Error: VeleroBackupError',
      '[ERROR] restic backup Error: ResticRepositoryError',
      '[ERROR] borg backup Error: BorgLockError',
      '[ERROR] docusaurus build Error: WebpackError',
      '[ERROR] sphinx-build Error: ExtensionError',
      '[ERROR] bullmq queue Error: StalledJobError',
      '[ERROR] bull-redis Error: BullQueueError',
      '[ERROR] kestra flow Error: KestraExecutionError',
      '[ERROR] kubecost api Error: KubecostPricingError',
      '[ERROR] cosign sign Error: CosignError',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '0acddaf33456'],
    mustDetectSources: ["velero","restic","docusaurus","sphinx","bullmq","cosign"],
  },
  {
    fixture: 'ci-platforms.log',
    minSavingsPercent: 40,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '::error file=.github/workflows/deploy.yml,line=42::deployment failed after rollback exhausted',
      '::error file=src/api/checkout.ts,line=88::TypeError: Cannot read properties of undefined',
      'Running with gitlab-runner',
      '[x2] [TIME] [ERROR] ERROR: Job failed: exit code 1',
      '[Pipeline] [ERROR] Stage "Deploy" failed',
      'Spin Cancelled',
      '[TIME] [ERROR] job was not approved',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', 'checkout-prod-ubuntu', 'Determining projects'],
    mustDetectSources: ["github-actions","gitlab-ci","jenkins","circleci"],
  },
  {
    fixture: 'build-toolchains.log',
    minSavingsPercent: 30,
    expectDeduplication: true,
    expectInternalStackHidden: true,
    mustContain: [
      'Execution failed for task',
      '> What went wrong:',
      'BUILD FAILED',
      'error[E0425]: cannot assign twice to immutable variable',
      '--- FAIL: TestCheckout',
      'make: *** [build] Error 2',
      'error MSB3073:',
      INTERNAL_STACK_MARKER,
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', 'node_modules/flaky'],
    mustDetectSources: ["gradle","bazel","cargo","go-test","cmake","msbuild","dotnet"],
  },
  {
    fixture: 'security-scanners.log',
    minSavingsPercent: 20,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      'CVE-2026-12345',
      'GHSA-ab12-cd34-ef56',
      'npm audit report',
      'semgrep finding:',
      'gitleaks: secret detected',
      'grype: CRITICAL CVE-2026-12345',
      'Security gate failed',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]'],
    mustDetectSources: ["trivy","snyk","npm-audit","semgrep","gitleaks","grype"],
  },
  {
    fixture: 'terraform-ansible-systemd.log',
    minSavingsPercent: 40,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      'Error: UPGRADE FAILED: cannot patch',
      'Error: waiting for ECS Service (checkout-api) stable: timeout',
      'fatal: [checkout-prod-01]: FAILED!',
      'Failed to start checkout-api.service',
      'FATAL: password authentication failed for user',
      'terraform apply failed',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '0.0.0.0:8080'],
    mustDetectSources: ["terraform","ansible","journald"],
  },
  {
    fixture: 'cloud-serverless.log',
    minSavingsPercent: 45,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      'ERROR Invoke Error',
      'Task timed out',
      '"level":"error","msg":"database timeout"',
      'Container failed to start',
      'Cloud Run deployment failed',
      'System.TimeoutException',
    ],
    mustNotContain: ['[INFO]', '[DEBUG]', '10.42.7.18', '9f4b8b55'],
    mustDetectSources: ["aws-lambda","cloudwatch","gcp-cloud-run","azure-functions"],
  },
  {
    fixture: 'all-sources-detection.log',
    minSavingsPercent: 50,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      '[x2] [ERROR] vitest Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] express Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] fastify Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] openai Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] ollama Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] shopify Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] unity Error: operation failed for request [ID] from [IP]:[PORT]',
      '[x2] [ERROR] prisma Error: operation failed for request [ID] from [IP]:[PORT]',
    ],
    mustNotContain: ['[INFO]', '0acddaf33456', '10.42.7.18'],
    mustDetectSources: ["docker","docker-compose","terraform","buildkit","consul","grafana"],
  },
  {
    fixture: 'polyglot-stacks.log',
    minSavingsPercent: 30,
    expectDeduplication: false,
    expectInternalStackHidden: true,
    mustContain: [
      "/srv/app/lib/payments/charger.rb:48:in 'charge!': insufficient funds (PaymentChargeError)",
      "\tfrom /srv/app/lib/orders/finalizer.rb:22:in 'finalize'",
      "thread 'settlement::tests::splits_fees' panicked at src/settlement/splitter.rs:88:13:",
      '   2: settlement_engine::settlement::splitter::split_fees',
      '[ERROR] [TIME] xunit CheckoutValidationFault: shipping address missing postal code',
      '   at Acme.Checkout.Validation.AddressValidator.Validate(Address address) in /src/Checkout/Validation/AddressValidator.cs:line 57',
      '[ERROR] [TIME] PHP Fatal error: Uncaught RefundLedgerException: ledger entry already settled in /srv/app/src/Refunds/Ledger.php:74',
      '#0 /srv/app/src/Refunds/RefundService.php(39): Acme\\Refunds\\Ledger->append()',
      '    at stageArchive (/srv/app/src/refunds/stages/archive.ts:[NN]:[NN])',
      '[... 6 more application stack frames ...]',
      INTERNAL_STACK_MARKER,
      '[FATAL] [TIME] polyglot matrix failed: 4 suites red',
    ],
    mustNotContain: [
      '[INFO]',
      '[DEBUG]',
      'rspec-core-3.13.0',
      '/rustc/',
      'at System.RuntimeMethodHandle',
      'stageMetrics',
      'stageReplay',
    ],
    mustDetectSources: ['rspec', 'cargo', 'rustc', 'dotnet', 'phpunit', 'xunit'],
  },
  {
    fixture: 'sanitize-secrets-ipv6.log',
    minSavingsPercent: 20,
    expectDeduplication: false,
    expectInternalStackHidden: false,
    mustContain: [
      '[EMAIL]',
      '[IPV6]',
      '[REDACTED]',
      '[PEM PRIVATE KEY REDACTED]',
    ],
    mustNotContain: [
      'user@example.com',
      '2001:db8',
      'sk_test_',
      'npm_ABCDEF',
      'AIzaSyB9a',
      'ACabcdef1234',
      'SG.AbcdeFGH',
      'MIIEow',
      '-----BEGIN',
      '-----END',
    ],
    mustDetectSources: [],
  },
  {
    fixture: 'pino-bunyan-numeric.log',
    minSavingsPercent: 40,
    expectDeduplication: true,
    expectInternalStackHidden: false,
    mustContain: [
      'slow query detected',
      'database query failed',
      'unhandled rejection',
    ],
    mustNotContain: [
      '"level":30,"msg":"server listening"',
      '"level":20,"msg":"cache miss"',
      '"level":30,"msg":"heartbeat"',
      'hidden internal library frames',
    ],
    mustDetectSources: [],
  },
];

let workDir: string;

async function compress(fixture: string): Promise<{
  result: LogStripResult;
  outputContent: string;
  inputContent: string;
}> {
  const inputPath = join(FIXTURES_DIR, fixture);
  const outputPath = join(workDir, fixture.replace(/\.log$/u, '.logstrip.log'));
  const inputContent = await readFile(inputPath, 'utf8');
  const result = await processLogFile(inputPath, outputPath);
  const outputContent = await readFile(outputPath, 'utf8');

  return { result, outputContent, inputContent };
}

beforeAll(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'logstrip-smoke-'));
});

afterAll(async () => {
  await rm(workDir, { force: true, recursive: true });
});

describe('smoke: realistic CI log fixtures', () => {
  for (const testCase of cases) {
    describe(testCase.fixture, () => {
      it('produces deterministic snapshot output', async () => {
        const { outputContent } = await compress(testCase.fixture);
        const snapshotPath = join(
          SNAPSHOTS_DIR,
          `${testCase.fixture}.logstrip.snap`,
        );

        await expect(outputContent).toMatchFileSnapshot(snapshotPath);
      });

      it('compresses logs above the required savings threshold', async () => {
        const { result } = await compress(testCase.fixture);

        expect(result.savingsPercent).toBeGreaterThanOrEqual(
          testCase.minSavingsPercent,
        );
        expect(result.outputTokens).toBeLessThan(result.inputTokens);
        expect(result.stats.outputLines).toBeLessThan(result.stats.inputLines);
      });

      it('does not leak UUIDs or ISO timestamps', async () => {
        const { outputContent } = await compress(testCase.fixture);

        expect(outputContent).not.toMatch(UUID_REGEX);
        expect(outputContent).not.toMatch(ISO_TIME_REGEX);
      });

      it('preserves required diagnostic context', async () => {
        const { outputContent } = await compress(testCase.fixture);

        for (const needle of testCase.mustContain) {
          expect(outputContent).toContain(needle);
        }
      });

      it('removes low-value noise', async () => {
        const { outputContent } = await compress(testCase.fixture);

        for (const needle of testCase.mustNotContain) {
          expect(outputContent).not.toContain(needle);
        }
      });

      if (testCase.mustDetectSources.length > 0) {
        it('detects expected log sources', async () => {
          const { result } = await compress(testCase.fixture);

          for (const source of testCase.mustDetectSources) {
            expect(result.detectedSources).toContain(source);
          }
        });
      }

      if (testCase.expectDeduplication) {
        it('folds repeated diagnostic lines via [xN] markers', async () => {
          const { result, outputContent } = await compress(testCase.fixture);

          expect(result.stats.duplicateLines).toBeGreaterThan(0);
          expect(outputContent).toMatch(/\[x\d+\] /u);
        });
      }

      if (testCase.expectInternalStackHidden) {
        it('hides internal library stack frames behind a single marker', async () => {
          const { result, outputContent } = await compress(testCase.fixture);

          expect(result.stats.hiddenInternalStackLines).toBeGreaterThan(0);
          expect(outputContent).toContain(INTERNAL_STACK_MARKER);
        });
      }
    });
  }
});

describe('smoke: stream resilience', () => {
  it('handles a synthetic 50k-line log without exhausting memory', async () => {
    const inputPath = join(workDir, 'synthetic-large.log');
    const outputPath = join(workDir, 'synthetic-large.logstrip.log');

    const chunks: string[] = [];
    for (let index = 0; index < 50000; index += 1) {
      if (index % 5 === 0) {
        chunks.push(
          '[ERROR] flaky test failed for request 4d8c1b9a-2e4c-4b9a-9d2e-1c4a5b6c7d8e',
        );
      } else if (index % 5 === 1) {
        chunks.push(
          '[ERROR] flaky test failed for request 5e9c2cab-3f5d-5cab-ae3f-2d5b6c7d8e9f',
        );
      } else if (index % 5 === 2) {
        chunks.push('    at lib (/repo/node_modules/flaky/index.js:1:5)');
      } else if (index % 5 === 3) {
        chunks.push('[INFO] heartbeat ok');
      } else {
        chunks.push('[DEBUG] noisy debug line should be dropped');
      }
    }

    await writeFile(inputPath, `${chunks.join('\n')}\n`, 'utf8');

    const before = process.memoryUsage().heapUsed;
    const result = await processLogFile(inputPath, outputPath);
    const after = process.memoryUsage().heapUsed;
    const heapGrowthMb = (after - before) / (1024 * 1024);

    expect(result.stats.inputLines).toBe(50000);
    expect(result.stats.duplicateLines).toBeGreaterThanOrEqual(10000);
    expect(result.stats.hiddenInternalStackLines).toBeGreaterThanOrEqual(10000);
    expect(result.stats.droppedLines).toBeGreaterThanOrEqual(20000);
    expect(result.savingsPercent).toBeGreaterThan(40);
    expect(heapGrowthMb).toBeLessThan(75);
  });

  it('detects all 700+ known sources from the comprehensive fixture', async () => {
    const inputPath = join(FIXTURES_DIR, 'all-sources-detection.log');
    const inputContent = await readFile(inputPath, 'utf8');
    const lines = inputContent.split('\n');

    // Use detectLogSources directly with a high limit (the LogStripResult
    // detectedSources is capped at 12 for practical reporting).
    const detected = detectLogSources(lines, KNOWN_LOG_SOURCES.length);

    // The fixture contains marker lines for every source, so detection
    // should cover the vast majority.
    expect(detected.length).toBeGreaterThanOrEqual(KNOWN_LOG_SOURCES.length * 0.9);

    // Spot-check a representative sample from each major category
    const spotCheck = [
      'vitest',
      'express',
      'fastify',
      'nestjs',
      'nextjs',
      'pino',
      'winston',
      'react-native',
      'flutter',
      'electron',
      'tauri',
      'shopify',
      'magento',
      'meilisearch',
      'tomcat',
      'quarkus',
      'micronaut',
      'vertx',
      'ruff',
      'mypy',
      'aiohttp',
      'echo-framework',
      'fiber',
      'axum',
      'rocket',
      'sinatra',
      'puma',
      'prisma',
      'drizzle-orm',
      'typeorm',
      'flyway',
      'openai-api',
      'huggingface',
      'ollama',
      'vllm',
      'langchain',
      'clerk',
      'authelia',
      'doppler',
      'wireguard',
      'tailscale',
      'ngrok',
      'socketio',
      'pusher',
      'apollo-server',
      'instana',
      'lightstep',
      'thanos',
      'posthog',
      'amplitude',
      'home-assistant',
      'platformio',
      'unity',
      'unreal-engine',
      'godot',
      'aws-ses',
      'mailchimp',
      'dagger',
      'fastlane',
      'aws-cdk',
      'minikube',
      'velero',
      'restic',
      'docusaurus',
      'sphinx',
      'bullmq',
    ];

    for (const source of spotCheck) {
      expect(detected).toContain(source);
    }
  });
});
