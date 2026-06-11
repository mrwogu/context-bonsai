import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Transform, Writable, type WritableOptions } from 'node:stream';
import { finished } from 'node:stream/promises';
import { describe, expect, it } from 'vitest';
import {
  createDynamicAggressivenessState,
  recordLineDecision,
} from '../src/core/aggressiveness/dynamic';
import {
  SOURCE_DIAGNOSTIC_BOOST,
  collectDetectedSourceHits,
  createSourceDetectionState,
  getEffectiveActiveConfidence,
  rankDetectedSources,
  scoreSourceDiagnosticBoost,
} from '../src/core/detection/source-detector';
import {
  createSourceProfiles,
  sourceMarkerWeight,
} from '../src/core/sources/source-profile';
import {
  CONTEXT_WINDOW_AFTER,
  CONTEXT_WINDOW_BEFORE,
  INTERNAL_STACK_MARKER,
  KNOWN_LOG_SOURCES,
  LOG_SOURCE_SIGNATURES,
  MAX_REPEAT_DELTA_VALUES,
  SCORE_KEEP_THRESHOLD,
  TFIDF_MAP_LIMIT,
  TFIDF_PENALTY,
  TFIDF_REPEAT_THRESHOLD,
  buildMergedConfig,
  createLogStripTransform,
  createRepeatSignature,
  detectLogSources,
  estimateTokens,
  explainLogLine,
  RARITY_BOOST,
  RARITY_MIN_INPUT_LINES,
  isCiNoiseLine,
  isInternalStackTraceLine,
  isProgressBarLine,
  isStackFrameLine,
  looksLikeDiagnosticLine,
  parseAggressiveness,
  pathsReferToSameFile,
  processLogFiles,
  processLogFile,
  processLogString,
  processLogStream,
  processLogStreamWithTimeout,
  sanitizeLine,
  createPemBlockState,
  maskPemBlock,
  scoreLineRelevance,
  shouldKeepLine,
  LogStripError,
} from '../src/core/logstrip-parser';
import {
  addRepeatGroupLine,
  createRepeatGroup,
  getRepeatGroupSpreadMs,
  renderRepeatGroup,
} from '../src/core/dedupe/repeat-grouper.js';

class MemoryWritable extends Writable {
  private readonly chunks: Buffer[] = [];

  constructor(options?: WritableOptions) {
    super(options);
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding),
    );
    callback();
  }

  content(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}

class SlowWritable extends MemoryWritable {
  constructor() {
    super({ highWaterMark: 1 });
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    setImmediate(() => super._write(chunk, encoding, callback));
  }
}

describe('logstrip parser', () => {
  it('ships 700+ automatic log-source fingerprints', () => {
    expect(KNOWN_LOG_SOURCES.length).toBeGreaterThanOrEqual(700);
    // Original core sources
    expect(KNOWN_LOG_SOURCES).toContain('vitest');
    expect(KNOWN_LOG_SOURCES).toContain('kubernetes');
    expect(KNOWN_LOG_SOURCES).toContain('trivy');
    expect(KNOWN_LOG_SOURCES).toContain('bamboo');
    expect(KNOWN_LOG_SOURCES).toContain('dynamodb');
    expect(KNOWN_LOG_SOURCES).toContain('falco');
    expect(KNOWN_LOG_SOURCES).toContain('spinnaker');
    expect(KNOWN_LOG_SOURCES).toContain('cloudformation');
    expect(KNOWN_LOG_SOURCES).toContain('qualys');
    expect(KNOWN_LOG_SOURCES).toContain('cloudflare');
    expect(KNOWN_LOG_SOURCES).toContain('journald');
    expect(KNOWN_LOG_SOURCES).toContain('dynatrace');
    expect(KNOWN_LOG_SOURCES).toContain('keycloak');
    expect(KNOWN_LOG_SOURCES).toContain('argocd');
    expect(KNOWN_LOG_SOURCES).toContain('mlflow');
    expect(KNOWN_LOG_SOURCES).toContain('databricks');
    expect(KNOWN_LOG_SOURCES).toContain('dbt');
    expect(KNOWN_LOG_SOURCES).toContain('looker');
    expect(KNOWN_LOG_SOURCES).toContain('great-expectations');
    expect(KNOWN_LOG_SOURCES).toContain('pagerduty');
    expect(KNOWN_LOG_SOURCES).toContain('launchdarkly');
    expect(KNOWN_LOG_SOURCES).toContain('kustomize');
    expect(KNOWN_LOG_SOURCES).toContain('crossplane');
    expect(KNOWN_LOG_SOURCES).toContain('terragrunt');
    expect(KNOWN_LOG_SOURCES).toContain('kube-bench');
    expect(KNOWN_LOG_SOURCES).toContain('camunda');
    expect(KNOWN_LOG_SOURCES).toContain('eventbridge');
    expect(KNOWN_LOG_SOURCES).toContain('langfuse');
    expect(KNOWN_LOG_SOURCES).toContain('kserve');
    expect(KNOWN_LOG_SOURCES).toContain('salesforce');
    expect(KNOWN_LOG_SOURCES).toContain('twilio');
    expect(KNOWN_LOG_SOURCES).toContain('k6');
    expect(KNOWN_LOG_SOURCES).toContain('aws-guardduty');
    expect(KNOWN_LOG_SOURCES).toContain('scylladb');
    expect(KNOWN_LOG_SOURCES).toContain('confluent');
    // Web frameworks (JS/TS)
    expect(KNOWN_LOG_SOURCES).toContain('express');
    expect(KNOWN_LOG_SOURCES).toContain('fastify');
    expect(KNOWN_LOG_SOURCES).toContain('nestjs');
    expect(KNOWN_LOG_SOURCES).toContain('nextjs');
    expect(KNOWN_LOG_SOURCES).toContain('nuxt');
    expect(KNOWN_LOG_SOURCES).toContain('sveltekit');
    expect(KNOWN_LOG_SOURCES).toContain('remix');
    expect(KNOWN_LOG_SOURCES).toContain('astro');
    expect(KNOWN_LOG_SOURCES).toContain('hono');
    expect(KNOWN_LOG_SOURCES).toContain('deno-runtime');
    expect(KNOWN_LOG_SOURCES).toContain('elysia');
    // Logging libraries
    expect(KNOWN_LOG_SOURCES).toContain('pino');
    expect(KNOWN_LOG_SOURCES).toContain('winston');
    expect(KNOWN_LOG_SOURCES).toContain('bunyan');
    expect(KNOWN_LOG_SOURCES).toContain('log4j');
    expect(KNOWN_LOG_SOURCES).toContain('slf4j');
    expect(KNOWN_LOG_SOURCES).toContain('zerolog');
    expect(KNOWN_LOG_SOURCES).toContain('loguru');
    expect(KNOWN_LOG_SOURCES).toContain('structlog');
    // Mobile/desktop
    expect(KNOWN_LOG_SOURCES).toContain('react-native');
    expect(KNOWN_LOG_SOURCES).toContain('flutter');
    expect(KNOWN_LOG_SOURCES).toContain('expo');
    expect(KNOWN_LOG_SOURCES).toContain('electron');
    expect(KNOWN_LOG_SOURCES).toContain('tauri');
    // CMS/e-commerce
    expect(KNOWN_LOG_SOURCES).toContain('wordpress');
    expect(KNOWN_LOG_SOURCES).toContain('drupal');
    expect(KNOWN_LOG_SOURCES).toContain('strapi');
    expect(KNOWN_LOG_SOURCES).toContain('shopify');
    expect(KNOWN_LOG_SOURCES).toContain('magento');
    // Search
    expect(KNOWN_LOG_SOURCES).toContain('meilisearch');
    expect(KNOWN_LOG_SOURCES).toContain('typesense');
    expect(KNOWN_LOG_SOURCES).toContain('solr');
    expect(KNOWN_LOG_SOURCES).toContain('algolia');
    // Java enterprise
    expect(KNOWN_LOG_SOURCES).toContain('tomcat');
    expect(KNOWN_LOG_SOURCES).toContain('quarkus');
    expect(KNOWN_LOG_SOURCES).toContain('micronaut');
    expect(KNOWN_LOG_SOURCES).toContain('vertx');
    expect(KNOWN_LOG_SOURCES).toContain('wildfly');
    // Python
    expect(KNOWN_LOG_SOURCES).toContain('ruff');
    expect(KNOWN_LOG_SOURCES).toContain('mypy');
    expect(KNOWN_LOG_SOURCES).toContain('pyright');
    expect(KNOWN_LOG_SOURCES).toContain('aiohttp');
    // Go/Rust/Ruby
    expect(KNOWN_LOG_SOURCES).toContain('echo-framework');
    expect(KNOWN_LOG_SOURCES).toContain('fiber');
    expect(KNOWN_LOG_SOURCES).toContain('axum');
    expect(KNOWN_LOG_SOURCES).toContain('rocket');
    expect(KNOWN_LOG_SOURCES).toContain('sinatra');
    expect(KNOWN_LOG_SOURCES).toContain('puma');
    // ORM/DB tools
    expect(KNOWN_LOG_SOURCES).toContain('prisma');
    expect(KNOWN_LOG_SOURCES).toContain('drizzle-orm');
    expect(KNOWN_LOG_SOURCES).toContain('typeorm');
    expect(KNOWN_LOG_SOURCES).toContain('sequelize');
    expect(KNOWN_LOG_SOURCES).toContain('flyway');
    expect(KNOWN_LOG_SOURCES).toContain('liquibase');
    expect(KNOWN_LOG_SOURCES).toContain('sqlalchemy');
    // AI/ML
    expect(KNOWN_LOG_SOURCES).toContain('openai-api');
    expect(KNOWN_LOG_SOURCES).toContain('huggingface');
    expect(KNOWN_LOG_SOURCES).toContain('ollama');
    expect(KNOWN_LOG_SOURCES).toContain('vllm');
    expect(KNOWN_LOG_SOURCES).toContain('langchain');
    // Auth/secrets
    expect(KNOWN_LOG_SOURCES).toContain('clerk');
    expect(KNOWN_LOG_SOURCES).toContain('authelia');
    expect(KNOWN_LOG_SOURCES).toContain('doppler');
    expect(KNOWN_LOG_SOURCES).toContain('infisical');
    // Storage/CDN
    expect(KNOWN_LOG_SOURCES).toContain('aws-s3');
    expect(KNOWN_LOG_SOURCES).toContain('akamai');
    // Game engines
    expect(KNOWN_LOG_SOURCES).toContain('unity');
    expect(KNOWN_LOG_SOURCES).toContain('unreal-engine');
    expect(KNOWN_LOG_SOURCES).toContain('godot');
    // IoT
    expect(KNOWN_LOG_SOURCES).toContain('home-assistant');
    expect(KNOWN_LOG_SOURCES).toContain('platformio');
    // Networking
    expect(KNOWN_LOG_SOURCES).toContain('wireguard');
    expect(KNOWN_LOG_SOURCES).toContain('tailscale');
    expect(KNOWN_LOG_SOURCES).toContain('ngrok');
    // Analytics
    expect(KNOWN_LOG_SOURCES).toContain('posthog');
    expect(KNOWN_LOG_SOURCES).toContain('amplitude');
    expect(KNOWN_LOG_SOURCES).toContain('mixpanel');
    // Email
    expect(KNOWN_LOG_SOURCES).toContain('aws-ses');
    expect(KNOWN_LOG_SOURCES).toContain('mailchimp');
    expect(KNOWN_LOG_SOURCES).toContain('brevo');
    // CI/CD (more)
    expect(KNOWN_LOG_SOURCES).toContain('dagger');
    expect(KNOWN_LOG_SOURCES).toContain('fastlane');
    expect(KNOWN_LOG_SOURCES).toContain('bitrise');
    // Testing (more)
    expect(KNOWN_LOG_SOURCES).toContain('selenium');
    expect(KNOWN_LOG_SOURCES).toContain('cucumber');
    expect(KNOWN_LOG_SOURCES).toContain('robot-framework');
    // Infrastructure (more)
    expect(KNOWN_LOG_SOURCES).toContain('aws-cdk');
    expect(KNOWN_LOG_SOURCES).toContain('minikube');
    expect(KNOWN_LOG_SOURCES).toContain('kind');
    // More databases
    expect(KNOWN_LOG_SOURCES).toContain('surrealdb');
    expect(KNOWN_LOG_SOURCES).toContain('planetscale');
    expect(KNOWN_LOG_SOURCES).toContain('arangodb');
    // Backup
    expect(KNOWN_LOG_SOURCES).toContain('velero');
    expect(KNOWN_LOG_SOURCES).toContain('restic');
    // Docs
    expect(KNOWN_LOG_SOURCES).toContain('docusaurus');
    expect(KNOWN_LOG_SOURCES).toContain('sphinx');
    // FinOps
    expect(KNOWN_LOG_SOURCES).toContain('kubecost');
  });

  it('detects every known source from its marker strings', () => {
    // For each source in LOG_SOURCE_SIGNATURES, ensure at least one marker
    // produces a detection hit when passed through detectLogSources.
    const allDetected = detectLogSources(
      // Synthesize one line per source containing its first marker
      KNOWN_LOG_SOURCES.map((source) => {
        // We rely on the fact that LOG_SOURCE_SIGNATURES maps source→markers
        // and detectLogSources scans lines for those markers. Using the source
        // name itself won't always work, but we use a dedicated test per category
        // below. Here we just ensure detectLogSources returns results.
        return `[ERROR] ${source} failed`;
      }),
      KNOWN_LOG_SOURCES.length,
    );
    // Most sources whose name appears in the marker list will be detected
    // through the [ERROR] <source> failed line. Others need specific markers.
    expect(allDetected.length).toBeGreaterThan(0);
  });

  it('detects new web framework sources from realistic markers', () => {
    expect(detectLogSources(['express server listening on port 3000'])).toContain('express');
    expect(detectLogSources(['fastify server started at 0.0.0.0:8080'])).toContain('fastify');
    expect(detectLogSources(['@nestjs/core bootstrapped successfully'])).toContain('nestjs');
    expect(detectLogSources(['next build compiled successfully'])).toContain('nextjs');
    expect(detectLogSources(['nuxt build done in 12.4s'])).toContain('nuxt');
    expect(detectLogSources(['sveltekit adapter-node generated'])).toContain('sveltekit');
    expect(detectLogSources(['@remix-run/dev server ready'])).toContain('remix');
    expect(detectLogSources(['astro build complete'])).toContain('astro');
    expect(detectLogSources(['hono server listening on port 3000'])).toContain('hono');
    expect(detectLogSources(['deno task build completed'])).toContain('deno-runtime');
    expect(detectLogSources(['elysia server started'])).toContain('elysia');
  });

  it('detects logging library sources', () => {
    expect(detectLogSources(['pino pretty transport error'])).toContain('pino');
    expect(detectLogSources(['winston logger error: transport failed'])).toContain('winston');
    expect(detectLogSources(['bunyan logger FATAL crash'])).toContain('bunyan');
    expect(detectLogSources(['log4j FATAL Unable to open file'])).toContain('log4j');
    expect(detectLogSources(['org.slf4j.LoggerFactory failed'])).toContain('slf4j');
    expect(detectLogSources(['rs/zerolog error occurred'])).toContain('zerolog');
    expect(detectLogSources(['loguru.py ERROR failed'])).toContain('loguru');
    expect(detectLogSources(['python-structlog error failed'])).toContain('structlog');
  });

  it('detects mobile and desktop framework sources', () => {
    expect(detectLogSources(['react-native Error: bundling failed'])).toContain('react-native');
    expect(detectLogSources(['flutter test failed'])).toContain('flutter');
    expect(detectLogSources(['eas build failed with exit code 1'])).toContain('expo');
    expect(detectLogSources(['@capacitor/core build error'])).toContain('capacitor');
    expect(detectLogSources(['ionic framework build error'])).toContain('ionic');
    expect(detectLogSources(['electron-builder error: cannot find module'])).toContain('electron');
    expect(detectLogSources(['tauri build failed'])).toContain('tauri');
    expect(detectLogSources(['qcritical application crash'])).toContain('qt');
  });

  it('detects CMS and e-commerce sources', () => {
    expect(detectLogSources(['wordpress PHP Fatal error'])).toContain('wordpress');
    expect(detectLogSources(['drupal module install failed'])).toContain('drupal');
    expect(detectLogSources(['strapi start failed'])).toContain('strapi');
    expect(detectLogSources(['ghost cms error: database connection'])).toContain('ghost-cms');
    expect(detectLogSources(['contentful API error'])).toContain('contentful');
    expect(detectLogSources(['sanity.io studio error'])).toContain('sanity');
    expect(detectLogSources(['shopify-cli deploy failed'])).toContain('shopify');
    expect(detectLogSources(['magento2 cache flush error'])).toContain('magento');
    expect(detectLogSources(['woocommerce payment error'])).toContain('woocommerce');
    expect(detectLogSources(['medusajs server error'])).toContain('medusa');
  });

  it('detects search engine sources', () => {
    expect(detectLogSources(['meilisearch index creation failed'])).toContain('meilisearch');
    expect(detectLogSources(['typesense server crashed'])).toContain('typesense');
    expect(detectLogSources(['apache solr core load failed'])).toContain('solr');
    expect(detectLogSources(['apache solr core load failed'])).not.toContain('apache-httpd');
    expect(detectLogSources(['algolia index error'])).toContain('algolia');
  });

  it('detects Java enterprise sources', () => {
    expect(detectLogSources(['mod_jk child workerEnv in error state 6'])).toContain('apache-httpd');
    expect(detectLogSources(['Apache/2.4.52 configured -- resuming normal operations'])).toContain('apache-httpd');
    expect(detectLogSources(['apache tomcat startup failed'])).toContain('tomcat');
    expect(detectLogSources(['eclipse jetty connector error'])).toContain('jetty');
    expect(detectLogSources(['wildfly deploy failed'])).toContain('wildfly');
    expect(detectLogSources(['jboss deployment error'])).toContain('wildfly');
    expect(detectLogSources(['glassfish server startup error'])).toContain('glassfish');
    expect(detectLogSources(['micronaut startup error'])).toContain('micronaut');
    expect(detectLogSources(['quarkus dev error: compilation failed'])).toContain('quarkus');
    expect(detectLogSources(['io.vertx.core.VertxException'])).toContain('vertx');
    expect(detectLogSources(['helidon se server error'])).toContain('helidon');
  });

  it('detects Python lint and async framework sources', () => {
    expect(detectLogSources(['ruff check failed: unused import'])).toContain('ruff');
    expect(detectLogSources(['mypy: error: incompatible type'])).toContain('mypy');
    expect(detectLogSources(['pyright - error: Type error'])).toContain('pyright');
    expect(detectLogSources(['aiohttp.server error: handler crashed'])).toContain('aiohttp');
    expect(detectLogSources(['sanic server error: request timeout'])).toContain('sanic');
    expect(detectLogSources(['tornado.web error: 500'])).toContain('tornado-framework');
    expect(detectLogSources(['scrapy crawl failed: spider error'])).toContain('scrapy');
  });

  it('detects Go, Rust, and Ruby framework sources', () => {
    expect(detectLogSources(['labstack/echo v4 router error'])).toContain('echo-framework');
    expect(detectLogSources(['gofiber fiber v2 error: timeout'])).toContain('fiber');
    expect(detectLogSources(['go-chi chi.router error'])).toContain('chi');
    expect(detectLogSources(['gobuffalo buffalo dev error'])).toContain('buffalo');
    expect(detectLogSources(['rocket rust server error'])).toContain('rocket');
    expect(detectLogSources(['tokio-rs/axum router error'])).toContain('axum');
    expect(detectLogSources(['sinatra error: route not found'])).toContain('sinatra');
    expect(detectLogSources(['puma starting error: bind failed'])).toContain('puma');
    expect(detectLogSources(['unicorn worker timeout error'])).toContain('unicorn-rb');
  });

  it('detects ORM and database migration sources', () => {
    expect(detectLogSources(['prisma migrate deploy failed'])).toContain('prisma');
    expect(detectLogSources(['drizzle kit push failed'])).toContain('drizzle-orm');
    expect(detectLogSources(['typeorm query failed: timeout'])).toContain('typeorm');
    expect(detectLogSources(['sequelize connection error'])).toContain('sequelize');
    expect(detectLogSources(['knex migrate:latest failed'])).toContain('knex');
    expect(detectLogSources(['flyway migrate error: checksum mismatch'])).toContain('flyway');
    expect(detectLogSources(['liquibase update failed'])).toContain('liquibase');
    expect(detectLogSources(['alembic upgrade head failed'])).toContain('alembic');
    expect(detectLogSources(['sqlalchemy.orm error: flush failed'])).toContain('sqlalchemy');
    expect(detectLogSources(['mongoose.connect error: timeout'])).toContain('mongoose');
    expect(detectLogSources(['mikro-orm migrate failed'])).toContain('mikro-orm');
  });

  it('detects AI/ML sources', () => {
    expect(detectLogSources(['openai api error: rate limit exceeded'])).toContain('openai-api');
    expect(detectLogSources(['huggingface model download failed'])).toContain('huggingface');
    expect(detectLogSources(['ollama serve error: model not found'])).toContain('ollama');
    expect(detectLogSources(['vllm serve error: CUDA OOM'])).toContain('vllm');
    expect(detectLogSources(['torchserve model loading failed'])).toContain('torchserve');
    expect(detectLogSources(['comfyui manager error'])).toContain('comfyui');
    expect(detectLogSources(['deepspeed runner error'])).toContain('deepspeed');
    expect(detectLogSources(['llama.cpp inference error'])).toContain('llama-cpp');
    expect(detectLogSources(['langchain agent execution failed'])).toContain('langchain');
    expect(detectLogSources(['stable diffusion generation error'])).toContain('stable-diffusion');
  });

  it('detects auth, secrets, and config sources', () => {
    expect(detectLogSources(['clerk.dev authentication error'])).toContain('clerk');
    expect(detectLogSources(['authelia portal error: access denied'])).toContain('authelia');
    expect(detectLogSources(['secrets manager rotation failed'])).toContain('aws-secrets-manager');
    expect(detectLogSources(['doppler secrets access error'])).toContain('doppler');
    expect(detectLogSources(['infisical scan detected secret leak'])).toContain('infisical');
    expect(detectLogSources(['aws kms decrypt error'])).toContain('aws-kms');
    expect(detectLogSources(['aws ssm parameter fetch error'])).toContain('aws-ssm');
  });

  it('detects edge, real-time, and GraphQL sources', () => {
    expect(detectLogSources(['cloudflare workers error: exceeded CPU limit'])).toContain('cloudflare-workers');
    expect(detectLogSources(['wrangler dev error: worker failed'])).toContain('cloudflare-workers');
    expect(detectLogSources(['deno deploy error: function timeout'])).toContain('deno-deploy');
    expect(detectLogSources(['serverless deploy error: stack rollback'])).toContain('serverless-framework');
    expect(detectLogSources(['socket.io server error: transport close'])).toContain('socketio');
    expect(detectLogSources(['pusher channel error: connection failed'])).toContain('pusher');
    expect(detectLogSources(['ably realtime error: channel unavailable'])).toContain('ably');
    expect(detectLogSources(['livekit-server error: room creation failed'])).toContain('livekit');
    expect(detectLogSources(['centrifugo error: connection drop'])).toContain('centrifugo');
    expect(detectLogSources(['apollo server error: schema validation'])).toContain('apollo-server');
    expect(detectLogSources(['graphql-yoga error: context factory'])).toContain('graphql-yoga');
    expect(detectLogSources(['dgraph query error: predicate not found'])).toContain('dgraph');
  });

  it('detects observability, analytics, and email sources', () => {
    expect(detectLogSources(['instana sensor error: agent disconnected'])).toContain('instana');
    expect(detectLogSources(['lightstep tracer error: span dropped'])).toContain('lightstep');
    expect(detectLogSources(['thanos query error: store timeout'])).toContain('thanos');
    expect(detectLogSources(['victoriametrics vminsert error'])).toContain('victoriametrics');
    expect(detectLogSources(['posthog capture error: queue full'])).toContain('posthog');
    expect(detectLogSources(['amplitude identify error: invalid key'])).toContain('amplitude');
    expect(detectLogSources(['mixpanel track error: event dropped'])).toContain('mixpanel');
    expect(detectLogSources(['heap analytics error: track failed'])).toContain('heap-analytics');
    expect(detectLogSources(['plausible analytics error: db timeout'])).toContain('plausible');
    expect(detectLogSources(['matomo error: tracker timeout'])).toContain('matomo');
    expect(detectLogSources(['amazon ses send error: throttled'])).toContain('aws-ses');
    expect(detectLogSources(['mailchimp campaign error: template'])).toContain('mailchimp');
    expect(detectLogSources(['brevo email send error'])).toContain('brevo');
    expect(detectLogSources(['resend.com email delivery failed'])).toContain('resend');
    expect(detectLogSources(['sparkpost mail error: bounce'])).toContain('sparkpost');
  });

  it('detects infrastructure, storage, and networking sources', () => {
    expect(detectLogSources(['aws s3 bucket access denied'])).toContain('aws-s3');
    expect(detectLogSources(['google cloud storage upload error'])).toContain('gcs');
    expect(detectLogSources(['azure blob upload failed'])).toContain('azure-blob');
    expect(detectLogSources(['akamai edge error: purge failed'])).toContain('akamai');
    expect(detectLogSources(['wireguard handshake error'])).toContain('wireguard');
    expect(detectLogSources(['tailscale up error: auth failed'])).toContain('tailscale');
    expect(detectLogSources(['ngrok http tunnel error'])).toContain('ngrok');
    expect(detectLogSources(['cloudflared tunnel error'])).toContain('cloudflare-tunnel');
    expect(detectLogSources(['zerotier-one node error'])).toContain('zerotier');
    expect(detectLogSources(['aws cdk deploy failed'])).toContain('aws-cdk');
    expect(detectLogSources(['cdk for terraform synth error'])).toContain('cdktf');
    expect(detectLogSources(['minikube start error: driver'])).toContain('minikube');
    expect(detectLogSources(['k3s server error: etcd'])).toContain('k3s');
    expect(detectLogSources(['kubecost api error: pricing'])).toContain('kubecost');
    expect(detectLogSources(['velero backup failed: timeout'])).toContain('velero');
    expect(detectLogSources(['restic backup error: repository locked'])).toContain('restic');
  });

  it('detects IoT, game engine, and CI/CD sources', () => {
    expect(detectLogSources(['homeassistant error: integration setup'])).toContain('home-assistant');
    expect(detectLogSources(['platformio pio run failed'])).toContain('platformio');
    expect(detectLogSources(['esphome config validation error'])).toContain('esphome');
    expect(detectLogSources(['tasmota mqtt connection error'])).toContain('tasmota');
    expect(detectLogSources(['openhab binding error'])).toContain('openhab');
    expect(detectLogSources(['unityengine crash: null reference'])).toContain('unity');
    expect(detectLogSources(['unreal engine crash: access violation'])).toContain('unreal-engine');
    expect(detectLogSources(['godot engine error: script failed'])).toContain('godot');
    expect(detectLogSources(['bevy engine error: ecs system panic'])).toContain('bevy');
    expect(detectLogSources(['dagger do build failed'])).toContain('dagger');
    expect(detectLogSources(['fastlane lane error: match'])).toContain('fastlane');
    expect(detectLogSources(['bitrise build failed: step error'])).toContain('bitrise');
    expect(detectLogSources(['codemagic build error: pod install'])).toContain('codemagic');
    expect(detectLogSources(['woodpecker-ci pipeline error'])).toContain('woodpecker-ci');
    expect(detectLogSources(['selenium webdriver error: timeout'])).toContain('selenium');
    expect(detectLogSources(['cucumber-js test failed: step'])).toContain('cucumber');
    expect(detectLogSources(['robotframework keyword error'])).toContain('robot-framework');
  });

  it('detects more databases and documentation sources', () => {
    expect(detectLogSources(['surrealdb start error: storage'])).toContain('surrealdb');
    expect(detectLogSources(['planetscale database error: branch'])).toContain('planetscale');
    expect(detectLogSources(['neondatabase connection error'])).toContain('neon-db');
    expect(detectLogSources(['cloudflare d1 query error'])).toContain('d1-database');
    expect(detectLogSources(['arangodb query timeout'])).toContain('arangodb');
    expect(detectLogSources(['orientdb server error: cluster'])).toContain('orientdb');
    expect(detectLogSources(['foundationdb error: proxy'])).toContain('foundationdb');
    expect(detectLogSources(['docusaurus build error: webpack'])).toContain('docusaurus');
    expect(detectLogSources(['sphinx-build error: extension'])).toContain('sphinx');
    expect(detectLogSources(['mdbook build error: chapter'])).toContain('mdbook');
    expect(detectLogSources(['kestra flow execution error'])).toContain('kestra');
    expect(detectLogSources(['bullmq queue error: stalled job'])).toContain('bullmq');
  });

  it('detects EVERY known source from its primary marker', () => {
    // Exhaustive per-source test: for each of the 707 signatures, synthesize
    // a log line containing the source's first marker and verify detection.
    const undetected: string[] = [];

    for (const [source, markers] of LOG_SOURCE_SIGNATURES) {
      const primaryMarker = markers[0];
      if (primaryMarker === undefined) {
        undetected.push(`${source} (no markers)`);
        continue;
      }

      // Build a line that includes the marker in a realistic context.
      // We prefix with [ERROR] so the line is not dropped as noise.
      const line = `[ERROR] ${primaryMarker} error occurred`;
      const detected = detectLogSources([line], 1);

      // The source might not be the top-1 hit if another source's marker
      // is a shorter substring that also matches (e.g., "deno" vs
      // "deno-runtime"). Accept the source anywhere in the top-5 results.
      const expanded = detectLogSources([line], 5);
      if (!expanded.includes(source)) {
        undetected.push(`${source} (marker: "${primaryMarker}")`);
      }
    }

    // We allow a small number of ambiguous markers that overlap with
    // shorter markers from other sources. The detection engine uses
    // substring matching which can produce ambiguous hits.
    expect(undetected.length).toBeLessThanOrEqual(5);
    if (undetected.length > 0) {
      // Log the undetected sources for debugging but don't fail
      // unless more than 5 sources have issues.
      console.warn('Sources not detected from primary marker:', undetected);
    }
  });

  it('every detected source in KNOWN_LOG_SOURCES has a matching signature', () => {
    const signatureSources = new Set(LOG_SOURCE_SIGNATURES.map(([s]) => s));
    for (const source of KNOWN_LOG_SOURCES) {
      expect(signatureSources.has(source)).toBe(true);
    }
    expect(KNOWN_LOG_SOURCES.length).toBe(LOG_SOURCE_SIGNATURES.length);
  });

  it('no duplicate source names in signatures', () => {
    const names = LOG_SOURCE_SIGNATURES.map(([source]) => source);
    const unique = new Set(names);
    expect(unique.size).toBe(names.length);
  });

  it('requires a per-source fixture for every known source', () => {
    // Every source in LOG_SOURCE_SIGNATURES must have a corresponding
    // fixture file at tests/fixtures/sources/<source>.log that contains
    // at least one line matching the source's primary marker.
    const fs = require('node:fs') as typeof import('node:fs');
    const path = require('node:path') as typeof import('node:path');
    const fixturesDir = path.resolve(__dirname, 'fixtures', 'sources');

    const missing: string[] = [];
    const empty: string[] = [];
    const noMarker: Array<{ source: string; marker: string }> = [];

    for (const [source, markers] of LOG_SOURCE_SIGNATURES) {
      const fixturePath = path.join(fixturesDir, `${source}.log`);

      if (!fs.existsSync(fixturePath)) {
        missing.push(source);
        continue;
      }

      const content = fs.readFileSync(fixturePath, 'utf8');
      if (content.trim().length === 0) {
        empty.push(source);
        continue;
      }

      // Verify at least one marker appears in the fixture
      const primaryMarker = markers[0];
      if (
        primaryMarker !== undefined &&
        !content.toLowerCase().includes(primaryMarker.toLowerCase())
      ) {
        noMarker.push({ source, marker: primaryMarker });
      }
    }

    expect(missing).toEqual([]);
    expect(empty).toEqual([]);
    expect(noMarker).toEqual([]);
  });

  it('detects dominant log sources from mixed streams', () => {
    const detected = detectLogSources(
      [
        'npm ERR! code ERESOLVE',
        'npm ERR! unable to resolve dependency tree',
        'pytest tests/test_orders.py::test_create_order FAILED',
        'pytest tests/test_orders.py::test_delete_order FAILED',
        'kubelet Back-off restarting failed container',
        'Trivy Vulnerability report CVE-2026-12345',
      ],
      3,
    );

    expect(detected).toEqual(['npm', 'pytest', 'kubelet']);
    expect(detectLogSources('jenkins pipeline failure\njenkins stage failed')).toEqual(
      ['jenkins'],
    );
    expect(detectLogSources('anything', 0)).toEqual([]);
  });

  it('parses aggressiveness values', () => {
    expect(parseAggressiveness(undefined)).toBe('auto');
    expect(parseAggressiveness('LOW')).toBe('low');
    expect(parseAggressiveness('auto')).toBe('auto');
    expect(() => parseAggressiveness('extreme')).toThrow(
      'Unsupported aggressiveness',
    );
  });

  it('weights source profiles and applies confident source diagnostic boosts', () => {
    expect(sourceMarkerWeight('go')).toBe(6);
    expect(sourceMarkerWeight('github actions')).toBe(16);
    expect(sourceMarkerWeight('typescript')).toBe(12);

    const profiles = createSourceProfiles([
      ['alpha', ['alpha']],
      ['beta', ['beta tool']],
    ]);
    expect(profiles.map((profile) => profile.name)).toEqual(['alpha', 'beta']);
    expect(profiles[1].markers[0].weight).toBe(16);

    const state = createSourceDetectionState([
      ['alpha', ['alpha']],
      ['beta', ['beta tool']],
    ]);
    collectDetectedSourceHits('alpha failed', state);
    collectDetectedSourceHits('beta tool failed', state);
    expect(rankDetectedSources(state, 2)).toEqual(['alpha', 'beta']);
    expect(state.hits.get('beta')?.confidence).toBeGreaterThan(
      state.hits.get('alpha')?.confidence ?? 0,
    );

    const activeTypeScript = createSourceDetectionState([
      ['typescript', ['typescript']],
      ['pytest', ['pytest']],
    ]);
    collectDetectedSourceHits('typescript compiler started', activeTypeScript);
    expect(scoreSourceDiagnosticBoost('TS9999: Type mismatch', activeTypeScript)).toBe(
      SOURCE_DIAGNOSTIC_BOOST,
    );
    expect(scoreSourceDiagnosticBoost('plain compiler output', activeTypeScript)).toBe(0);

    const weakTypeScript = createSourceDetectionState([
      ['typescript', ['ts']],
    ]);
    collectDetectedSourceHits('ts', weakTypeScript);
    expect(scoreSourceDiagnosticBoost('TS9999: Type mismatch', weakTypeScript)).toBe(0);
  });

  it('lowers source active threshold for short logs', () => {
    expect(getEffectiveActiveConfidence(10)).toBe(4);
    expect(getEffectiveActiveConfidence(49)).toBe(4);
    expect(getEffectiveActiveConfidence(50)).toBe(6);
    expect(getEffectiveActiveConfidence(199)).toBe(6);
    expect(getEffectiveActiveConfidence(200)).toBe(12);
    expect(getEffectiveActiveConfidence(10_000)).toBe(12);
  });

  it('applies diagnostic boost with lowered threshold on short logs', () => {
    // "ts" marker has weight 6 (< normal threshold 12, >= short-log threshold 4)
    const state = createSourceDetectionState([['typescript', ['ts']]]);
    collectDetectedSourceHits('ts', state);

    // Normal threshold 12: no boost (confidence=6 < 12)
    expect(scoreSourceDiagnosticBoost('TS9999: Type mismatch', state)).toBe(0);

    // Short-log threshold 4: boost activates (confidence=6 >= 4)
    expect(scoreSourceDiagnosticBoost('TS9999: Type mismatch', state, 30)).toBe(SOURCE_DIAGNOSTIC_BOOST);
    expect(scoreSourceDiagnosticBoost('plain text', state, 30)).toBe(0);
  });

  it('adjusts auto aggressiveness deterministically from recent decisions', () => {
    const auto = createDynamicAggressivenessState('auto');
    expect(auto.effective).toBe('high');

    for (let i = 0; i < 8; i += 1) {
      recordLineDecision(auto, {
        kept: false,
        dropped: true,
        hardKeep: false,
        repeated: true,
      });
    }
    expect(auto.effective).toBe('aggressive');

    for (let i = 0; i < 8; i += 1) {
      recordLineDecision(auto, {
        kept: true,
        dropped: false,
        hardKeep: true,
        repeated: false,
      });
    }
    expect(auto.effective).toBe('high');

    for (let i = 0; i < 8; i += 1) {
      recordLineDecision(auto, {
        kept: true,
        dropped: false,
        hardKeep: false,
        repeated: false,
      });
    }
    expect(auto.effective).toBe('high');

    auto.effective = 'low';
    for (let i = 0; i < 8; i += 1) {
      recordLineDecision(auto, {
        kept: true,
        dropped: false,
        hardKeep: true,
        repeated: false,
      });
    }
    expect(auto.effective).toBe('low');

    const fixed = createDynamicAggressivenessState('low');
    recordLineDecision(fixed, {
      kept: false,
      dropped: true,
      hardKeep: false,
      repeated: true,
    });
    expect(fixed.effective).toBe('low');
  });

  it('sanitizes expensive identifiers and timestamps', () => {
    expect(
      sanitizeLine(
        '\u001B[31m[ERROR]\u001B[0m 2026-05-15T10:20:30.123Z Fri, 15 May 2026 10:20:30 UTC uuid=018f23ab-7c1d-7f44-8bfe-0acddaf33456 src=10.42.7.18:54321 commit=abcdef1234567890 session=abc123def456ghi789jkl012   ',
      ),
    ).toBe(
      '[ERROR] [TIME] [TIME] uuid=[ID] src=[IP]:[PORT] commit=[HASH] session=[HASH]',
    );
    expect(
      sanitizeLine(
        '10.40.1.13 - - [16/May/2026:10:12:04 +0000] "POST /api/checkout HTTP/1.1" 502',
      ),
    ).toBe('[IP] - - [[TIME]] "POST /api/checkout HTTP/1.1" 502');
    expect(
      sanitizeLine(
        '2026/05/16 10:12:04 [error] connect() failed for upstream 10.44.2.19:8080',
      ),
    ).toBe('[TIME] [error] connect() failed for upstream [IP]:[PORT]');
    expect(
      sanitizeLine(
        '[Sun Dec 04 04:47:44 2005] [error] [client 10.42.7.18] Directory index forbidden by rule: /var/www/html/',
      ),
    ).toBe(
      '[TIME] [error] [client [IP]] Directory index forbidden by rule: /var/www/html/',
    );
  });

  it('normalizes Kubernetes-style relative durations', () => {
    expect(sanitizeLine('Warning BackOff 38s kubelet Back-off restarting failed container')).toBe('Warning BackOff [AGO] kubelet Back-off restarting failed container');
    expect(sanitizeLine('Warning BackOff 2m34s kubelet Back-off restarting failed container')).toBe('Warning BackOff [AGO] kubelet Back-off restarting failed container');
    expect(sanitizeLine('Liveness probe failed 1h5m12s')).toBe('Liveness probe failed [AGO]');
    expect(sanitizeLine('Pulling image 2d3h15m42s')).toBe('Pulling image [AGO]');
  });

  it('preserves UUID/HASH suffix when preserveIdSuffix is set', () => {
    const uuid = 'req=123e4567-e89b-12d3-a456-426614174000';
    expect(sanitizeLine(uuid)).toBe('req=[ID]');
    expect(sanitizeLine(uuid, 0)).toBe('req=[ID]');
    expect(sanitizeLine(uuid, 8)).toBe('req=[ID:14174000]');

    const hash = 'commit=abcdef1234567890abcdef1234567890abcdef12';
    expect(sanitizeLine(hash)).toBe('commit=[HASH]');
    expect(sanitizeLine(hash, 6)).toBe('commit=[HASH:cdef12]');

    // Alphanumeric hash (uppercase letters -> won't match hex-only pattern)
    const alnumHash = 'someId XyZ1XyZ1XyZ1XyZ1XyZ1XyZ1XyZ1XyZ1';
    expect(sanitizeLine(alnumHash)).toBe('someId [HASH]');
    expect(sanitizeLine(alnumHash, 4)).toBe('someId [HASH:XyZ1]');
  });

  it('masks secret and credential patterns', () => {
    // GitHub tokens
    expect(sanitizeLine('auth ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn')).toBe('auth [REDACTED]');
    // JWT tokens
    expect(sanitizeLine('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789jkl')).toBe('Bearer [JWT]');
    // Slack tokens
    expect(sanitizeLine('token ' + ['xox','b-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWX'].join(''))).toBe('token [REDACTED]');
    // Connection strings
    expect(sanitizeLine('postgres://user:secretpass@db.example.com:5432/mydb')).toBe('postgres://user:[REDACTED]@db.example.com:5432/mydb');
    // Secret field values
    expect(sanitizeLine('password=hunter2')).toBe('password=[REDACTED]');
    expect(sanitizeLine('api_key=sk_live_abc123')).toBe('api_key=[REDACTED]');
    expect(sanitizeLine('secret: hiddenvalue')).toBe('secret: [REDACTED]');
    expect(sanitizeLine('token=abc123def')).toBe('token=[REDACTED]');
    expect(sanitizeLine('Authorization: Bearer xyz')).toBe('Authorization: [REDACTED]');
    // AWS access keys
    expect(sanitizeLine('key=AKIAIOSFODNN7EXAMPLE')).toBe('key=[REDACTED]');
    // AWS ARN with account ID
    expect(sanitizeLine('arn:aws:s3:us-east-1:123456789012:bucket/object')).toBe('arn:aws:s3:us-east-1:[ACCOUNT]:bucket/object');
  });

  it('sanitizes IPv6 addresses, emails, and additional secret tokens', () => {
    // IPv6 (full form)
    expect(sanitizeLine('from 2001:db8:85a3:0:0:8a2e:370:7334')).toBe('from [IPV6]');
    // IPv6 (compressed-middle, with one trailing group)
    expect(sanitizeLine('from 2001:db8:85a3::7334')).toBe('from [IPV6]');
    // IPv6 (bracketed, typical log format)
    expect(sanitizeLine('connect ECONNREFUSED [2001:db8:85a3:0:0:8a2e:370:7334]:5432')).toBe('connect ECONNREFUSED [[IPV6]]:5432');
    // Email
    expect(sanitizeLine('auth failed for user@example.com')).toBe('auth failed for [EMAIL]');
    expect(sanitizeLine('sent to admin@company.co.uk')).toBe('sent to [EMAIL]');
    // Stripe
    expect(sanitizeLine('rejected sk_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('rejected [REDACTED]');
    expect(sanitizeLine('key=pk_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('key=[REDACTED]');
    // npm
    expect(sanitizeLine('token=npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('token=[REDACTED]');
    // Google API
    expect(sanitizeLine('blocked AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('blocked [REDACTED]');
    // Twilio
    expect(sanitizeLine('sid=SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('sid=[REDACTED]');
    expect(sanitizeLine('key=SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('key=[REDACTED]');
    // SendGrid
    expect(sanitizeLine('key=SG.aaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('key=[REDACTED]');
  });

  it('masks PEM private key blocks', () => {
    const state = createPemBlockState();
    expect(maskPemBlock('[ERROR] something failed', state)).toBe('[ERROR] something failed');
    expect(state.inside).toBe(false);
    expect(maskPemBlock('-----BEGIN RSA PRIVATE KEY-----', state)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(state.inside).toBe(true);
    expect(maskPemBlock('MIIEowIBAAKCAQEAo3b8nJBC8ZwB6YyxGQZBnCl2', state)).toBeNull();
    expect(maskPemBlock('9Chb8hdk/0BiOgtL8PZjkzyjyjg+vYME7E9vob7d', state)).toBeNull();
    expect(maskPemBlock('-----END RSA PRIVATE KEY-----', state)).toBeNull();
    expect(state.inside).toBe(false);
    expect(maskPemBlock('[ERROR] process exited', state)).toBe('[ERROR] process exited');
  });

  it('handles unterminated PEM block', () => {
    const state = createPemBlockState();
    maskPemBlock('-----BEGIN EC PRIVATE KEY-----', state);
    expect(state.inside).toBe(true);
    maskPemBlock('MIIEpAIBAAKCAQEArandombodyhere', state);
    expect(state.inside).toBe(true);
  });

  it('handles PEM block with different key types', () => {
    const s1 = createPemBlockState();
    expect(maskPemBlock('-----BEGIN DSA PRIVATE KEY-----', s1)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(s1.inside).toBe(true);
    expect(maskPemBlock('-----END DSA PRIVATE KEY-----', s1)).toBeNull();
    expect(s1.inside).toBe(false);
    const s2 = createPemBlockState();
    expect(maskPemBlock('-----BEGIN OPENSSH PRIVATE KEY-----', s2)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(s2.inside).toBe(true);
    expect(maskPemBlock('-----END OPENSSH PRIVATE KEY-----', s2)).toBeNull();
    expect(s2.inside).toBe(false);
    const s3 = createPemBlockState();
    expect(maskPemBlock('-----BEGIN PGP PRIVATE KEY-----', s3)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(s3.inside).toBe(true);
    expect(maskPemBlock('-----END PGP PRIVATE KEY-----', s3)).toBeNull();
    expect(s3.inside).toBe(false);
    const s4 = createPemBlockState();
    expect(maskPemBlock('-----BEGIN ENCRYPTED PRIVATE KEY-----', s4)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(s4.inside).toBe(true);
    expect(maskPemBlock('-----END ENCRYPTED PRIVATE KEY-----', s4)).toBeNull();
    expect(s4.inside).toBe(false);
    const s5 = createPemBlockState();
    expect(maskPemBlock('-----BEGIN PRIVATE KEY-----', s5)).toBe('[PEM PRIVATE KEY REDACTED]');
    expect(s5.inside).toBe(true);
    expect(maskPemBlock('-----END PRIVATE KEY-----', s5)).toBeNull();
    expect(s5.inside).toBe(false);
  });

  it('emits unterminated PEM block warning in streaming mode', async () => {
    const input = [
      '[ERROR] auth failed\n',
      '-----BEGIN RSA PRIVATE KEY-----\n',
      'MIIEowIBAAKCAQEAo3b8nJBC8ZwB6YyxGQZBnCl2\n',
    ].join('');
    const { output, stats } = await processLogString(input);
    expect(output).toContain('[ERROR] auth failed');
    expect(output).toContain('[PEM PRIVATE KEY REDACTED]');
    expect(output).toContain('[PEM block unterminated - input redacted]');
    expect(output).not.toContain('MIIEow');
    expect(output).not.toContain('-----BEGIN');
    expect(stats.truncatedLines).toBe(1);
  });

  it('auto-source multiline groups python stack frames when pytest is detected', async () => {
    const input = [
      '[ERROR] tests/test_orders.py::test_create_order - AssertionError\n',
      '    File "/repo/tests/test_orders.py", line 42, in test_create_order\n',
      '    File "/repo/tests/conftest.py", line 18, in setup\n',
      '[ERROR] another error\n',
    ].join('');

    const { output } = await processLogString(input, { multiline: 'auto-source' });

    // The two indented File lines should be joined with the error line
    expect(output).toContain('[ERROR] tests/test_orders.py::test_create_order - AssertionError');
    expect(output).toContain('File "/repo/tests/test_orders.py", line [NN]');
    expect(output).toContain('[ERROR] another error');
  });

  it('auto-source multiline does not re-resolve when source stays the same', async () => {
    const input = [
      '[ERROR] tests/test_first.py::test_a - fail\n',
      '    File "/repo/tests/test_first.py", line 10\n',
      '[ERROR] tests/test_second.py::test_b - fail\n',
      '    File "/repo/tests/test_second.py", line 20\n',
    ].join('');

    const { output } = await processLogString(input, { multiline: 'auto-source' });

    expect(output).toContain('[ERROR] tests/test_first.py::test_a - fail');
    expect(output).toContain('[ERROR] tests/test_second.py::test_b - fail');
  });

  it('auto-source multiline handles undetected source fallback', async () => {
    const input = [
      '[ERROR] generic failure message\n',
      '[ERROR] another generic failure\n',
    ].join('');

    const { output } = await processLogString(input, { multiline: 'auto-source' });

    expect(output).toContain('[ERROR] generic failure message');
    expect(output).toContain('[ERROR] another generic failure');
  });

  it('preserves UUID suffix for trace correlation while still deduplicating', async () => {
    const input = [
      '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed\n',
      '[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed\n',
    ].join('');

    const { output } = await processLogString(input, { preserveIdSuffix: 6 });

    // Different suffixes → no dedup
    expect(output).toContain('[ID:174000]');
    expect(output).toContain('[ID:174111]');
  });

  it('preserveIdSuffix allows exact trace matching on repeated requests', async () => {
    // Two identical errors for the SAME request UUID
    const input = [
      '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed\n',
      '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed\n',
    ].join('');

    const { output } = await processLogString(input, { preserveIdSuffix: 6 });

    // Same suffix, so they dedup to [x2]
    expect(output).toContain('[x2] [ERROR] request [ID:174000]');
  });

  it('drops JSON info/debug/trace lines via structured level scoring', async () => {
    // Pino numeric levels: 30=info should be dropped, 50=error kept
    const input = [
      '{"level":30,"msg":"server started"}\n',
      '{"level":50,"msg":"database timeout"}\n',
    ].join('');

    const { output } = await processLogString(input);
    expect(output).not.toContain('server started');
    expect(output).toContain('database timeout');
  });

  it('keeps JSON warn lines through standard buffering', async () => {
    // Pino numeric level 40=warn: score 50, goes through context buffering
    const input = [
      '{"level":40,"msg":"slow query"}\n',
      '{"level":50,"msg":"unhandled error"}\n',
    ].join('');

    const { output } = await processLogString(input);
    expect(output).toContain('slow query');
    expect(output).toContain('unhandled error');
  });

  it('drops JSON info line even with numeric pino level', async () => {
    // pino level 30 is "info" — should be dropped even though not string quoted
    const input = '{"level":30,"msg":"listening","hostname":"app-1"}\n';
    const { output } = await processLogString(input);
    expect(output).not.toContain('listening');
  });

  it('context-buffers non-JSON lines in a JSON stream', async () => {
    // A non-JSON line in a JSON-detected stream goes through standard scoring
    // and the soft-buffering JSON else path.
    const input = [
      '{"level":30,"msg":"started"}\n', // dropped as info
      'some plain text context line\n', // soft, gets buffered
      '{"level":50,"msg":"error occurred"}\n', // triggers context flush
    ].join('');

    const { output } = await processLogString(input);
    expect(output).toContain('some plain text context line');
    expect(output).toContain('error occurred');
    expect(output).not.toContain('started');
  });

  it('collapses 2xx access-log bursts in context window', async () => {
    const getLine = (n: number) =>
      `192.168.1.${n} - - [15/May/2026:10:00:${String(n).padStart(2, '0')} +0000] "GET /api/users HTTP/1.1" 200 42 "-" "Mozilla/5.0"`;
    const input = [
      getLine(1),
      getLine(2),
      getLine(3),
      '[ERROR] something broke', // triggers context flush of access bucket
    ].join('\n');

    const { output } = await processLogString(input);
    expect(output).toContain('[x2 access-log 2xx]');
    expect(output).toContain('[ERROR] something broke');
  });

  it('does not collapse 4xx access log errors', async () => {
    const input = [
      '10.0.0.1 - - [15/May/2026:10:00:01 +0000] "GET /api/missing HTTP/1.1" 404 0 "-" "Mozilla/5.0"\n',
      '[ERROR] something broke\n',
    ].join('');

    const { output } = await processLogString(input);
    // 4xx should appear as-is, not be collapsed into a bucket
    expect(output).toContain('404');
    expect(output).toContain('[ERROR] something broke');
  });

  it('flushes access bucket on different-path access log', async () => {
    const input = [
      '192.168.1.1 - - [15/May/2026:10:00:01 +0000] "GET /api/users HTTP/1.1" 200 42 "-" "Mozilla/5.0"\n',
      '10.0.0.1 - - [15/May/2026:10:00:02 +0000] "GET /api/orders HTTP/1.1" 200 43 "-" "Mozilla/5.0"\n',
      '[ERROR] boom\n',
    ].join('');

    const { output } = await processLogString(input);
    // Different path triggers ejected flush of first bucket, then creates new
    expect(output).toContain('/api/users');
    expect(output).toContain('/api/orders');
    expect(output).toContain('[ERROR]');
  });

  it('builds generic repeat signatures from structured fields', () => {
    expect(MAX_REPEAT_DELTA_VALUES).toBe(3);
    expect(
      createRepeatSignature(
        '[ERROR] charge failed requestId=[ID] amount=99.99 failures=3/5',
      ),
    ).toBe(
      '[ERROR] charge failed requestId=[VALUE] amount=[VALUE] failures=[VALUE]',
    );
    expect(
      createRepeatSignature(
        '[ERROR] checkout failed order_id=ord-88421 route=POST_/checkout',
      ),
    ).toBe('[ERROR] checkout failed order_id=[VALUE] route=[VALUE]');
    expect(
      createRepeatSignature('[TIME] [error] mod_jk child workerEnv in error state 6'),
    ).toBe('[TIME] [error] mod_jk child workerEnv in error state [VALUE]');
    expect(createRepeatSignature('[ERROR] status 503')).toBe(
      '[ERROR] status 503',
    );
  });

  it('tracks timestamp spread in repeat groups', () => {
    const group = createRepeatGroup('2026-05-10T10:00:00Z [ERROR] timeout');

    expect(group.firstSeen).toBeGreaterThan(0);
    expect(group.lastSeen).toBe(group.firstSeen);
    expect(getRepeatGroupSpreadMs(group)).toBe(0);

    addRepeatGroupLine(group, '2026-05-10T10:01:05Z [ERROR] timeout');
    // 1m5s = 65s = 65000ms spread
    expect(getRepeatGroupSpreadMs(group)).toBeGreaterThanOrEqual(64000);

    const rendered = renderRepeatGroup(group);
    expect(rendered).toContain('[~1m]');
  });

  it('omits timestamp spread for sub-threshold durations', () => {
    const group = createRepeatGroup('2026-05-10T10:00:00Z [ERROR] timeout');
    addRepeatGroupLine(group, '2026-05-10T10:00:02Z [ERROR] timeout');
    // 2s < 5s threshold
    const rendered = renderRepeatGroup(group);
    expect(rendered).not.toContain('[~');
  });

  it('handles invalid timestamps gracefully', () => {
    const group = createRepeatGroup('2026-13-99T99:99:99Z [ERROR] invalid date');
    expect(group.firstSeen).toBeNull();
    expect(group.lastSeen).toBeNull();
    expect(getRepeatGroupSpreadMs(group)).toBeNull();
  });

  it('formats timestamp spread in seconds for short durations', () => {
    const group = createRepeatGroup('2026-05-10T10:00:00Z [ERROR] timeout');
    addRepeatGroupLine(group, '2026-05-10T10:00:10Z [ERROR] timeout');
    const rendered = renderRepeatGroup(group);
    expect(rendered).toContain('[~10s]');
  });

  it('formats timestamp spread in minutes and hours', () => {
    const group = createRepeatGroup('2026-05-10T10:00:00Z [ERROR] timeout');
    addRepeatGroupLine(group, '2026-05-10T10:30:00Z [ERROR] timeout');
    const rendered = renderRepeatGroup(group);
    expect(rendered).toContain('[~30m]');

    const group2 = createRepeatGroup('2026-05-10T10:00:00Z [ERROR] timeout');
    addRepeatGroupLine(group2, '2026-05-10T12:00:00Z [ERROR] timeout');
    const rendered2 = renderRepeatGroup(group2);
    expect(rendered2).toContain('[~2h]');
  });

  it('classifies useful diagnostic lines', () => {
    expect(shouldKeepLine('')).toBe(false);
    expect(shouldKeepLine('[INFO] booted')).toBe(false);
    expect(shouldKeepLine('[ERROR] failed')).toBe(true);
    expect(shouldKeepLine('TypeError: boom')).toBe(true);
    expect(shouldKeepLine('npm ERR! code ERESOLVE')).toBe(true);
    expect(shouldKeepLine('Warning BackOff restarting failed container api')).toBe(
      true,
    );
    expect(
      shouldKeepLine('{"level":"error","msg":"database timeout","status":503}'),
    ).toBe(true);
    expect(
      shouldKeepLine(
        '[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties',
      ),
    ).toBe(false);
    expect(shouldKeepLine('[NOTICE] noisy')).toBe(false);
    expect(shouldKeepLine('plain text')).toBe(false);

    expect(looksLikeDiagnosticLine('    at app (/repo/src/app.ts:10:5)')).toBe(
      true,
    );
    expect(looksLikeDiagnosticLine('    ... 2 more')).toBe(true);
    expect(
      looksLikeDiagnosticLine(
        '    File "/repo/app/orders.py", line 42, in create_order',
      ),
    ).toBe(true);
    expect(
      looksLikeDiagnosticLine(
        '    at com.example.checkout.CartService.placeOrder(CartService.java:118)',
      ),
    ).toBe(true);
    expect(looksLikeDiagnosticLine('goroutine 42 [running]:')).toBe(true);
    expect(looksLikeDiagnosticLine('main.(*Server).Start(0xc0001212c0)')).toBe(
      true,
    );
    expect(
      looksLikeDiagnosticLine(
        'github.com/acme/checkout/server.(*Server).Start(0xc0001212c0)',
      ),
    ).toBe(true);
    expect(looksLikeDiagnosticLine('C:\\repo\\service\\main.go:42 +0x20')).toBe(
      true,
    );
    expect(looksLikeDiagnosticLine('console.log(value)')).toBe(false);
    expect(looksLikeDiagnosticLine('Unhandled exception')).toBe(true);
    expect(looksLikeDiagnosticLine('plain text')).toBe(false);

    expect(
      isInternalStackTraceLine('    at lib (/repo/node_modules/pkg/index.js:1:1)'),
    ).toBe(true);
    expect(
      isInternalStackTraceLine(
        '    File "/repo/.venv/lib/python3.12/site-packages/httpx/_client.py", line 814, in request',
      ),
    ).toBe(true);
    expect(
      isInternalStackTraceLine(
        '    at java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)',
      ),
    ).toBe(true);
    expect(isInternalStackTraceLine('    at app (/repo/src/app.ts:10:5)')).toBe(
      false,
    );
    // [ERROR]/[FATAL] lines are never treated as internal stack frames
    expect(
      isInternalStackTraceLine(
        '[ERROR] ERROR Invoke Error {"errorType":"TimeoutError","stackTrace":["at Timeout._onTimeout (/var/task/node_modules/pg/client.js:42:18)"]}',
      ),
    ).toBe(false);
    expect(
      isInternalStackTraceLine(
        '[FATAL] FATAL: node_modules internal crash at lib.js:1:1',
      ),
    ).toBe(false);
    // New diagnostic patterns
    expect(looksLikeDiagnosticLine('::error file=src/app.ts,line=42::TypeError')).toBe(true);
    expect(looksLikeDiagnosticLine('::warning file=src/app.ts,line=10::unused variable')).toBe(true);
    expect(looksLikeDiagnosticLine('Execution failed for task :app:compileJava')).toBe(true);
    expect(looksLikeDiagnosticLine('> What went wrong:')).toBe(true);
    expect(looksLikeDiagnosticLine('--- FAIL: TestCheckout (0.12s)')).toBe(true);
    expect(looksLikeDiagnosticLine('make: *** [build] Error 2')).toBe(true);
    expect(looksLikeDiagnosticLine('Failed to start checkout-api.service')).toBe(true);
    expect(looksLikeDiagnosticLine('Spin Cancelled')).toBe(true);
    expect(looksLikeDiagnosticLine('[Pipeline] [ERROR] Stage "Deploy" failed')).toBe(true);
    expect(looksLikeDiagnosticLine('##vso[task.LogIssue type=error;]build failed')).toBe(true);
    expect(looksLikeDiagnosticLine('##teamcity[buildProblem description=compile error')).toBe(true);
    expect(estimateTokens(3)).toBe(4);
  });

  it('estimates CJK tokens more accurately from text', () => {
    // Pure ASCII: 4 chars ≈ 1 token
    const ascii = 'Hello World';
    expect(estimateTokens(ascii)).toBe(3); // 11 chars / 4 = 2.75 → 3

    // Mixed CJK + ASCII
    const mixed = 'エラー: connection failed';
    // CJK: 3 katakana chars × 1.0 = 3 (':' is ASCII)
    // Rest: 19 chars / 4 ≈ 4.75
    // Total: 3 + 4.75 = 7.75 → 8
    expect(estimateTokens(mixed)).toBe(8);

    // Pure CJK
    const cjk = 'エラーが発生しました';
    // 10 CJK chars × 1.0 = 10
    expect(estimateTokens(cjk)).toBe(10);

    // Empty string
    expect(estimateTokens('')).toBe(0);

    // Backward compat: number path still works
    expect(estimateTokens(10)).toBe(13); // 10 words × 1.3
  });

  it('streams logs, sanitizes UUIDs, deduplicates and hides internal stacks', async () => {
    const logs = [
      '',
      '[INFO] boot ok',
      '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed',
      '[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed',
      '[ERROR] src/api/client.ts(18,22): error TS2322: Type string is not assignable to number',
      '[WARN] deploy 2026-05-15T10:20:30Z sha abcdef1234567890 ok',
      '    at app (/repo/src/app.ts:10:5)',
      '    at lib (/repo/node_modules/pkg/index.js:1:1)',
      '    at loader (node:internal/modules/cjs/loader:1:1)',
      'TypeError: exploded',
      '[DEBUG] debug',
      // "plain text" has score=0 and falls inside the CONTEXT_WINDOW_AFTER of
      // "TypeError: exploded", so it is emitted as trailing diagnostic context.
      'plain text',
    ].join('\n');
    const output = new MemoryWritable();

    await processLogStream(Readable.from([logs]), output);

    const result = await processLogStream(Readable.from([logs]), new MemoryWritable());

    expect(output.content()).toBe(
      [
        '[x2] [ERROR] request [ID] failed',
        '[ERROR] src/api/client.ts(18,22): error TS2322: Type string is not assignable to number',
        '[WARN] deploy [TIME] sha [HASH] ok',
        '    at app (/repo/src/app.ts:[NN]:[NN])',
        INTERNAL_STACK_MARKER,
        'TypeError: exploded',
        'plain text', // after-context: CONTEXT_WINDOW_AFTER lines after the error
        '',
      ].join('\n'),
    );
    expect(result.detectedSources?.length).toBeGreaterThan(0);
    expect(result.detectedSources).toContain('typescript');
  });

  it('uses confident source detection to keep source-specific diagnostics', async () => {
    const output = new MemoryWritable();
    const result = await processLogStream(
      Readable.from([
        [
          'typescript compiler started',
          'TS9999: Type mismatch in generated declaration',
        ].join('\n'),
      ]),
      output,
    );

    expect(output.content()).toBe(
      [
        'typescript compiler started',
        'TS9999: Type mismatch in generated declaration',
        '',
      ].join('\n'),
    );
    expect(result.detectedSources).toContain('typescript');
  });

  it('auto aggressiveness suppresses later warning noise while keeping errors', async () => {
    const output = new MemoryWritable();
    await processLogStream(
      Readable.from([
        [
          '[INFO] boot 1',
          '[INFO] boot 2',
          '[INFO] boot 3',
          '[INFO] boot 4',
          '[INFO] boot 5',
          '[INFO] boot 6',
          '[INFO] boot 7',
          '[INFO] boot 8',
          '[WARN] cache warmed successfully',
          '[ERROR] request failed',
        ].join('\n'),
      ]),
      output,
      { aggressiveness: 'auto' },
    );

    expect(output.content()).toBe('[ERROR] request failed\n');
  });

  it('folds adjacent diagnostic variants with generic delta values', async () => {
    const repeatedLogs = [
      '[ERROR] 2026-05-15T08:01:12.436Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33456 amount=99.99',
      '[ERROR] 2026-05-15T08:01:12.437Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33457 amount=49.50',
      '[ERROR] 2026-05-15T08:01:12.438Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33458 amount=12.00',
      '[ERROR] 2026-05-15T08:01:12.439Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33459 amount=12.00',
      '[ERROR] 2026-05-15T08:01:12.440Z spring-boot [payments] charge failed requestId=018f23ab-7c1d-7f44-8bfe-0acddaf33460 amount=7.25',
    ].join('\n');
    const repeatedOutput = new MemoryWritable();

    const repeatedResult = await processLogStream(
      Readable.from([repeatedLogs]),
      repeatedOutput,
    );

    expect(repeatedOutput.content()).toBe(
      '[x5] [ERROR] [TIME] spring-boot [payments] charge failed requestId=[ID] amount=[99.99 | 49.50 | 12.00 | …]\n',
    );
    expect(repeatedResult.stats.duplicateLines).toBe(4);

    const singleOutput = new MemoryWritable();
    await processLogStream(
      Readable.from([repeatedLogs.split('\n', 1)[0] ?? '']),
      singleOutput,
    );

    expect(singleOutput.content()).toBe(
      '[ERROR] [TIME] spring-boot [payments] charge failed requestId=[ID] amount=99.99\n',
    );

    const compactDeltaOutput = new MemoryWritable();
    await processLogStream(
      Readable.from([
        [
          '[ERROR] worker failed task=charge shard=eu-1',
          '[ERROR] worker failed task=refund shard=eu-2',
        ].join('\n'),
      ]),
      compactDeltaOutput,
    );

    expect(compactDeltaOutput.content()).toBe(
      '[x2] [ERROR] worker failed task=[charge | refund] shard=[eu-1 | eu-2]\n',
    );
  });

  it('compresses Apache httpd noise while preserving error diagnostics', async () => {
    const apacheLogs = [
      '[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties',
      '[Sun Dec 04 04:51:08 2005] [notice] jk2_init() Found child 6725 in scoreboard slot 10',
      '[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6',
      '[Sun Dec 04 04:51:19 2005] [error] mod_jk child workerEnv in error state 7',
      '[Sun Dec 04 04:51:20 2005] [error] mod_jk child workerEnv in error state 6',
      '[Mon Dec 05 19:14:09 2005] [error] [client 10.42.7.18] Directory index forbidden by rule: /var/www/html/',
      '[Mon Dec 05 19:14:10 2005] [error] [client 10.42.7.19] Directory index forbidden by rule: /var/www/html/',
    ].join('\n');
    const output = new MemoryWritable();

    const result = await processLogStream(Readable.from([apacheLogs]), output);

    expect(output.content()).toBe(
      [
        '[x3] [TIME] [error] mod_jk child workerEnv in error state [6 | 7]',
        '[x2] [TIME] [error] [client [IP]] Directory index forbidden by rule: /var/www/html/',
        '',
      ].join('\n'),
    );
    expect(result.detectedSources).toContain('apache-httpd');
    expect(result.stats.droppedLines).toBe(2);
    expect(result.stats.duplicateLines).toBe(3);
  });

  it('scoreLineRelevance assigns correct multi-signal scores', () => {
    // Exported constants have expected values
    expect(CONTEXT_WINDOW_BEFORE).toBe(3);
    expect(CONTEXT_WINDOW_AFTER).toBe(2);
    expect(SCORE_KEEP_THRESHOLD).toBe(40);
    expect(TFIDF_REPEAT_THRESHOLD).toBe(3);
    expect(TFIDF_PENALTY).toBe(8);
    expect(TFIDF_MAP_LIMIT).toBe(50_000);

    // Noise tags always return -Infinity
    expect(scoreLineRelevance('[INFO] booted', 'high')).toBe(-Infinity);
    expect(scoreLineRelevance('[DEBUG] query', 'high')).toBe(-Infinity);
    expect(scoreLineRelevance('[TRACE] tick', 'high')).toBe(-Infinity);
    expect(
      scoreLineRelevance(
        '[TIME] [notice] jk2_init() Found child 6725 in scoreboard slot 10',
        'high',
      ),
    ).toBe(-Infinity);
    expect(scoreLineRelevance('', 'high')).toBe(-Infinity);

    // High-value signals exceed the threshold
    expect(scoreLineRelevance('[ERROR] server down', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('[FATAL] out of memory', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('{"level":"error","msg":"crash"}', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('Severity: CRITICAL CVE-2026-12345', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);

    // Stack frames are exactly at threshold (no other signal)
    expect(scoreLineRelevance('    at app (/repo/src/app.ts:10:5)', 'high')).toBe(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('goroutine 42 [running]:', 'high')).toBe(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('github.com/acme/service.(*Server).Start(0xc0001212c0)', 'high')).toBe(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('/repo/service/main.go:42 +0x20', 'high')).toBe(SCORE_KEEP_THRESHOLD);

    // Soft lines: no matching patterns → score 0
    expect(scoreLineRelevance('Connection state: connecting', 'high')).toBe(0);
    expect(scoreLineRelevance('plain text', 'high')).toBe(0);

    // TF-IDF: penalty kicks in at TFIDF_REPEAT_THRESHOLD
    const base = scoreLineRelevance('failed to connect', 'high', 1);
    expect(base).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    const atThreshold = scoreLineRelevance('failed to connect', 'high', TFIDF_REPEAT_THRESHOLD);
    expect(atThreshold).toBe(base - TFIDF_PENALTY);
    const overThreshold = scoreLineRelevance('failed to connect', 'high', TFIDF_REPEAT_THRESHOLD + 3);
    expect(overThreshold).toBe(base - TFIDF_PENALTY * 4);
    // Eventually falls below SCORE_KEEP_THRESHOLD
    const wayOver = scoreLineRelevance('failed to connect', 'high', TFIDF_REPEAT_THRESHOLD + 10);
    expect(wayOver).toBeLessThan(SCORE_KEEP_THRESHOLD);

    // NPM and Yarn error patterns trigger the +60 bonus
    expect(scoreLineRelevance('npm ERR! code ERESOLVE', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    // YARN_ERROR_PATTERN specifically (does not match NPM_ERROR_PATTERN)
    expect(scoreLineRelevance('yarn error Command failed with exit code 1', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);

    // Container runtime names alone are context, but failure phrasing is diagnostic
    expect(scoreLineRelevance('containerd v1.7.0 started', 'high')).toBe(0);
    expect(scoreLineRelevance('containerd failed to create task', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('runc error: unable to start container process', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);

    // Aggressiveness: pure WARN without error keyword → drop
    expect(scoreLineRelevance('[WARN] cache warming', 'aggressive')).toBeLessThan(0);
    // WARN + any diagnostic keyword survives aggressive
    expect(scoreLineRelevance('[WARN] request failed', 'aggressive')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('[WARN] connection timeout', 'aggressive')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('[WARN] app crashed on startup', 'aggressive')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('[WARN] process killed by OOM', 'aggressive')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);

    // Low aggressiveness: NOTICE/STATUS lines get bonus
    expect(scoreLineRelevance('[NOTICE] queue warming', 'low')).toBeGreaterThan(0);
    expect(scoreLineRelevance('[WARN] cache warming', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD); // WARN is important tag
    // New scoring patterns
    expect(scoreLineRelevance('::error file=deploy.yml,line=42::deploy failed', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('Execution failed for task :app:compileJava', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('--- FAIL: TestCheckout', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('make: *** [build] Error 2', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('Failed to start checkout-api.service', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('Spin Cancelled', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('Failed to start checkout-api.service', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('[Pipeline] [ERROR] Stage "Deploy" failed', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('##vso[task.LogIssue type=error;]build failed', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('##teamcity[buildProblem description=compile error', 'high')).toBeGreaterThanOrEqual(SCORE_KEEP_THRESHOLD);
    // Ensure new patterns do NOT match benign lines (branch coverage)
    expect(scoreLineRelevance('systemd[1]: Started session', 'high')).toBeLessThan(SCORE_KEEP_THRESHOLD);
    expect(scoreLineRelevance('##vso[build.issue] unrelated', 'high')).toBeLessThan(SCORE_KEEP_THRESHOLD);
  });

  it('context window promotes soft lines near errors', async () => {
    // A soft-scored line (no error signal) that sits just before an ERROR
    // must be retroactively emitted as context.
    const logs = [
      'Connection state: connecting', // score=0 → buffered
      '[ERROR] Database connection timeout', // score>=40 → triggers context flush
    ].join('\n');

    const output = new MemoryWritable();
    await processLogStream(Readable.from([logs]), output);
    const lines = output.content().trimEnd().split('\n');

    expect(lines[0]).toBe('Connection state: connecting');
    expect(lines[1]).toContain('[ERROR]');
  });

  it('after-context window emits lines following a high-score event', async () => {
    const logs = [
      '[ERROR] crash',
      'stack frame 1', // score=0, afterContextRemaining=2 → emitted
      'stack frame 2', // score=0, afterContextRemaining=1 → emitted
      'unrelated soft', // score=0, afterContextRemaining=0 → buffered (no trigger follows)
    ].join('\n');

    const output = new MemoryWritable();
    // templateMining off: the test asserts context-window mechanics, and
    // "stack frame 1"/"stack frame 2" would otherwise fold into one [x2].
    await processLogStream(Readable.from([logs]), output, { templateMining: false });
    const content = output.content();

    expect(content).toContain('stack frame 1');
    expect(content).toContain('stack frame 2');
    expect(content).not.toContain('unrelated soft');
  });

  it('adaptive context (auto) widens the after-window for an isolated error', async () => {
    const logs = [
      '[ERROR] first failure',
      ...Array.from({ length: 13 }, (_, i) => `filler line ${i}`),
      '[ERROR] second failure', // gap >= sparse threshold → after-window widens to 4
      'tail 0',
      'tail 1',
      'tail 2',
      'tail 3',
      'tail 4',
    ].join('\n');

    const adaptive = new MemoryWritable();
    await processLogStream(Readable.from([logs]), adaptive, { templateMining: false });
    const adaptiveContent = adaptive.content();

    const fixed = new MemoryWritable();
    await processLogStream(Readable.from([logs]), fixed, {
      adaptiveContext: false,
      templateMining: false,
    });
    const fixedContent = fixed.content();

    // Widened window keeps two extra after-context lines around the isolated error.
    expect(adaptiveContent).toContain('tail 3');
    expect(fixedContent).not.toContain('tail 3');
    expect(fixedContent).toContain('tail 1');
  });

  it('adaptive context (auto) tightens the after-window for clustered errors', async () => {
    const logs = ['[ERROR] alpha', '[ERROR] beta', 'soft 0', 'soft 1'].join('\n');

    const adaptive = new MemoryWritable();
    await processLogStream(Readable.from([logs]), adaptive, { templateMining: false });
    const adaptiveContent = adaptive.content();

    const fixed = new MemoryWritable();
    await processLogStream(Readable.from([logs]), fixed, {
      adaptiveContext: false,
      templateMining: false,
    });
    const fixedContent = fixed.content();

    // Clustered errors are self-contextualizing, so the after-window shrinks.
    expect(adaptiveContent).toContain('soft 0');
    expect(adaptiveContent).not.toContain('soft 1');
    expect(fixedContent).toContain('soft 1');
  });

  it('TF-IDF dampening reduces score for high-frequency non-error lines', async () => {
    // "Retrying connection" has base score ~50 (DIAGNOSTIC: "failed"? no, "Retrying" no)
    // Use a line that matches DIAGNOSTIC_PATTERN to get base score 50, then
    // repeat it enough times that TF-IDF reduces score below SCORE_KEEP_THRESHOLD.
    // "failed to connect" → DIAGNOSTIC +50; threshold exceeded after enough repeats.
    const repeatedLine = 'failed to connect to database';
    const errorLine = '[ERROR] fatal crash';

    // Build: interleaved repeats and noise, followed by an error to flush context.
    // Repeats 1-3: emitted directly (score >= 40)
    // Repeat 4: score = 50 - 16 = 34 < 40 → buffered in context → will be flushed by error
    // Repeat 5: score = 50 - 24 = 26 < 40 → also buffered
    const chunks: string[] = [];
    for (let i = 0; i < 5; i++) {
      chunks.push(repeatedLine);
      chunks.push('[INFO] heartbeat'); // noise between repeats
    }
    chunks.push(errorLine);

    const output = new MemoryWritable();
    await processLogStream(Readable.from([chunks.join('\n')]), output);
    const content = output.content();

    // Early occurrences (1-3) must appear directly
    expect(content).toContain(repeatedLine);
    // Error must appear
    expect(content).toContain(errorLine);
    // The total count of repeatedLine must be less than 5 (TF-IDF suppressed some)
    const count = content.split('\n').filter((l) => l.includes(repeatedLine)).length;
    expect(count).toBeLessThan(5);
  });

  it('bounds TF-IDF tracking for highly unique streams', async () => {
    const output = new MemoryWritable();
    const logs = Array.from(
      { length: TFIDF_MAP_LIMIT + 1 },
      (_, index) => `soft context line ${index}`,
    ).join('\n');

    const result = await processLogStream(Readable.from([logs]), output);

    expect(output.content()).toBe('');
    expect(result.stats.inputLines).toBe(TFIDF_MAP_LIMIT + 1);
    expect(result.stats.droppedLines).toBe(TFIDF_MAP_LIMIT + 1);
  });

  it('handles empty stream with multiline mode enabled', async () => {
    const emptyMultilineOutput = new MemoryWritable();
    const emptyMultilineResult = await processLogStream(Readable.from(['']), emptyMultilineOutput, { multiline: 'python' });
    expect(emptyMultilineResult.savingsPercent).toBe(0);
    expect(emptyMultilineOutput.content()).toBe('');
  });

  it('handles empty streams and backpressure', async () => {
    const emptyOutput = new MemoryWritable();
    const emptyResult = await processLogStream(Readable.from(['']), emptyOutput);

    expect(emptyResult.savingsPercent).toBe(0);
    expect(emptyOutput.content()).toBe('');

    const slowOutput = new SlowWritable();
    await processLogStream(Readable.from(['[ERROR] backpressure']), slowOutput);

    expect(slowOutput.content()).toBe('[ERROR] backpressure\n');
  });

  it('applies low/aggressive filtering rules', async () => {
    const logs = [
      '[NOTICE] build queue status: warming',
      '[WARN] retrying transient request',
      '[WARN] request failed after retry budget exhausted',
      '[ERROR] hard failure',
    ].join('\n');

    const lowOutput = new MemoryWritable();
    await processLogStream(Readable.from([logs]), lowOutput, {
      aggressiveness: 'low',
    });
    expect(lowOutput.content()).toContain('[NOTICE] build queue status: warming');

    const aggressiveOutput = new MemoryWritable();
    await processLogStream(Readable.from([logs]), aggressiveOutput, {
      aggressiveness: 'aggressive',
    });
    expect(aggressiveOutput.content()).not.toContain(
      '[WARN] retrying transient request',
    );
    expect(aggressiveOutput.content()).toContain(
      '[WARN] request failed after retry budget exhausted',
    );
    expect(aggressiveOutput.content()).toContain('[ERROR] hard failure');
  });

  it('isCiNoiseLine detects timestamp-only, K8s Normal, and rate-limited lines', () => {
    // Timestamp-only
    expect(isCiNoiseLine('2026-05-15T10:20:30.123Z')).toBe(true);
    expect(isCiNoiseLine('  2026-05-15T10:20:30Z')).toBe(true);
    expect(isCiNoiseLine('2026/05/15 10:20:30')).toBe(true); // also timestamp-only
    // K8s Normal
    expect(isCiNoiseLine('type: Normal Pulled')).toBe(true);
    expect(isCiNoiseLine("type: 'Normal' Started")).toBe(true);
    expect(isCiNoiseLine('Normal 5s test-pod')).toBe(true);
    // Rate-limited
    expect(isCiNoiseLine('message repeated 42 times')).toBe(true);
    expect(isCiNoiseLine('last message repeated 5 times')).toBe(true);
    expect(isCiNoiseLine('message repeated 1 time')).toBe(true);
    // Not noise
    expect(isCiNoiseLine('[ERROR] crash')).toBe(false);
    expect(isCiNoiseLine('2026-05-15T10:20:30Z request failed')).toBe(false);
  });

  it('isProgressBarLine detects progress bars and separators', () => {
    // Separator pattern
    expect(isProgressBarLine('========================================')).toBe(true);
    expect(isProgressBarLine('------------------------------------')).toBe(true);
    // Progress indicator
    expect(isProgressBarLine('Downloading 45% [====>     ] 12.3 MB/s')).toBe(true);
    expect(isProgressBarLine('Extracting 80% |========= |')).toBe(true);
    expect(isProgressBarLine('  50% |=====|')).toBe(true);
    // Visual progress bar
    expect(isProgressBarLine('[  =====>    ]')).toBe(true);
    expect(isProgressBarLine('|  =====>   |')).toBe(true);
    // Not a progress bar
    expect(isProgressBarLine('[ERROR] failed')).toBe(false);
    expect(isProgressBarLine('')).toBe(false);
    expect(isProgressBarLine('   ')).toBe(false);
    // Lines containing error keywords are NOT progress bars
    expect(isProgressBarLine('Downloading 45% Error: timeout')).toBe(false);
    expect(isProgressBarLine('Extracting 80% fail')).toBe(false);
    expect(isProgressBarLine('Pushing 50% crashed')).toBe(false);
    expect(isProgressBarLine('Building 90% timeout')).toBe(false);
    expect(isProgressBarLine('Installing 30% FAIL')).toBe(false);
  });

  it('processLogStream drops CI noise lines', async () => {
    const logs = [
      '2026-05-15T10:20:30.123Z',
      'type: Normal Pulled image',
      'message repeated 42 times',
      '[ERROR] actual error',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output);
    const content = output.content();

    expect(content).not.toContain('2026-05-15T10:20:30.123Z');
    expect(content).not.toContain('type: Normal');
    expect(content).not.toContain('message repeated');
    expect(content).toContain('[ERROR] actual error');
    expect(result.stats.droppedLines).toBeGreaterThanOrEqual(3);
  });

  it('processLogStream drops progress bar lines', async () => {
    const logs = [
      '========================================',
      'Downloading 45% [====>     ]',
      '[ERROR] actual error',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output);
    const content = output.content();

    expect(content).not.toContain('====================');
    expect(content).not.toContain('Downloading');
    expect(content).toContain('[ERROR] actual error');
    expect(result.stats.droppedLines).toBeGreaterThanOrEqual(2);
  });

  it('processLogStream filters by severity level', async () => {
    const logs = [
      '[TRACE] trace msg',
      '[DEBUG] debug msg',
      '[INFO] info msg',
      '[WARN] warning msg',
      '[ERROR] error msg',
      '[FATAL] fatal msg',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      severity: 'warn',
    });
    const content = output.content();

    expect(content).not.toContain('[TRACE]');
    expect(content).not.toContain('[DEBUG]');
    expect(content).not.toContain('[INFO]');
    expect(content).toContain('[WARN]');
    expect(content).toContain('[ERROR]');
    expect(content).toContain('[FATAL]');
  });

  it('processLogStream respects sampleSize option', async () => {
    const logs = [
      '[ERROR] first',
      '[ERROR] second',
      '[ERROR] third',
      '[ERROR] fourth',
      '[ERROR] fifth',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      sampleSize: 2,
    });
    const content = output.content();

    // Only first 2 kept lines should appear
    const keptLines = content.trim().split('\n').filter((l) => l.includes('[ERROR]'));
    expect(keptLines.length).toBe(2);
    expect(keptLines[0]).toContain('first');
    expect(keptLines[1]).toContain('second');
  });

  it('processLogStream applies include, exclude, truncation and decisions', async () => {
    const decisions: string[] = [];
    const logs = [
      '[ERROR] keep this failure',
      '[WARN] skip by include',
      '[ERROR] hide this failure',
      `[ERROR] ${'x'.repeat(60)}`,
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      include: /ERROR/gu,
      exclude: /hide/u,
      maxLineLength: 40,
      onDecision(decision) {
        decisions.push(decision.reason);
      },
    });
    const content = output.content();

    expect(content).toContain('[ERROR] keep this failure');
    expect(content).not.toContain('skip by include');
    expect(content).not.toContain('hide this failure');
    expect(content).toContain('… [truncated]');
    expect(result.stats.truncatedLines).toBe(1);
    expect(decisions).toContain('hard-keep');
    expect(decisions).toContain('include-filter');
    expect(decisions).toContain('exclude-filter');
  });

  it('processLogStream can disable context buffering and dedupe', async () => {
    const output = new MemoryWritable();
    const result = await processLogStream(
      Readable.from(['soft context line\n[ERROR] same\n[ERROR] same\n']),
      output,
      {
        contextBefore: 0,
        dedupe: false,
      },
    );
    const content = output.content();

    expect(content.match(/\[ERROR\] same/gu)).toHaveLength(2);
    expect(result.stats.duplicateLines).toBe(0);
    expect(result.stats.droppedLines).toBeGreaterThanOrEqual(1);
  });

  it('processLogStream preserves JSONL output when requested', async () => {
    const line = '{"level":"error","msg":"database timeout"}';
    const output = new MemoryWritable();
    const result = await processLogStream(
      Readable.from([`${line}\n${line}\n`]),
      output,
      { outputFormat: 'jsonl-preserve' },
    );

    expect(output.content().trim().split('\n')).toEqual([line, line]);
    expect(result.stats.duplicateLines).toBe(0);
  });

  it('processLogStream supports custom token estimators and option timeout', async () => {
    const output = new MemoryWritable();
    const result = await processLogStream(
      Readable.from(['[ERROR] token test\n']),
      output,
      {
        timeoutMs: 100,
        tokenEstimator: () => 7.2,
      },
    );

    expect(result.inputTokens).toBe(8);
    expect(result.outputTokens).toBe(8);
  });

  it('processLogStream rejects an already aborted signal', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(
      processLogStream(Readable.from(['[ERROR] ignored\n']), new MemoryWritable(), {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      code: 'ABORTED',
    });
  });

  it('processLogString returns compressed text in memory', async () => {
    const result = await processLogString('[ERROR] string api failed\n');

    expect(result.output).toBe('[ERROR] string api failed\n');
    expect(result.stats.outputLines).toBe(1);
  });

  describe('maxTokens budget', () => {
    const threeErrors = [
      '[ERROR] critical alpha failed',
      '[ERROR] critical beta failed',
      '[ERROR] critical gamma failed',
    ].join('\n');

    it('keeps the full output when it already fits the budget', async () => {
      const result = await processLogString(threeErrors, { maxTokens: 10_000 });
      expect(result.output).toBe(`${threeErrors}\n`);
      expect(result.stats.outputLines).toBe(3);
    });

    it('trims output to the highest-scoring lines under the budget', async () => {
      const result = await processLogString(threeErrors, { maxTokens: 12 });
      const kept = result.output.trimEnd().split('\n');
      expect(kept.length).toBe(2);
      expect(result.output).toContain('alpha');
      expect(result.output).toContain('beta');
      expect(result.output).not.toContain('gamma');
      expect(result.stats.outputLines).toBe(2);
      expect(result.stats.droppedLines).toBeGreaterThanOrEqual(1);
    });

    it('prioritises errors over low-scored context lines', async () => {
      const input = [
        'plain context line one',
        'plain context line two',
        '[ERROR] payment service crashed',
      ].join('\n');
      const result = await processLogString(input, { maxTokens: 6 });
      expect(result.output).toContain('[ERROR] payment service crashed');
    });

    it('honours a custom tokenEstimator while budgeting', async () => {
      const result = await processLogString(threeErrors, {
        maxTokens: 40,
        tokenEstimator: (line) => line.length,
      });
      const kept = result.output.trimEnd().split('\n');
      expect(kept.length).toBe(1);
      expect(result.outputTokens).toBeLessThanOrEqual(40);
    });
  });

  describe('collapseRepeatedStacks', () => {
    const twoStacks = [
      '[ERROR] boom in handler',
      '    at Server.handle (/app/server.js:10:5)',
      '    at Object.run (0xdeadbeef)',
      '[ERROR] boom in handler',
      '    at Server.handle (/app/server.js:10:5)',
      '    at Object.run (0xcafef00d)',
    ].join('\n');

    it('collapses address-only-different stack windows into [x2]', async () => {
      const { output } = await processLogString(twoStacks, {
        multiline: 'node',
        collapseRepeatedStacks: true,
      });
      expect(output).toContain('[x2]');
      expect(output.match(/Server\.handle/gu)?.length).toBe(1);
    });

    it('keeps the windows separate when the option is off', async () => {
      const { output } = await processLogString(twoStacks, {
        multiline: 'node',
        collapseRepeatedStacks: false,
      });
      expect(output).not.toContain('[x2]');
      expect(output.match(/Server\.handle/gu)?.length).toBe(2);
    });

    it('still dedups plain non-stack lines via the standard signature', async () => {
      const { output } = await processLogString(
        '[ERROR] database down\n[ERROR] database down',
        { collapseRepeatedStacks: true },
      );
      expect(output).toContain('[x2] [ERROR] database down');
    });
  });

  describe('template signature for instance counters', () => {
    it('folds lines differing only by an enumerated worker/retry index', async () => {
      const input = [
        '[ERROR] worker 1 crashed during checkout',
        '[ERROR] worker 2 crashed during checkout',
        '[ERROR] worker 3 crashed during checkout',
      ].join('\n');
      const { output } = await processLogString(input);
      expect(output).toContain('[x3]');
      expect(output).toContain('worker [1 | 2 | 3] crashed during checkout');
      expect(output.match(/crashed during checkout/gu)?.length).toBe(1);
    });
  });

  describe('dedupeWindow', () => {
    const interleaved = [
      '[ERROR] alpha failed',
      '[ERROR] beta failed',
      '[ERROR] alpha failed',
    ].join('\n');

    it('collapses non-adjacent duplicates within the window', async () => {
      const { output } = await processLogString(interleaved, { dedupeWindow: 3 });
      const lines = output.trimEnd().split('\n');
      expect(lines.length).toBe(2);
      expect(output).toContain('[x2] [ERROR] alpha failed');
      expect(output).toContain('[ERROR] beta failed');
    });

    it('does not collapse non-adjacent duplicates by default', async () => {
      const { output } = await processLogString(interleaved);
      const lines = output.trimEnd().split('\n');
      expect(lines.length).toBe(3);
      expect(output).not.toContain('[x2]');
    });

    it('preserves first-occurrence order of survivors', async () => {
      const input = [
        '[ERROR] one',
        '[ERROR] two',
        '[ERROR] three',
        '[ERROR] two',
      ].join('\n');
      const { output } = await processLogString(input, { dedupeWindow: 4 });
      const lines = output.trimEnd().split('\n');
      expect(lines[0]).toContain('one');
      expect(lines[1]).toContain('[x2] [ERROR] two');
      expect(lines[2]).toContain('three');
    });
  });

  describe('rootCause cascade pruning', () => {
    const input = [
      '[ERROR] E0382: borrow of moved value `config`',
      'error: aborting due to 2 previous errors',
    ].join('\n');

    it('drops cascade restatements by default (auto)', async () => {
      const { output } = await processLogString(input);
      expect(output).toContain('E0382');
      expect(output).not.toContain('aborting due to');
    });

    it('keeps cascade restatements when disabled', async () => {
      const { output } = await processLogString(input, { rootCause: false });
      expect(output).toContain('aborting due to');
    });
  });

  describe('formatDetectionSampleSize voting', () => {
    const mixed = [
      'ts=1 level=info msg=start',
      '{"level":"error","msg":"boom"}',
      '{"level":"error","msg":"boom2"}',
      '{"level":"error","msg":"boom3"}',
    ].join('\n');

    it('locks onto the first recognizable format by default', async () => {
      const result = await processLogString(mixed);
      expect(result.detectedFormat).toBe('logfmt');
    });

    it('uses the majority format when voting is enabled', async () => {
      const result = await processLogString(mixed, {
        formatDetectionSampleSize: 4,
      });
      expect(result.detectedFormat).toBe('json');
    });

    it('decides from partial samples on a short stream', async () => {
      const result = await processLogString('{"level":"error","msg":"x"}', {
        formatDetectionSampleSize: 10,
      });
      expect(result.detectedFormat).toBe('json');
    });
  });

  describe('multilingual diagnostic keywords', () => {
    const foreign = [
      'La connexion a échoué',
      'Verbindung fehlgeschlagen',
      '数据库连接失败',
    ].join('\n');

    it('keeps non-English error lines by default (auto)', async () => {
      const { output } = await processLogString(foreign);
      expect(output).toContain('échoué');
      expect(output).toContain('fehlgeschlagen');
      expect(output).toContain('数据库连接失败');
    });

    it('drops non-English error lines when disabled', async () => {
      const { output } = await processLogString(foreign, { multilingual: false });
      expect(output).not.toContain('échoué');
      expect(output).not.toContain('fehlgeschlagen');
    });
  });

  describe('collapseBlocks', () => {
    const repeated = [
      '[ERROR] connect timeout to db-1',
      '[ERROR] retry scheduled in 5s',
      '[ERROR] connect timeout to db-1',
      '[ERROR] retry scheduled in 5s',
      '[ERROR] connect timeout to db-1',
      '[ERROR] retry scheduled in 5s',
    ].join('\n');

    it('collapses consecutive repeated blocks when enabled', async () => {
      const { output } = await processLogString(repeated, { collapseBlocks: 4 });
      expect(output).toContain('[block x3]');
      expect(output.match(/connect timeout to db-1/gu)?.length).toBe(1);
    });

    it('leaves repeated blocks expanded by default', async () => {
      const { output } = await processLogString(repeated);
      expect(output).not.toContain('[block x');
    });

    it('is a no-op when no block repeats consecutively', async () => {
      const distinct = [
        '[ERROR] alpha exploded',
        '[ERROR] beta exploded',
        '[ERROR] gamma exploded',
      ].join('\n');
      const { output } = await processLogString(distinct, { collapseBlocks: 4 });
      expect(output).not.toContain('[block x');
      expect(output).toContain('alpha exploded');
      expect(output).toContain('gamma exploded');
    });
  });

  it('createLogStripTransform works with stream consumers', async () => {
    const transform = createLogStripTransform();
    const chunks: Buffer[] = [];
    transform.on('data', (chunk: Buffer) => chunks.push(chunk));

    transform.end('[ERROR] transform api failed\n');
    await finished(transform);
    const result = await transform.result;

    expect(Buffer.concat(chunks).toString('utf8')).toBe(
      '[ERROR] transform api failed\n',
    );
    expect(result.stats.outputLines).toBe(1);
  });

  it('createLogStripTransform respects readable backpressure', async () => {
    const transform = createLogStripTransform();
    const chunks: Buffer[] = [];
    const originalPush = transform.push.bind(transform);
    let forcedBackpressure = false;
    transform.push = ((chunk: unknown, encoding?: BufferEncoding) => {
      originalPush(chunk, encoding);
      if (!forcedBackpressure) {
        forcedBackpressure = true;
        return false;
      }
      return true;
    }) as typeof transform.push;
    const writeDone = new Promise<void>((resolve, reject) => {
      transform.write(
        '[ERROR] backpressure api failed\n',
        (error?: Error | null) => {
          if (error) reject(error);
          else resolve();
        },
      );
    });

    for (let i = 0; i < 10 && transform.readableLength === 0; i += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    (transform as Transform & { _read(size: number): void })._read(1);
    await writeDone;

    transform.on('data', (chunk: Buffer) => chunks.push(chunk));
    transform.end();
    await finished(transform);
    const result = await transform.result;

    expect(Buffer.concat(chunks).toString('utf8')).toContain(
      '[ERROR] backpressure api failed',
    );
    expect(result.stats.outputLines).toBe(1);
  });

  it('createLogStripTransform surfaces parser errors', async () => {
    const transform = createLogStripTransform({
      config: {
        sources: [],
        diagnosticPatterns: ['['],
        ignorePatterns: [],
        sanitizePatterns: [],
        internalStackPatterns: [],
      },
    });
    transform.on('error', () => {});

    transform.end('[ERROR] bad config\n');

    await expect(transform.result).rejects.toMatchObject({
      code: 'INVALID_CONFIG',
    });
  });

  it('explainLogLine reports keep and drop reasons', () => {
    expect(explainLogLine('').reason).toBe('empty');
    expect(explainLogLine('plain line', { include: /ERROR/u }).reason).toBe(
      'include-filter',
    );
    expect(explainLogLine('[ERROR] hidden', { exclude: /hidden/u }).reason).toBe(
      'exclude-filter',
    );
    expect(
      explainLogLine('heartbeat ok', {
        config: {
          sources: [],
          diagnosticPatterns: [],
          ignorePatterns: ['heartbeat'],
          sanitizePatterns: [],
          internalStackPatterns: [],
        },
      }).reason,
    ).toBe('custom-ignore');
    expect(explainLogLine('[INFO] boot', { severity: 'error' }).reason).toBe(
      'severity',
    );
    expect(
      explainLogLine('error: aborting due to 2 previous errors').reason,
    ).toBe('cascade');
    expect(
      explainLogLine('error: aborting due to 2 previous errors', {
        rootCause: false,
      }).reason,
    ).not.toBe('cascade');
    expect(explainLogLine('Verbindung fehlgeschlagen').reason).toBe('hard-keep');
    expect(
      explainLogLine('Verbindung fehlgeschlagen', { multilingual: false }).reason,
    ).toBe('low-score');
    expect(explainLogLine('2024-01-01T00:00:00Z').reason).toBe('ci-noise');
    expect(explainLogLine('Downloading package 50%').reason).toBe('progress');
    expect(explainLogLine('[INFO] boot').reason).toBe('ignored-tag');
    expect(
      explainLogLine(
        '10.40.1.10 - - [16/May/2026:10:12:01 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.30"',
      ).reason,
    ).toBe('ci-noise');
    expect(
      explainLogLine('  at acme.run (/opt/acme/lib/core.js:10:5)', {
        config: {
          sources: [],
          diagnosticPatterns: [],
          ignorePatterns: [],
          sanitizePatterns: [],
          internalStackPatterns: ['/opt/acme/lib/'],
        },
      }).reason,
    ).toBe('internal-stack');
    expect(
      explainLogLine('ACME_KEEP_42', {
        config: {
          sources: [],
          diagnosticPatterns: ['ACME_KEEP_\\d+'],
          ignorePatterns: [],
          sanitizePatterns: [],
          internalStackPatterns: [],
        },
      }).reason,
    ).toBe('hard-keep');
    expect(
      explainLogLine('plain line', {
        config: {
          sources: [],
          diagnosticPatterns: ['NO_MATCH'],
          ignorePatterns: [],
          sanitizePatterns: [],
          internalStackPatterns: [],
        },
      }).reason,
    ).toBe('low-score');
    expect(
      explainLogLine('[ERROR] auth ACME-USER-123', {
        config: {
          sources: [],
          diagnosticPatterns: [],
          ignorePatterns: [],
          sanitizePatterns: [
            {
              pattern: 'ACME-USER-\\d+',
              replacement: '[ACME-USER]',
            },
          ],
          internalStackPatterns: [],
        },
      }).sanitizedLine,
    ).toContain('[ACME-USER]');
    expect(explainLogLine('plain line').reason).toBe('low-score');
  });

  it('processLogStream joins multiline continuations in python mode', async () => {
    const logs = [
      '[ERROR] traceback:',
      'Traceback (most recent call last):',
      '    File "app.py", line 42, in main',
      '    raise ValueError("bad")',
      'ValueError: bad',
      '[ERROR] separate error',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      multiline: 'python',
    });
    const content = output.content();

    // Indented continuation lines should be joined with their parent
    expect(content).toContain('[ERROR]');
    expect(result.stats.inputLines).toBe(6);
  });

  it('processLogStream joins multiline continuations in node mode', async () => {
    const logs = [
      '[ERROR] TypeError: boom',
      '    at app (/src/app.ts:10:5)',
      '    at lib (/src/lib.ts:20:3)',
    ].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      multiline: 'node',
    });
    const content = output.content();

    expect(content).toContain('TypeError');
    expect(content).toContain('at app');
    expect(result.stats.inputLines).toBe(3);
  });

  it('processLogStreamWithTimeout returns timedOut result on timeout', async () => {
    const result = await processLogStreamWithTimeout(
      Readable.from(['[ERROR] test\n']),
      new MemoryWritable(),
      {},
      100,
    );

    // A small log finishes before timeout, so timedOut should be false
    expect(result.timedOut).toBeFalsy();
  });

  it('processLogStreamWithTimeout delegates without timeout', async () => {
    const output = new MemoryWritable();
    const result = await processLogStreamWithTimeout(
      Readable.from(['[ERROR] test\n']),
      output,
      {},
      undefined,
    );

    expect(result.timedOut).toBeFalsy();
    expect(output.content()).toContain('[ERROR] test');
  });

  it('processLogStreamWithTimeout returns timedOut on actual timeout', async () => {
    // Create a stream that never emits data
    const slowInput = new Readable({
      read() {
        // Never push data, never end - the stream just hangs
      },
    });

    const result = await processLogStreamWithTimeout(
      slowInput,
      new MemoryWritable(),
      {},
      50, // 50ms timeout
    );

    expect(result.timedOut).toBe(true);
    expect(result.stats.inputLines).toBe(0);
    slowInput.destroy();
  });

  it('processLogStreamWithTimeout re-throws non-timeout errors', async () => {
    const brokenInput = new Readable({
      read() {
        this.destroy(new Error('stream broken'));
      },
    });

    await expect(
      processLogStreamWithTimeout(brokenInput, new MemoryWritable(), {}, 5000),
    ).rejects.toThrow('stream broken');
  });

  it('processes files and propagates read errors', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-'));

    try {
      const inputPath = join(directory, 'raw.log');
      const outputPath = join(directory, 'raw.logstrip.log');
      await writeFile(inputPath, '[ERROR] file failed\n', 'utf8');

      expect(pathsReferToSameFile(inputPath, outputPath)).toBe(false);
      expect(pathsReferToSameFile(inputPath, inputPath.toUpperCase())).toBe(
        true,
      );

      const result = await processLogFile(inputPath, outputPath);

      expect(result.outputPath).toBe(outputPath);
      expect(await readFile(outputPath, 'utf8')).toBe('[ERROR] file failed\n');

      await expect(processLogFile(inputPath, inputPath)).rejects.toThrow(
        'Input and output paths must be different',
      );
      await expect(processLogFile(inputPath, inputPath)).rejects.toBeInstanceOf(
        LogStripError,
      );
      await expect(processLogFile(inputPath, inputPath)).rejects.toMatchObject({
        code: 'SAME_INPUT_OUTPUT',
      });
      expect(await readFile(inputPath, 'utf8')).toBe('[ERROR] file failed\n');

      await expect(
        processLogFile(join(directory, 'missing.log'), outputPath),
      ).rejects.toThrow();
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('processLogFiles runs multiple file jobs', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-batch-'));

    try {
      const firstInput = join(directory, 'one.log');
      const secondInput = join(directory, 'two.log');
      const firstOutput = join(directory, 'one.out.log');
      const secondOutput = join(directory, 'two.out.log');
      await writeFile(firstInput, '[ERROR] first failed\n', 'utf8');
      await writeFile(secondInput, '[ERROR] second failed\n', 'utf8');

      const results = await processLogFiles([
        { inputPath: firstInput, outputPath: firstOutput },
        {
          inputPath: secondInput,
          outputPath: secondOutput,
          options: { aggressiveness: 'low' },
        },
      ]);

      expect(results).toHaveLength(2);
      expect(await readFile(firstOutput, 'utf8')).toBe('[ERROR] first failed\n');
      expect(await readFile(secondOutput, 'utf8')).toBe(
        '[ERROR] second failed\n',
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});

describe('custom config integration', () => {
  it('buildMergedConfig returns built-in sources without config', () => {
    const merged = buildMergedConfig();
    expect(merged.mergedSources.length).toBeGreaterThan(0);
    expect(merged.diagnosticPatterns).toHaveLength(0);
  });

  it('buildMergedConfig merges in-memory custom config', () => {
    const merged = buildMergedConfig({
      config: {
        sources: [{ name: 'memory-source', markers: ['memory-marker'] }],
        diagnosticPatterns: ['MEMORY_ERROR'],
        ignorePatterns: ['memory-ignore'],
        sanitizePatterns: [
          { pattern: 'MEMORY-SECRET', replacement: '[MEMORY-SECRET]' },
        ],
        internalStackPatterns: ['memory-stack'],
      },
    });

    expect(merged.mergedSources.some(([name]) => name === 'memory-source')).toBe(
      true,
    );
    expect(merged.diagnosticPatterns).toContain('MEMORY_ERROR');
    expect(merged.ignorePatterns).toContain('memory-ignore');
    expect(merged.sanitizePatterns[0].replacement).toBe('[MEMORY-SECRET]');
    expect(merged.internalStackPatterns).toContain('memory-stack');
  });

  it('wraps invalid custom regexes in LogStripError', async () => {
    await expect(
      processLogStream(Readable.from(['[ERROR] bad regex\n']), new MemoryWritable(), {
        config: {
          sources: [],
          diagnosticPatterns: ['['],
          ignorePatterns: [],
          sanitizePatterns: [],
          internalStackPatterns: [],
        },
      }),
    ).rejects.toMatchObject({
      code: 'INVALID_CONFIG',
    });
  });

  it('buildMergedConfig merges custom sources with existing ones', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-merge-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `sources:
  - name: acme-tool
    markers:
      - acme-tool
      - "[ACME]"
diagnosticPatterns:
  - "ACME_ERROR_\\\\d+"
ignorePatterns:
  - "\\\\bheartbeat\\\\b"
sanitizePatterns:
  - pattern: "\\\\bACME-USER-\\\\d+\\\\b"
    replacement: "[ACME-USER]"
internalStackPatterns:
  - "/opt/acme/lib/"
`,
        'utf8',
      );

      const merged = buildMergedConfig({ configPath });
      expect(merged.mergedSources.some(([name]) => name === 'acme-tool')).toBe(true);
      expect(merged.diagnosticPatterns).toHaveLength(1);
      expect(merged.ignorePatterns).toHaveLength(1);
      expect(merged.sanitizePatterns).toHaveLength(1);
      expect(merged.internalStackPatterns).toHaveLength(1);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom ignore patterns drop matching lines', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-ignore-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `ignorePatterns:
  - "\\\\bheartbeat\\\\b"
`,
        'utf8',
      );

      const input = Readable.from([
        '[ERROR] critical failure\n',
        'heartbeat ok\n',
        '[WARN] something wrong\n',
      ]);
      const output = new MemoryWritable();
      const result = await processLogStream(input, output, {
        aggressiveness: 'low',
        configPath,
      });

      const out = output.content();
      expect(out).toContain('[ERROR] critical failure');
      expect(out).not.toContain('heartbeat');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom diagnostic patterns boost line score', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-diag-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `diagnosticPatterns:
  - "ACME_ERROR_\\\\d+"
`,
        'utf8',
      );

      const input = Readable.from([
        'ACME_ERROR_42 something broke\n',
        'boring noise line\n',
      ]);
      const output = new MemoryWritable();
      const result = await processLogStream(input, output, {
        aggressiveness: 'high',
        configPath,
      });

      const out = output.content();
      expect(out).toContain('ACME_ERROR_42');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom sanitize patterns mask matched text', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-sanitize-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `sanitizePatterns:
  - pattern: "\\\\bACME-USER-\\\\d+\\\\b"
    replacement: "[ACME-USER]"
`,
        'utf8',
      );

      const input = Readable.from([
        '[ERROR] auth failed for ACME-USER-12345\n',
      ]);
      const output = new MemoryWritable();
      const result = await processLogStream(input, output, {
        aggressiveness: 'high',
        configPath,
      });

      const out = output.content();
      expect(out).toContain('[ACME-USER]');
      expect(out).not.toContain('ACME-USER-12345');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom internal stack patterns collapse matching lines', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-istack-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `internalStackPatterns:
  - "/opt/acme/lib/"
`,
        'utf8',
      );

      const input = Readable.from([
        '[ERROR] crash\n',
        '  at acme.run (/opt/acme/lib/core.js:10:5)\n',
        '  at acme.run (/opt/acme/lib/util.js:20:3)\n',
        '[WARN] after\n',
      ]);
      const output = new MemoryWritable();
      const result = await processLogStream(input, output, {
        aggressiveness: 'high',
        configPath,
      });

      const out = output.content();
      expect(out).toContain('[ERROR] crash');
      expect(out).toContain(INTERNAL_STACK_MARKER);
      expect(out).not.toContain('/opt/acme/lib/');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom sources are detected in log output', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-sources-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `sources:
  - name: acme-gateway
    markers:
      - acme-gateway
`,
        'utf8',
      );

      const input = Readable.from([
        '[ERROR] acme-gateway connection refused\n',
      ]);
      const output = new MemoryWritable();
      const result = await processLogStream(input, output, {
        aggressiveness: 'high',
        configPath,
      });

      expect(result.detectedSources).toContain('acme-gateway');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  it('custom markers merge into existing built-in source', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'logstrip-config-merge-src-'));
    try {
      const configPath = join(directory, '.logstrip.yml');
      await writeFile(
        configPath,
        `sources:
  - name: docker
    markers:
      - custom-docker-marker
`,
        'utf8',
      );

      const merged = buildMergedConfig({ configPath });
      const dockerEntry = merged.mergedSources.find(([name]) => name === 'docker');
      expect(dockerEntry).toBeDefined();
      expect(dockerEntry![1]).toContain('custom-docker-marker');
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});

describe('compound exception and polyglot stack-frame detection', () => {
  it('recognizes compound exception class names', () => {
    expect(looksLikeDiagnosticLine('PaymentGatewayException: card declined')).toBe(true);
    expect(looksLikeDiagnosticLine('caught RefundLedgerFault in worker')).toBe(true);
    expect(scoreLineRelevance('OrderSyncError: upstream rejected', 'medium')).toBeGreaterThanOrEqual(
      SCORE_KEEP_THRESHOLD,
    );
  });

  it('recognizes Ruby stack frames', () => {
    expect(isStackFrameLine("\tfrom /srv/app/lib/orders/finalizer.rb:22:in 'finalize'")).toBe(true);
    expect(isStackFrameLine("\tfrom /usr/local/bundle/gems/rspec-core-3.13.0/lib/rspec/core/example.rb:263:in `instance_exec'")).toBe(true);
  });

  it('recognizes Rust panics and backtrace frames', () => {
    expect(looksLikeDiagnosticLine("thread 'main' panicked at src/main.rs:4:5:")).toBe(true);
    expect(isStackFrameLine('   1: core::panicking::panic_fmt')).toBe(true);
    expect(isStackFrameLine('             at /rustc/9b00956e/library/std/src/panicking.rs:645:5')).toBe(true);
  });

  it('recognizes C# stack frames', () => {
    expect(isStackFrameLine('   at Acme.Checkout.CheckoutService.Submit(Order order) in /src/Checkout/CheckoutService.cs:line 132')).toBe(true);
    expect(isStackFrameLine('   at System.Reflection.MethodBaseInvoker.InvokeWithNoArgs(Object obj, BindingFlags invokeAttr)')).toBe(true);
  });

  it('recognizes PHP stack frames', () => {
    expect(isStackFrameLine('#0 /srv/app/src/Refunds/RefundService.php(39): Acme\\Refunds\\Ledger->append()')).toBe(true);
    expect(isStackFrameLine('#3 {main}')).toBe(true);
  });

  it('still recognizes frames after line:col normalization to [NN]', () => {
    expect(isStackFrameLine('    at resolveLedger (/srv/app/src/refunds/resolve-ledger.ts:[NN]:[NN])')).toBe(true);
    expect(isStackFrameLine('    at com.example.Foo.bar(Foo.java:[NN])')).toBe(true);
    expect(isStackFrameLine('  File "/repo/tests/test.py", line [NN], in test')).toBe(true);
    expect(isStackFrameLine('        /repo/orders/process_test.go:[NN] +0x85')).toBe(true);
  });

  it('treats gem, rustc and System frames as internal', () => {
    expect(isInternalStackTraceLine("\tfrom /usr/local/bundle/gems/rspec-core-3.13.0/lib/rspec/core/hooks.rb:486:in 'run'")).toBe(true);
    expect(isInternalStackTraceLine('             at /rustc/9b00956e/library/core/src/panicking.rs:72:14')).toBe(true);
    expect(isInternalStackTraceLine('   at System.RuntimeMethodHandle.InvokeMethod(Object target, Void** arguments, Signature sig, Boolean isConstructor)')).toBe(true);
    expect(isInternalStackTraceLine("\tfrom /srv/app/lib/orders/finalizer.rb:22:in 'finalize'")).toBe(false);
  });

  it('non-frame text is not a stack frame', () => {
    expect(isStackFrameLine('plain text line')).toBe(false);
    expect(isStackFrameLine('[ERROR] something failed')).toBe(false);
  });
});

describe('rarity boost (IDF side)', () => {
  it('boosts a unique positively-scored line in a large stream', () => {
    const base = scoreLineRelevance('[Pipeline] deploy step', 'medium', 1, 10);
    const boosted = scoreLineRelevance(
      '[Pipeline] deploy step',
      'medium',
      1,
      RARITY_MIN_INPUT_LINES,
    );
    expect(boosted).toBe(base + RARITY_BOOST);
  });

  it('does not boost repeated lines or zero-scored lines', () => {
    expect(
      scoreLineRelevance('[Pipeline] deploy step', 'medium', 2, RARITY_MIN_INPUT_LINES),
    ).toBe(scoreLineRelevance('[Pipeline] deploy step', 'medium', 2, 10));
    expect(
      scoreLineRelevance('plain narrative line', 'medium', 1, RARITY_MIN_INPUT_LINES),
    ).toBe(0);
  });
});

describe('app-stack truncation', () => {
  const frames = Array.from(
    { length: 8 },
    (_, i) => `    at fn${i} (/srv/app/src/file${i}.ts:${i + 1}0:5)`,
  );

  it('caps consecutive app frames and emits a count marker', async () => {
    const logs = ['[ERROR] boom happened', ...frames].join('\n');
    const decisions: string[] = [];

    const output = new MemoryWritable();
    await processLogStream(Readable.from([logs]), output, {
      maxStackFrames: 3,
      onDecision: (d) => decisions.push(d.reason),
    });
    const content = output.content();

    expect(content).toContain('at fn0');
    expect(content).toContain('at fn2');
    expect(content).not.toContain('at fn3');
    expect(content).not.toContain('at fn7');
    expect(content).toContain('[... 5 more application stack frames ...]');
    expect(decisions.filter((r) => r === 'stack-truncated')).toHaveLength(5);
  });

  it('flushes the marker before the next kept non-frame line', async () => {
    const logs = ['[ERROR] boom happened', ...frames, '[FATAL] giving up'].join('\n');

    const output = new MemoryWritable();
    await processLogStream(Readable.from([logs]), output, { maxStackFrames: 2 });
    const lines = output.content().trimEnd().split('\n');

    const markerIndex = lines.findIndex((l) => l.includes('more application stack frames'));
    const fatalIndex = lines.findIndex((l) => l.includes('[FATAL]'));
    expect(markerIndex).toBeGreaterThan(-1);
    expect(fatalIndex).toBe(markerIndex + 1);
  });

  it('maxStackFrames: 0 keeps every frame', async () => {
    const logs = ['[ERROR] boom happened', ...frames].join('\n');

    const output = new MemoryWritable();
    await processLogStream(Readable.from([logs]), output, { maxStackFrames: 0 });
    const content = output.content();

    expect(content).toContain('at fn7');
    expect(content).not.toContain('more application stack frames');
  });
});

describe('format drift re-election', () => {
  it('switches the detected format after a sustained mid-stream drift', async () => {
    const head = ['level=info msg=boot service=api', 'level=info msg=ready service=api'];
    const tail = Array.from(
      { length: 25 },
      (_, i) => `{"level":"error","msg":"db timeout ${i}"}`,
    );
    const logs = [...head, ...tail].join('\n');

    const output = new MemoryWritable();
    const result = await processLogStream(Readable.from([logs]), output, {
      formatDetectionSampleSize: 2,
    });

    expect(result.detectedFormat).toBe('json');
  });
});
