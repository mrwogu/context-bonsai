#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const { chmodSync, cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { delimiter, join, resolve } = require('node:path');

const repoRoot = resolve(__dirname, '..');
const sourcePluginRoot = resolve(repoRoot, 'plugins', 'logstrip');
const cliPath = resolve(repoRoot, 'dist', 'cli', 'index.js');
const expectedLine = '[x2] [ERROR] request [ID] failed';
const expectedHookCommand = 'logstrip hook';
const pluginManifestPaths = [
  '.factory-plugin/plugin.json',
  '.claude-plugin/plugin.json',
  '.github/plugin.json',
  '.codex-plugin/plugin.json',
  '.cursor-plugin/plugin.json',
];
const rawLog = [
  '[INFO] boot ok',
  '[ERROR] request 123e4567-e89b-12d3-a456-426614174000 failed',
  '[ERROR] request 987e6543-e21b-42d3-b456-526614174111 failed',
  '2024-01-15 10:23:47.789 [WARN] retrying connection',
  '2024-01-15 10:23:48.012 [INFO] boot ok',
  '',
].join('\n');

function fail(message, result) {
  console.error(message);
  if (result?.stdout) {
    console.error(result.stdout);
  }
  if (result?.stderr) {
    console.error(result.stderr);
  }
  process.exit(1);
}

function createCliWrapper(binDir) {
  mkdirSync(binDir, { recursive: true });

  if (process.platform === 'win32') {
    writeFileSync(
      join(binDir, 'logstrip.cmd'),
      `@echo off\r\nnode "${cliPath}" %*\r\n`,
    );
    return;
  }

  const wrapperPath = join(binDir, 'logstrip');
  writeFileSync(wrapperPath, `#!/bin/sh\nexec node "${cliPath}" "$@"\n`);
  chmodSync(wrapperPath, 0o755);
}

function runHook(command, env, input, label) {
  if (command !== expectedHookCommand) {
    fail(`${label} hook command is not "${expectedHookCommand}": ${command}`);
  }

  const result = spawnSync(command, {
    shell: true,
    encoding: 'utf8',
    input: JSON.stringify(input),
    env,
    timeout: 30_000,
  });

  if (result.status !== 0) {
    fail(`${label} hook command failed: ${command}`, result);
  }

  if (!result.stdout.trim()) {
    fail(`${label} hook command produced no JSON: ${command}`, result);
  }

  return JSON.parse(result.stdout);
}

function smokePreToolUse(command, pluginRoot, env, label, options) {
  const eventName = options?.eventName ?? 'PreToolUse';
  const toolName = options?.toolName ?? 'Read';
  const fixtureDir = join(
    pluginRoot,
    'fixtures',
    `${label.replaceAll(/[^\w-]/g, '-')}-${eventName}-${toolName}`,
  );
  mkdirSync(fixtureDir, { recursive: true });
  const inputPath = join(fixtureDir, 'raw.log');
  writeFileSync(inputPath, rawLog);

  const preToolUseResult = runHook(
    command,
    env,
    {
      hook_event_name: eventName,
      tool_name: toolName,
      tool_input: { file_path: inputPath },
      session_id: 'plugin-smoke',
    },
    `${label} [${eventName}/${toolName}]`,
  );

  if (preToolUseResult?.hookSpecificOutput?.permissionDecision !== 'deny') {
    fail(
      `${label} [${eventName}/${toolName}] missing Claude-style hookSpecificOutput.permissionDecision='deny'`,
    );
  }
  if (preToolUseResult?.permission !== 'deny') {
    fail(
      `${label} [${eventName}/${toolName}] missing Cursor-style permission='deny'`,
    );
  }
  if (typeof preToolUseResult?.user_message !== 'string') {
    fail(
      `${label} [${eventName}/${toolName}] missing Cursor-style user_message`,
    );
  }

  const outputPath = `${inputPath}.logstrip.log`;
  if (!existsSync(outputPath)) {
    fail(`${label} PreToolUse hook did not create output file: ${outputPath}`);
  }

  const compressed = readFileSync(outputPath, 'utf8');
  if (!compressed.split(/\r?\n/).includes(expectedLine)) {
    fail(`${label} compressed output did not contain exact line: ${expectedLine}`);
  }
}

function smokeSharedHooks(manifestPath, pluginRoot, manifest, env) {
  if (manifest.hooks !== './hooks/hooks.json') {
    fail(`${manifestPath} did not point at ./hooks/hooks.json`);
  }

  const hooksConfig = JSON.parse(
    readFileSync(resolve(pluginRoot, manifest.hooks), 'utf8'),
  );
  const preToolUseCommand = hooksConfig.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command;
  const userPromptCommand = hooksConfig.hooks?.UserPromptSubmit?.[0]?.hooks?.[0]?.command;

  if (typeof preToolUseCommand !== 'string' || typeof userPromptCommand !== 'string') {
    fail(`${manifestPath} hooks config is missing expected commands`);
  }

  smokePreToolUse(preToolUseCommand, pluginRoot, env, manifestPath);
  // Copilot CLI / VS Code uses "view" as the file-read tool; the matcher in
  // hooks.json says "Read" but VS Code ignores matcher values, so make sure
  // the runtime handler accepts the camelCase / alternate tool name too.
  smokePreToolUse(preToolUseCommand, pluginRoot, env, manifestPath, {
    toolName: 'view',
  });

  for (const eventName of ['UserPromptSubmit', 'userPromptSubmitted']) {
    const userPromptResult = runHook(
      userPromptCommand,
      env,
      {
        hook_event_name: eventName,
        prompt: rawLog,
        session_id: 'plugin-smoke',
      },
      `${manifestPath} [${eventName}]`,
    );

    if (
      userPromptResult?.decision !== 'block'
      || typeof userPromptResult?.reason !== 'string'
      || !userPromptResult.reason.includes('LogStrip blocked')
    ) {
      fail(
        `${manifestPath} [${eventName}] hook did not emit decision='block'`,
      );
    }
    // Copilot CLI ignores decision-control on userPromptSubmitted; verify the
    // additionalContext fallback so the model still receives the warning.
    if (
      typeof userPromptResult?.hookSpecificOutput?.additionalContext !== 'string'
      || !userPromptResult.hookSpecificOutput.additionalContext.includes(
        'LogStrip blocked',
      )
    ) {
      fail(
        `${manifestPath} [${eventName}] missing Copilot fallback hookSpecificOutput.additionalContext`,
      );
    }
  }
}

function smokeCursorHooks(manifestPath, pluginRoot, manifest, env) {
  if (manifest.hooks !== './hooks/cursor-hooks.json') {
    fail(`${manifestPath} did not point at ./hooks/cursor-hooks.json`);
  }

  const hooksConfig = JSON.parse(
    readFileSync(resolve(pluginRoot, manifest.hooks), 'utf8'),
  );
  const preToolUseCommand = hooksConfig.hooks?.preToolUse?.[0]?.command;
  const beforeSubmitPromptCommand =
    hooksConfig.hooks?.beforeSubmitPrompt?.[0]?.command;

  if (typeof preToolUseCommand !== 'string') {
    fail(`${manifestPath} cursor hooks config is missing the preToolUse command`);
  }
  if (typeof beforeSubmitPromptCommand !== 'string') {
    fail(
      `${manifestPath} cursor hooks config is missing the beforeSubmitPrompt command`,
    );
  }

  // Cursor invokes hooks with camelCase hook_event_name="preToolUse"; make sure
  // the handler recognises that dialect and still emits Cursor-native fields.
  smokePreToolUse(preToolUseCommand, pluginRoot, env, manifestPath, {
    eventName: 'preToolUse',
  });

  const beforeSubmitPromptResult = runHook(
    beforeSubmitPromptCommand,
    env,
    {
      hook_event_name: 'beforeSubmitPrompt',
      prompt: rawLog,
      session_id: 'plugin-smoke',
    },
    `${manifestPath} [beforeSubmitPrompt]`,
  );

  if (beforeSubmitPromptResult?.continue !== false) {
    fail(
      `${manifestPath} beforeSubmitPrompt hook did not emit continue=false`,
    );
  }
  if (
    typeof beforeSubmitPromptResult?.user_message !== 'string'
    || !beforeSubmitPromptResult.user_message.includes('LogStrip blocked')
  ) {
    fail(
      `${manifestPath} beforeSubmitPrompt hook missing user_message with block reason`,
    );
  }
  // Claude's `continue: false` aborts the entire session; emitting both
  // would corrupt multi-host setups, so explicitly assert Cursor-only shape.
  if (beforeSubmitPromptResult?.decision !== undefined) {
    fail(
      `${manifestPath} beforeSubmitPrompt hook must not emit Claude-style "decision"`,
    );
  }
}

function main() {
  const tempRoot = mkdtempSync(join(tmpdir(), 'logstrip plugin smoke '));
  const pluginRoot = join(tempRoot, 'plugin root');
  cpSync(sourcePluginRoot, pluginRoot, { recursive: true });

  try {
    const binDir = join(tempRoot, 'bin');
    createCliWrapper(binDir);

    const env = {
      ...process.env,
      PATH: `${binDir}${delimiter}${process.env.PATH ?? ''}`,
    };

    for (const manifestPath of pluginManifestPaths) {
      const manifest = JSON.parse(
        readFileSync(join(pluginRoot, manifestPath), 'utf8'),
      );

      if (manifest.hooks === './hooks/hooks.json') {
        smokeSharedHooks(manifestPath, pluginRoot, manifest, env);
        continue;
      }

      if (manifest.hooks === './hooks/cursor-hooks.json') {
        smokeCursorHooks(manifestPath, pluginRoot, manifest, env);
        continue;
      }

      fail(`${manifestPath} has unsupported hooks path: ${manifest.hooks ?? 'missing'}`);
    }
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

main();
