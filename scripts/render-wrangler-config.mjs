#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const strict = process.argv.includes("--strict");
const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = resolve(rootDir, "wrangler.toml");
const outputPath = resolve(
  rootDir,
  process.env.WRANGLER_CONFIG_OUT || "wrangler.deploy.toml",
);

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value && strict) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

const optional = (name) => process.env[name]?.trim();

const optionalRate = (name) => {
  const value = optional(name);
  if (!value) return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new Error(`${name} must be a number between 0 and 1`);
  }
  return parsed;
};

const tomlString = (value) => `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

const replaceLine = (config, pattern, replacement) => {
  if (!pattern.test(config)) {
    throw new Error(`Unable to find expected wrangler.toml line: ${pattern}`);
  }
  return config.replace(pattern, replacement);
};

const setVar = (config, name, value) => {
  if (!value) {
    return config;
  }

  const line = `${name} = ${tomlString(value)}`;
  const existing = new RegExp(`^${name}\\s*=\\s*".*"$`, "m");
  if (existing.test(config)) {
    return config.replace(existing, line);
  }

  const varsHeader = "[vars]\n";
  if (!config.includes(varsHeader)) {
    throw new Error("Unable to find [vars] section in wrangler.toml");
  }
  return config.replace(varsHeader, `${varsHeader}${line}\n`);
};

const removeVar = (config, name) => {
  const existing = new RegExp(`^${name}\\s*=\\s*".*"\\n?`, "m");
  return config.replace(existing, "");
};

const setObservabilityRate = (config, section, value) => {
  if (value === undefined) return config;
  const escaped = section.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`(\\[${escaped}\\][\\s\\S]*?^head_sampling_rate\\s*=\\s*)[0-9.]+`, "m");
  if (!pattern.test(config)) throw new Error(`Unable to find ${section} head_sampling_rate`);
  return config.replace(pattern, `$1${value}`);
};

const replaceQueueName = (config, currentName, value) => value
  ? config.replaceAll(`queue = ${tomlString(currentName)}`, `queue = ${tomlString(value)}`)
  : config;

let config = readFileSync(sourcePath, "utf8");

const workerName = required("WORKER_NAME");
const d1DatabaseName = required("D1_DATABASE_NAME");
const d1DatabaseId = required("D1_DATABASE_ID");
const attachmentsBucketName = required("ATTACHMENTS_BUCKET_NAME");
const iconsCacheId = required("ICONS_CACHE_ID");
const iconsCachePreviewId = required("ICONS_CACHE_PREVIEW_ID");

if (workerName) {
  config = replaceLine(config, /^name\s*=\s*".*"$/m, `name = ${tomlString(workerName)}`);
}

if (d1DatabaseName) {
  config = replaceLine(
    config,
    /^database_name\s*=\s*".*"$/m,
    `database_name = ${tomlString(d1DatabaseName)}`,
  );
}

if (d1DatabaseId) {
  config = replaceLine(config, /^database_id\s*=\s*".*"$/m, `database_id = ${tomlString(d1DatabaseId)}`);
}

if (attachmentsBucketName) {
  config = replaceLine(
    config,
    /^bucket_name\s*=\s*".*"$/m,
    `bucket_name = ${tomlString(attachmentsBucketName)}`,
  );
}

if (iconsCacheId) {
  config = replaceLine(config, /^id\s*=\s*".*"$/m, `id = ${tomlString(iconsCacheId)}`);
}

if (iconsCachePreviewId) {
  config = replaceLine(
    config,
    /^preview_id\s*=\s*".*"$/m,
    `preview_id = ${tomlString(iconsCachePreviewId)}`,
  );
}

const emailMode = optional("EMAIL_MODE") || "disabled";
config = setVar(config, "EMAIL_MODE", emailMode);
config = setVar(config, "EMAIL_FROM", optional("EMAIL_FROM"));
config = setVar(config, "EMAIL_FROM_NAME", optional("EMAIL_FROM_NAME"));
config = setVar(config, "EMAIL_REPLY_TO", optional("EMAIL_REPLY_TO"));
config = setVar(config, "EMAIL_PROVIDER_ENDPOINT", optional("EMAIL_PROVIDER_ENDPOINT"));
config = setVar(config, "SIGNUPS_ALLOWED", optional("SIGNUPS_ALLOWED"));
config = setVar(config, "VAULT_BASE_URL", optional("VAULT_BASE_URL"));
config = setVar(config, "SSO_BASE_URL", optional("SSO_BASE_URL"));
config = setVar(config, "FORCE_INVITE_REGISTER", optional("FORCE_INVITE_REGISTER"));
config = setVar(config, "WORKER_VERSION", optional("WORKER_VERSION"));
config = setVar(config, "WEB_PUSH_VAPID_PUBLIC_KEY", optional("WEB_PUSH_VAPID_PUBLIC_KEY"));
config = setVar(config, "WEB_PUSH_VAPID_SUBJECT", optional("WEB_PUSH_VAPID_SUBJECT"));
config = setObservabilityRate(config, "observability.logs", optionalRate("WORKERS_LOG_SAMPLING_RATE"));
config = setObservabilityRate(config, "observability.traces", optionalRate("WORKERS_TRACE_SAMPLING_RATE"));
config = replaceQueueName(config, "bitwarden-web-push-dev", optional("WEB_PUSH_QUEUE_NAME"));
config = replaceQueueName(config, "bitwarden-web-push-dlq-dev", optional("WEB_PUSH_DLQ_NAME"));

if (!optional("EMAIL_REPLY_TO")) {
  config = removeVar(config, "EMAIL_REPLY_TO");
}

if (emailMode === "cloudflare") {
  const senderAddress = required("EMAIL_SENDER_ADDRESS");
  if (senderAddress) {
    const sendEmailBlock = `# Cloudflare Email Service Workers binding. Rendered for EMAIL_MODE=cloudflare.\n[[send_email]]\nname = "EMAIL"\nallowed_sender_addresses = [${tomlString(senderAddress)}]\n\n`;
    if (/^\[\[send_email\]\]$/m.test(config)) {
      config = replaceLine(
        config,
        /^allowed_sender_addresses\s*=\s*\[.*\]$/m,
        `allowed_sender_addresses = [${tomlString(senderAddress)}]`,
      );
    } else {
      config = config.replace("[[d1_databases]]", `${sendEmailBlock}[[d1_databases]]`);
    }
  }
} else {
  config = config.replace(
    /\n# Cloudflare Email Service Workers binding[^\n]*\n\[\[send_email\]\]\nname = "EMAIL"\nallowed_sender_addresses = \["[^"]*"\]\n/g,
    "\n",
  );
}

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(
  outputPath,
  `# Generated by scripts/render-wrangler-config.mjs. Do not commit this file.\n${config}`,
);

console.log(`Rendered Wrangler config: ${outputPath}`);
