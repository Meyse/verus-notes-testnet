import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = resolve(scriptDirectory, "..");
const repoRoot = parseRootArg(process.argv.slice(2));

const ignoredDirectoryNames = new Set([
  ".git",
  ".svelte-kit",
  ".wrangler",
  "build",
  "dist",
  "node_modules",
  "target",
]);
const ignoredRelativeDirectories = new Set([
  "app/src-tauri/gen",
  "tools/protocol-harness/tmp",
]);
const ignoredFiles = new Set([
  "scripts/check-no-unlock-artifacts.mjs",
  "scripts/test-unlock-artifact-scan.mjs",
]);

const callbackUrlPattern =
  /https:\/\/[A-Za-z0-9.-]+\/wallet-callback\/(?<requestId>[A-Za-z0-9_-]{32,96})\/(?<secret>[A-Za-z0-9_-]{32,96})(?:["'\s,})\]]|$)/g;

const detectors = [
  {
    name: "live responseBase64Url assignment",
    fields: ["responseBase64Url", "response_base64_url"],
    validators: [isLongEncodedArtifact],
  },
  {
    name: "callback mailbox token assignment",
    fields: [
      "pollToken",
      "poll_token",
      "writeToken",
      "write_token",
      "nonce",
      "callbackNonce",
      "callback_nonce",
    ],
    validators: [isTokenLike],
  },
  {
    name: "raw GenericResponse artifact assignment",
    fields: [
      "genericResponse",
      "generic_response",
      "genericResponseBase64Url",
      "generic_response_base64_url",
      "genericResponseHex",
      "generic_response_hex",
    ],
    validators: [isLongEncodedArtifact, isLongHexArtifact],
  },
  {
    name: "raw DataDescriptor artifact assignment",
    fields: [
      "dataDescriptor",
      "data_descriptor",
      "dataDescriptorBase64Url",
      "data_descriptor_base64_url",
      "dataDescriptorHex",
      "data_descriptor_hex",
    ],
    validators: [isLongEncodedArtifact, isLongHexArtifact],
  },
  {
    name: "encrypted wallet response data assignment",
    fields: ["encryptedDataHex", "encrypted_data_hex"],
    validators: [isLongHexArtifact],
  },
  {
    name: "ephemeral public key assignment",
    fields: ["ephemeralPublicKeyHex", "ephemeral_public_key_hex"],
    validators: [isHexLength(64)],
  },
  {
    name: "request/response hash assignment",
    fields: [
      "requestHashHex",
      "request_hash_hex",
      "unsignedRequestHashHex",
      "unsigned_request_hash_hex",
      "signedRequestHashHex",
      "signed_request_hash_hex",
      "responseHashHex",
      "response_hash_hex",
    ],
    validators: [isHexLength(64)],
  },
].map((detector) => ({
  ...detector,
  patterns: detector.fields.map(fieldAssignmentPattern),
}));

const findings = [];

await scanDirectory(repoRoot);

if (findings.length > 0) {
  console.error("Unlock artifacts are not allowed in durable repository files:");
  for (const finding of findings) {
    console.error(`- ${finding.path}:${finding.line}: ${finding.detector}`);
  }
  process.exit(1);
}

function parseRootArg(args) {
  if (args.length === 0) return defaultRepoRoot;
  if (args.length === 2 && args[0] === "--root") {
    return resolve(process.cwd(), args[1]);
  }

  console.error("usage: node scripts/check-no-unlock-artifacts.mjs [--root <path>]");
  process.exit(2);
}

async function scanDirectory(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;

    const path = join(directory, entry.name);
    const relativePath = normalizePath(relative(repoRoot, path));

    if (entry.isDirectory()) {
      if (
        ignoredDirectoryNames.has(entry.name) ||
        ignoredRelativeDirectories.has(relativePath)
      ) {
        continue;
      }
      await scanDirectory(path);
      continue;
    }

    if (!entry.isFile() || ignoredFiles.has(relativePath)) continue;
    await scanFile(path, relativePath);
  }
}

async function scanFile(path, relativePath) {
  let fileStats;
  try {
    fileStats = await stat(path);
  } catch {
    return;
  }

  if (!fileStats.isFile()) return;

  let content;
  try {
    content = await readFile(path, "utf8");
  } catch {
    return;
  }

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    callbackUrlPattern.lastIndex = 0;
    if (callbackUrlPattern.test(line)) {
      findings.push({
        detector: "live callback URL with write token",
        line: index + 1,
        path: relativePath,
      });
    }

    for (const detector of detectors) {
      for (const pattern of detector.patterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (!match) continue;

        const value = match.groups?.double ?? match.groups?.single ?? match.groups?.bare ?? "";
        if (detector.validators.some((validator) => validator(value))) {
          findings.push({
            detector: detector.name,
            line: index + 1,
            path: relativePath,
          });
          return;
        }
      }
    }
  });
}

function fieldAssignmentPattern(field) {
  return new RegExp(
    String.raw`(?:^|[\s{,])["']?${escapeRegExp(field)}["']?\s*(?::|=)\s*(?:"(?<double>[^"]*)"|'(?<single>[^']*)'|(?<bare>[^\s,}]+))`,
    "i",
  );
}

function isTokenLike(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^[A-Za-z0-9_-]{32,96}$/.test(normalized);
}

function isLongEncodedArtifact(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^[A-Za-z0-9+/_=-]{120,}$/.test(normalized);
}

function isLongHexArtifact(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^(?:0x)?[0-9a-f]{96,}$/i.test(normalized);
}

function isHexLength(length) {
  return (value) => {
    const normalized = cleanLiteral(value);
    if (isPlaceholder(normalized)) return false;
    return new RegExp(`^(?:0x)?[0-9a-f]{${length}}$`, "i").test(normalized);
  };
}

function cleanLiteral(value) {
  return value
    .trim()
    .replace(/^String\(["']?/, "")
    .replace(/["');,]+$/g, "");
}

function isPlaceholder(value) {
  const normalized = value.toLowerCase();
  return (
    normalized === "" ||
    normalized === "..." ||
    normalized.includes("<redacted") ||
    normalized.includes("redacted") ||
    normalized.includes("placeholder") ||
    normalized.includes("{") ||
    normalized.includes("}") ||
    normalized.includes("<") ||
    normalized.includes(">")
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizePath(path) {
  return path.split("\\").join("/");
}
