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
const ignoredRelativeDirectories = new Set(["app/src-tauri/gen"]);
const ignoredFiles = new Set(["scripts/check-no-wallet-secrets.mjs"]);
const detectors = [
  {
    name: "raw incomingViewingKeyHex assignment",
    fields: ["incomingViewingKeyHex", "incoming_viewing_key_hex"],
    validators: [isHexSecret],
  },
  {
    name: "raw incomingViewingKey assignment",
    fields: ["incomingViewingKey", "incoming_viewing_key"],
    validators: [isHexSecret, isEncodedSecret],
  },
  {
    name: "wallet-derived root key assignment",
    fields: [
      "vaultRootKey",
      "vault_root_key",
      "rootKey",
      "root_key",
      "noteRootKey",
      "note_root_key",
      "folderRootKey",
      "folder_root_key",
      "localCacheKey",
      "local_cache_key",
      "exportArchiveKey",
      "export_archive_key",
    ],
    validators: [isHexSecret, isEncodedSecret],
  },
  {
    name: "wallet-derived note/folder key assignment",
    fields: ["noteKey", "note_key", "folderKey", "folder_key"],
    validators: [isHexSecret, isEncodedSecret],
  },
  {
    name: "backend auth secret assignment",
    fields: [
      "backendAuthSeed",
      "backend_auth_seed",
      "backendAuthPrivateKey",
      "backend_auth_private_key",
    ],
    validators: [isHexSecret, isEncodedSecret],
  },
  {
    name: "wallet seed assignment",
    fields: [
      "walletSeed",
      "wallet_seed",
      "seedPhrase",
      "seed_phrase",
      "mnemonic",
    ],
    validators: [isSeedPhrase, isEncodedSecret],
  },
  {
    name: "wallet WIF assignment",
    fields: ["wif", "walletWif", "wallet_wif"],
    validators: [isWifLike],
  },
  {
    name: "private key assignment",
    fields: ["privateKey", "private_key", "secretKey", "secret_key"],
    validators: [isPemPrivateKey, isHexSecret, isEncodedSecret],
  },
  {
    name: "extended spending key assignment",
    fields: [
      "extendedSpendingKey",
      "extended_spending_key",
      "extendedSpendingKeyHex",
      "extended_spending_key_hex",
    ],
    validators: [isHexSecret, isEncodedSecret],
  },
].map((detector) => ({
  ...detector,
  patterns: detector.fields.map(fieldAssignmentPattern),
}));

const findings = [];

await scanDirectory(repoRoot);

if (findings.length > 0) {
  console.error("Wallet secret material is not allowed in this repository:");
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

  console.error("usage: node scripts/check-no-wallet-secrets.mjs [--root <path>]");
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

function isHexSecret(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^(?:0x)?[0-9a-f]{64,}$/i.test(normalized);
}

function isEncodedSecret(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^[A-Za-z0-9+/_=-]{43,}$/.test(normalized);
}

function isSeedPhrase(value) {
  const normalized = cleanLiteral(value).toLowerCase();
  if (isPlaceholder(normalized)) return false;
  return normalized.split(/\s+/).filter(Boolean).length >= 12;
}

function isWifLike(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50,90}$/.test(
    normalized,
  );
}

function isPemPrivateKey(value) {
  const normalized = cleanLiteral(value);
  if (isPlaceholder(normalized)) return false;
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(normalized);
}

function isPlaceholder(value) {
  return (
    value.length === 0 ||
    /(?:redacted|placeholder|example|dummy|sample|test-only|todo|missing)/i.test(value) ||
    /[<>{}$]/.test(value) ||
    /\.{3,}/.test(value) ||
    /x{4,}/i.test(value)
  );
}

function cleanLiteral(value) {
  return value.trim().replace(/[;,)]+$/g, "");
}

function normalizePath(path) {
  return path.split("\\").join("/");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
