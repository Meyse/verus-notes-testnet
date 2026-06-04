import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

const repoRoot = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const blockedPatterns = [
  "127.0.0.1:8791",
  "localhost:8791",
  "devWalletServer",
  "dev:wallet",
  "kms:wallet",
  "VERUS_NOTES_DEV_WALLET_HOST",
  "VERUS_NOTES_DEV_WALLET_PORT",
  "DEFAULT_WALLET_SIGNER_URL",
  "PUBLIC_WALLET_SIGNER_URL",
  "VITE_WALLET_SIGNER_URL",
];
const ignoredDirectories = new Set([
  ".git",
  ".svelte-kit",
  "build",
  "dist",
  "node_modules",
  "target",
]);
const ignoredFiles = new Set([
  "scripts/check-no-local-wallet-signer.mjs",
]);

const findings = [];

await scanDirectory(repoRoot);

if (findings.length > 0) {
  console.error("Local wallet signer residue is not allowed in the app workflow:");
  for (const finding of findings) {
    console.error(`- ${finding.path}:${finding.line}: ${finding.pattern}`);
  }
  process.exit(1);
}

async function scanDirectory(directory) {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const path = join(directory, entry.name);
    const relativePath = relative(repoRoot, path);

    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        await scanDirectory(path);
      }
      continue;
    }

    if (!entry.isFile() || ignoredFiles.has(relativePath)) continue;
    await scanFile(path, relativePath);
  }
}

async function scanFile(path, relativePath) {
  let content;
  try {
    content = await readFile(path, "utf8");
  } catch {
    return;
  }

  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const pattern of blockedPatterns) {
      if (line.includes(pattern)) {
        findings.push({
          line: index + 1,
          path: relativePath,
          pattern,
        });
      }
    }
  });
}
