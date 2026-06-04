import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const scannerPath = fileURLToPath(new URL("check-no-wallet-secrets.mjs", import.meta.url));

const unsafeRoot = await mkdtemp(join(tmpdir(), "verus-notes-unsafe-secret-scan-"));
const safeRoot = await mkdtemp(join(tmpdir(), "verus-notes-safe-secret-scan-"));

try {
  const fakeIvk = Array.from({ length: 32 }, (_, index) =>
    (index + 1).toString(16).padStart(2, "0"),
  ).join("");

  await writeFile(
    join(unsafeRoot, "latest-unsafe-unlock-payload.json"),
    JSON.stringify(
      {
        warning: "test fixture",
        incomingViewingKeyHex: fakeIvk,
      },
      null,
      2,
    ),
  );

  const unsafeResult = await runScanner(unsafeRoot);
  assert.equal(unsafeResult.status, 1);
  assert.match(unsafeResult.stderr, /raw incomingViewingKeyHex assignment/);
  assert.doesNotMatch(`${unsafeResult.stdout}\n${unsafeResult.stderr}`, new RegExp(fakeIvk));

  const fakeHash = Array.from({ length: 32 }, (_, index) =>
    (255 - index).toString(16).padStart(2, "0"),
  ).join("");

  await writeFile(
    join(safeRoot, "safe-summary.json"),
    JSON.stringify(
      {
        incomingViewingKey: "<redacted>",
        incomingViewingKeySha256: fakeHash,
        noteRootKey: "redacted",
      },
      null,
      2,
    ),
  );

  const safeResult = await runScanner(safeRoot);
  assert.equal(safeResult.status, 0, safeResult.stderr);
} finally {
  await Promise.all([
    rm(unsafeRoot, { force: true, recursive: true }),
    rm(safeRoot, { force: true, recursive: true }),
  ]);
}

function runScanner(root) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scannerPath, "--root", root], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}
