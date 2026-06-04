import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const scannerPath = fileURLToPath(new URL("check-no-unlock-artifacts.mjs", import.meta.url));

const unsafeRoot = await mkdtemp(join(tmpdir(), "verus-notes-unsafe-unlock-artifacts-"));
const safeRoot = await mkdtemp(join(tmpdir(), "verus-notes-safe-unlock-artifacts-"));

try {
  const requestId = "request12345678901234567890123456789012";
  const writeToken = "write1234567890123456789012345678901234";
  const pollToken = "poll12345678901234567890123456789012345";
  const encodedResponse = "A".repeat(160);
  const requestHashHex = "0123456789abcdef".repeat(4);
  const encryptedDataHex = "abcdef0123456789".repeat(8);

  await writeFile(
    join(unsafeRoot, "latest-unlock-artifacts.json"),
    JSON.stringify(
      {
        callbackUrl: `https://callback.example.test/wallet-callback/${requestId}/${writeToken}`,
        encryptedDataHex,
        pollToken,
        requestHashHex,
        responseBase64Url: encodedResponse,
      },
      null,
      2,
    ),
  );

  const unsafeResult = await runScanner(unsafeRoot);
  assert.equal(unsafeResult.status, 1);
  assert.match(unsafeResult.stderr, /live callback URL with write token/);
  assert.match(unsafeResult.stderr, /callback mailbox token assignment/);
  assert.match(unsafeResult.stderr, /live responseBase64Url assignment/);
  assert.match(unsafeResult.stderr, /request\/response hash assignment/);
  assert.match(unsafeResult.stderr, /encrypted wallet response data assignment/);
  assert.doesNotMatch(`${unsafeResult.stdout}\n${unsafeResult.stderr}`, new RegExp(writeToken));
  assert.doesNotMatch(`${unsafeResult.stdout}\n${unsafeResult.stderr}`, new RegExp(pollToken));
  assert.doesNotMatch(`${unsafeResult.stdout}\n${unsafeResult.stderr}`, new RegExp(encodedResponse));

  await writeFile(
    join(safeRoot, "protocol-doc-snippet.md"),
    [
      'callbackUrl: "https://callback.example.test/wallet-callback/{requestId}/{writeToken}"',
      'pollToken: "<redacted>"',
      'responseBase64Url: "..."',
      'requestHashHex: "request-hash"',
      "GenericResponse and DataDescriptor are protocol type names here.",
    ].join("\n"),
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
