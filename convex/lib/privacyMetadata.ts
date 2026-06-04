import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { utf8Bytes } from "./encoding";

const METADATA_HASH_PROTOCOL = "hmac-sha256-v1";

export function metadataHash(kind: "app-identity" | "wallet-signer-identity", value: string) {
  const digest = hmac(
    sha256,
    metadataHashSecret(),
    utf8Bytes(`verus-notes/metadata/${kind}/v1\0${value}`),
  );
  return `${METADATA_HASH_PROTOCOL}:${bytesToHex(digest)}`;
}

function metadataHashSecret() {
  const secret = process.env.CONVEX_METADATA_HASH_SECRET;
  if (!secret) {
    throw new Error("CONVEX_METADATA_HASH_SECRET is required for metadata hashing");
  }
  return utf8Bytes(secret);
}
