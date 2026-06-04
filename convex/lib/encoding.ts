import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64URL_LOOKUP = new Map(
  Array.from(BASE64URL_ALPHABET, (char, index) => [char, index]),
);

export function encodeBase64Url(bytes: Uint8Array): string {
  let output = "";

  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const chunk = (first << 16) | (second << 8) | third;

    output += BASE64URL_ALPHABET[(chunk >> 18) & 63];
    output += BASE64URL_ALPHABET[(chunk >> 12) & 63];

    if (index + 1 < bytes.length) {
      output += BASE64URL_ALPHABET[(chunk >> 6) & 63];
    }

    if (index + 2 < bytes.length) {
      output += BASE64URL_ALPHABET[chunk & 63];
    }
  }

  return output;
}

export function decodeBase64Url(name: string, value: string, expectedLength?: number): Uint8Array {
  if (value.length % 4 === 1) {
    throw new Error(`${name} is invalid base64url`);
  }

  const bytes: number[] = [];

  for (let index = 0; index < value.length; index += 4) {
    const first = decodeChar(name, value[index]);
    const second = decodeChar(name, value[index + 1]);
    const third = value[index + 2] === undefined ? 0 : decodeChar(name, value[index + 2]);
    const fourth = value[index + 3] === undefined ? 0 : decodeChar(name, value[index + 3]);
    const chunk = (first << 18) | (second << 12) | (third << 6) | fourth;

    bytes.push((chunk >> 16) & 255);

    if (index + 2 < value.length) {
      bytes.push((chunk >> 8) & 255);
    }

    if (index + 3 < value.length) {
      bytes.push(chunk & 255);
    }
  }

  const decoded = Uint8Array.from(bytes);

  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw new Error(`${name} must decode to ${expectedLength} bytes`);
  }

  return decoded;
}

export function randomBase64Url(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

export function sha256Base64Url(bytes: Uint8Array): string {
  return encodeBase64Url(sha256(bytes));
}

export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function decodeChar(name: string, value: string | undefined): number {
  if (value === undefined) {
    throw new Error(`${name} is invalid base64url`);
  }

  const decoded = BASE64URL_LOOKUP.get(value);

  if (decoded === undefined) {
    throw new Error(`${name} is invalid base64url`);
  }

  return decoded;
}
