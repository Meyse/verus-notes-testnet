# Verus Notes Testnet

Verus Notes is a native encrypted notes app unlocked with a Verus wallet. This
repository contains the public testnet desktop app and the Convex backend used
for ciphertext sync.

The app is currently a testnet alpha. It is meant for trying the wallet unlock,
local encrypted note storage, and encrypted sync flow before any mainnet release.

## What It Does

- Unlocks a note vault through Verus Mobile instead of a password.
- Derives the same local vault from the approved Verus wallet response.
- Encrypts note and folder data on the device before saving or syncing.
- Stores readable note text only while the app is unlocked.
- Syncs ciphertext through Convex when cloud sync is enabled.
- Supports local-only use when Convex is not configured.
- Provides native desktop builds for macOS, Windows, and Linux.

## Wallet Unlock

Verus Notes starts an unlock session and shows a QR code for Verus Mobile. After
approval, the app verifies the signed wallet response in Rust, derives the local
vault material, and opens the workspace.

The app never asks for a seed phrase, WIF, spending key, or extended spending
key. Normal app unlock does not request `FLAG_RETURN_ESK`.

## Notes And Sync

Notes and folders are encrypted client-side. Convex receives encrypted records,
metadata needed for sync, and quota/accounting state. It does not receive raw
note text, folder names, wallet seeds, note keys, vault root keys, or the raw
`incomingViewingKey`.

Cloud sync is optional. Without a Convex URL, the app runs in local-only mode and
keeps the encrypted vault on the device.

## Downloads

Draft testnet builds are published from GitHub Actions:

[Verus Notes Testnet Releases](https://github.com/Meyse/verus-notes-testnet/releases)

Current build artifacts use names like:

- `verus-notes-testnet-...-macos-universal.dmg`
- `verus-notes-testnet-...-windows-nsis.exe`
- `verus-notes-testnet-...-linux-x86_64.AppImage`

The macOS DMG is signed and notarized. The Windows installer is currently
unsigned.

## Local Development

Use Node 22 and pnpm.

```bash
pnpm install
pnpm verify:frontend
pnpm convex:typecheck
cargo test --manifest-path src-tauri/Cargo.toml
```

Run the native app locally:

```bash
export VERUS_NOTES_SIGNER_BASE_URL="https://your-signer.example/testnet"
export VERUS_NOTES_CALLBACK_BASE_URL="https://your-callback.example"
export VERUS_API_BASE_URL="https://your-verus-testnet-api.example"
pnpm tauri dev
```

Cloud sync is enabled when `PUBLIC_CONVEX_URL` or `VITE_CONVEX_URL` is present.
Without that value, the app runs in local-only mode.

## Project Shape

- `src/`: Svelte frontend and notes workspace UI.
- `src-tauri/`: Tauri native shell, Rust wallet verification, vault crypto, and
  local encrypted store.
- `convex/`: Convex sync backend and cloud-auth functions.
- `scripts/`: local verification and regression checks.
- `.github/workflows/`: CI and release builds.

## Verification

```bash
pnpm verify:frontend
pnpm convex:typecheck
cargo test --manifest-path src-tauri/Cargo.toml
```

Frontend verification includes scans for wallet secrets, unlock artifacts, and
local signer residue.

## Security Notes

Verus Notes is designed so the app can sync encrypted data without giving the
cloud or signer readable note content. The deployed signer/callback services are
used to create and verify the wallet unlock flow, while the desktop app owns the
wallet response verification, key derivation, local encryption, and note
decryption.

Do not use this testnet alpha for important notes or mainnet production data.
