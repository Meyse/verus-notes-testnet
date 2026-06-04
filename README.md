# Verus Notes Testnet

Native encrypted notes app for the Verus testnet wallet unlock flow.

This repository contains the desktop app and Convex backend code needed for
public testnet builds. The deployed signer and callback infrastructure are
configured outside this repository.

## Local Development

```bash
pnpm install
pnpm verify:frontend
pnpm convex:typecheck
cd src-tauri
cargo test
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

## Release Configuration

Release builds need these GitHub repository or environment variables:

- `VERUS_NOTES_SIGNER_BASE_URL`
- `VERUS_NOTES_CALLBACK_BASE_URL`

Release builds need these GitHub secrets or protected-environment secrets:

- `PUBLIC_CONVEX_URL`
- `PUBLIC_CONVEX_SITE_URL`
- `VERUS_API_BASE_URL`
- `APPLE_CERTIFICATE`
- `APPLE_CERTIFICATE_PASSWORD`
- `KEYCHAIN_PASSWORD`
- `APPLE_API_ISSUER`
- `APPLE_API_KEY`
- `APPLE_API_KEY_PRIVATE_BASE64`

`VERUS_NOTES_SIGNER_BASE_URL`, `VERUS_NOTES_CALLBACK_BASE_URL`, and
`VERUS_API_BASE_URL` are compiled into the native app at build time. The signer
and callback URLs are public app configuration. Do not print secret values from
workflows.

Convex deployment env vars used by the backend:

- `CONVEX_AUTH_ATTESTATION_MODE`
- `CONVEX_ATTESTATION_SIGNER_URL`
- `CONVEX_ATTESTATION_EDGE_SECRET`
- `CONVEX_METADATA_HASH_SECRET`

Production testnet deployments should keep signer attestation required.

## Verification

```bash
pnpm verify:frontend
pnpm convex:typecheck
cargo test --manifest-path src-tauri/Cargo.toml
```

The frontend verification includes local scans for wallet secrets, unlock
artifacts, and local signer residue.
