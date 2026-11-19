# Releasing RustyKey

## Updater signing key
App updates use `tauri-plugin-updater`. Every update bundle is signed with a minisign key; the app only installs
bundles whose signature matches the public key in `src-tauri/tauri.conf.json` (`plugins.updater.pubkey`).

- Generate (once): `cargo tauri signer generate -w ~/.tauri/rustykey.key` (an empty password is allowed for now).
- Private key: `~/.tauri/rustykey.key` on the maintainer's machine, plus the CI secret below. Never commit it.
- Public key: `~/.tauri/rustykey.key.pub`; its contents go in `plugins.updater.pubkey`.
- Losing the private key means installed apps can no longer update: they reject bundles signed by a new key.
  Back it up somewhere safe. Rotating it needs one release, signed with the old key, that ships the new pubkey.

## CI secrets
- `TAURI_SIGNING_PRIVATE_KEY` — contents of `~/.tauri/rustykey.key` (or the path to it).
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — its password (empty for now).

With these set, `cargo tauri build` signs the updater artifacts (`bundle.createUpdaterArtifacts: true`).

## Update manifest
The app checks `https://github.com/horknfbr/rustykey-app/releases/latest/download/latest.json`, so every release
must attach a `latest.json` (version, notes, and per-platform URL + signature) to the GitHub release.

Linux `.deb` installs do not self-update; the app shows "Open release page" instead. AppImage, macOS and Windows
installs update in place and restart.
