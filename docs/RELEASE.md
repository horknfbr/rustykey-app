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

## Cutting a release
1. Bump `version` in `src-tauri/tauri.conf.json` (and the workspace `Cargo.toml`), commit, push to `main`.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. `.github/workflows/release.yml` builds macOS (universal `.dmg` + `.app.tar.gz`), Windows (NSIS `-setup.exe`)
   and Linux (`.deb` + `.AppImage`), signs the updater artifacts, and uploads them plus `latest.json` to a
   **draft** release named after the tag.
4. Check the draft on GitHub, then click **Publish release**. The updater only sees published releases
   (`releases/latest/download/latest.json` ignores drafts and pre-releases).

`TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (above) are required; the release fails without
them. Repository → Settings → Secrets and variables → Actions → New repository secret.

## Unsigned macOS and Windows builds
Until code-signing secrets are added, installers are unsigned (the updater signature above is separate and always
present).
- macOS: Gatekeeper blocks the first launch ("cannot be opened because the developer cannot be verified"). Users
  right-click the app → Open, or run `xattr -dr com.apple.quarantine /Applications/RustyKey.app`.
- Windows: SmartScreen shows "Windows protected your PC". Users click More info → Run anyway.

To sign later, add these secrets; the release workflow picks them up and skips signing when they are absent:
- macOS (Developer ID Application certificate + notarization): `APPLE_CERTIFICATE` (base64 of the `.p12`),
  `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY` (e.g. `Developer ID Application: Name (TEAMID)`),
  `APPLE_ID`, `APPLE_PASSWORD` (app-specific password), `APPLE_TEAM_ID`.
- Windows (Authenticode `.pfx`): `WINDOWS_CERTIFICATE` (base64 of the `.pfx`), `WINDOWS_CERTIFICATE_PASSWORD`.
  The workflow imports it and passes its thumbprint as `bundle.windows.certificateThumbprint`.

## Linux udev rules
The `.deb` installs `/etc/udev/rules.d/49-rustykey.rules` (every OnlyKey USB ID, `TAG+="uaccess"`, mode 0660) and
reloads udev in its post-install script. The AppImage cannot install system files: AppImage users install the rules
once by hand with `sudo curl -fsSL -o /etc/udev/rules.d/49-rustykey.rules
https://raw.githubusercontent.com/horknfbr/rustykey-app/main/src-tauri/resources/linux/49-rustykey.rules && sudo
udevadm control --reload-rules && sudo udevadm trigger`, then unplug and replug the OnlyKey. Without the rules the
app cannot open the device.

## Web build (GitHub Pages)
`.github/workflows/pages.yml` builds the ChromeOS web app (`trunk build --release --config Trunk.web.toml`) on every
push to `main` and deploys `crates/rustykey-ui/dist-web/` to `https://horknfbr.github.io/rustykey-app/`. One-time
setup: repository → Settings → Pages → Build and deployment → Source: **GitHub Actions**.
