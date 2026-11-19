# RustyKey — plan

Status: `[ ]` todo, `[~]` in progress, `[x]` accepted. Every task: read `CLAUDE.md`, `docs/SPEC.md`, the cited `docs/PARITY.md` sections and the cited reference TS files. Update `filemap.md` when you add or move files. Every fn gets a one-line `///` doc comment.

## 1. [x] Scaffold — Medium — after: none
Cargo workspace (`crates/onlykey-core`, `crates/rustykey-ui`, `src-tauri`) per SPEC §Architecture, with every core module created as an empty stub with its `///` module doc. Leptos 0.8 CSR app that renders "RustyKey" via Trunk; Tauri 2.12 app whose `frontendDist` is the Trunk output and `beforeDevCommand`/`beforeBuildCommand` run Trunk. `.cargo/config.toml` sets `--cfg=web_sys_unstable_apis` for wasm32. Add `NOTICE` with the upstream BSD licence text (`reference/OnlyKey-App/LICENSE.txt`) and a short credit. `.gitignore`: `target/`, `dist/`, `reference/`. App and tray icons: draw a simple original key glyph (1024 px PNG) and run `cargo tauri icon` on it. Do not reuse the OnlyKey logo (trademark). Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cd crates/rustykey-ui && trunk build`, `cargo build -p rustykey`, and `trunk build --features web`.

## 2. [x] Core: protocol, parser, helpers — Careful — after: 1
`protocol`, `parser`, `device_type`, `encoding`, `backup`, `firmware` (pure parts), `password`, `api` types. Port the logic and the test cases from the matching reference files and their `__tests__` (ResponseParser, deviceTypeFromStatus, firmwareConstants, deviceProduct, configMode, base32, utils, backupVerify, passwordGenerator, firmwareCheck version rules, firmwareDownload asset/digest selection). PARITY §1, §3 (backup, helpers), §4 (password generator), §5 (firmware file + version). Verify: `cargo test -p onlykey-core`; each ported test case named after its TS original.

## 3. [x] Core: device engine — Fable — after: 2
`engine` + `transport::MockDevice`, sans-IO as SPEC §Engine design. Every PARITY §2 method as a `Command`; request queue, single pending, predicates, error windows, sleeps, timeouts, epoch abort on disconnect, error remap, status state machine (auto set-time on unlock, 2500 ms stale echo, config-mode inference, message filter), label collection (400 ms quiet), type transitions, Classic PIN prompt/commit/cancel flush, DUO PIN payloads, chunked OKSETPRIV / OKRESTORE (progress events) / firmware blocks, bootloader trigger. Port `MockTransport.ts` behaviour and the store tests that exercise device behaviour (`hotplugConnect`, `connectAnnounce`, `initialize.dip`, `sessionWipe.security`). Verify: `cargo test -p onlykey-core engine::` with deterministic time; clippy clean.

## 4. [x] Core: key import — Careful — after: 2
`keys`: OpenPGP (rpgp) and SSH/PEM parsing to device bytes + type byte, candidates, Auto Load rules, explicit-slot selection error, backup-passphrase key (sha256), Advanced raw-hex keys, and `Vec<Command>` builders. PARITY §3. Test fixtures: generate keys with `gpg`/`ssh-keygen` (RSA 2048/4096, ed25519/cv25519, P-256, secp256k1 where tools allow), encrypted with a known passphrase, committed under `crates/onlykey-core/tests/fixtures/` (test-only keys). Must compile for wasm32 (`cargo build -p onlykey-core --target wasm32-unknown-unknown`). Verify: tests assert exact bytes (p‖q, scalars) and type bytes.

## 5. [x] Desktop: HID service + commands — Careful — after: 3
`src-tauri/src/device/`: hidapi driver thread per SPEC §src-tauri, interface selection (PARITY §1), 2 s rescan, connect watchdog, unplug detection, permission error → `connect_error`, pending firmware resume on PID B001, events to webview. Tauri commands `device` and `snapshot`; capabilities file. Verify: unit test for interface selection with fake device-info lists; `cargo build -p rustykey`; manual run with a device if available (report if not).

## 6. [ ] Desktop: tray, window, prefs, autostart — Medium — after: 5
SPEC §Tray, §src-tauri Window/Prefs/Autostart: tray menu rebuilt on every change, status line from Snapshot, quick actions, close-to-tray, `--hidden`, single instance, macOS Accessory policy, autostart plugin, prefs store + `prefs_get/prefs_set`, `pick_text_file`, `save_text_file`, `open_url`. Verify: `cargo build -p rustykey`, `cargo tauri dev` run on macOS; screenshot of menu; report what was checked on each OS.

## 7. [ ] Desktop: app + firmware updates — Medium — after: 5
Updater plugin (SPEC §App updates) and firmware fetch (PARITY §5 Firmware, SPEC §Firmware fetch) with commands `app_update_check/install`, `fw_check/fw_download`, once-per-session + pref gating + timeouts. Unit-test the redirect allowlist and digest check with canned JSON. Document key generation (`cargo tauri signer generate`) in `docs/RELEASE.md`. Verify: tests; a live `fw_check` against GitHub returns the current firmware version.

## 8. [ ] UI: shell, bridge, lock screen — Medium — after: 2
Leptos app per SPEC §rustykey-ui and §Design: `Backend` trait + `tauri` impl, state signals, sidebar with all 8 tabs (placeholder pages), status block, DeviceMessages terminal, disconnected overlay, LockScreen (DUO + Classic, 1500 ms poll), WorkingDialog (progress), ConfirmDialog, udev/permission dialog, theme toggle, default-tab rules, epoch keying. Verify: `trunk build`, `cargo tauri dev` screenshots dark + light.

## 9. [ ] UI: Setup wizard — Medium — after: 8, 4
PARITY §4 Setup, Classic and DUO flows, all steps, validation, cancel. Uses core command builders. Verify: `trunk build`; walk every step against `reference/OnlyKey-App/src/components/Setup.tsx` and list them in the report.

## 10. [ ] UI: Slots + editor + generator — Medium — after: 8
PARITY §4 Slots/SlotEditor/Password generator, device photos, DUO profiles, field enable checkboxes, validation, write order (core builder), wipe. Verify: `trunk build`; screenshot Classic + DUO grid with mock data.

## 11. [ ] UI: Keys, Backup, Firmware, Preferences, Advanced, Tools — Medium — after: 8, 4
PARITY §4 for those six pages, including PrivateKeySelectDialog and AppUpdateDialog / FirmwareUpdateDialog. Verify: `trunk build`; per-page control checklist vs the TS component.

## 12. [ ] Web build for ChromeOS — Careful — after: 3, 8
`web` Backend: WebHID driver running the core engine (SPEC §Web build), localStorage prefs, file input / download, connect button, web manifest, hide desktop-only controls. Verify: `trunk build --release --features web`; served locally, Chrome shows the WebHID picker with the OnlyKey filter.

## 13. [ ] Packaging + CI — Medium — after: 6, 7, 12
Tauri bundle config (dmg universal, NSIS, deb with udev rules + postinst, AppImage), GitHub Actions: test/clippy/fmt on 3 OSes; release workflow building installers, signing updater artifacts, publishing `latest.json`; Pages deploy for the web build. Verify: `cargo tauri build` locally on macOS; workflows pass `actionlint`.

## 15. [ ] 1Password sync — Careful — after: 5, 6, 10
SPEC §1Password sync. Core `onepassword` module (pure: item JSON → slot plan via the existing slot builder, limits, otpauth secret, duplicate-tag error, out-of-date logic) with tests on canned `op` JSON (fixtures with fake data only). `src-tauri/src/onepassword.rs`: find `op`, run without a shell, 60 s timeout, `Zeroizing` buffers, commands `op_status`, `op_list`, `op_sync(slots)`, `op_item(id)`; links in prefs; tray item. UI: Slots "Sync from 1Password" + badges, SlotEditor "Fill from 1Password" picker. Verify: `cargo test -p onlykey-core onepassword::`; on this Mac `op` 2.42 is installed — run `op_status`/`op_list` live (report result; do not print secrets).

## 14. [ ] Parity audit — Heavy — after: 9, 10, 11, 12, 13, 15
Walk `docs/PARITY.md` line by line against the Rust code; output a gap list with file:line evidence. No code changes. Verify: every PARITY bullet marked present / missing / dropped.
