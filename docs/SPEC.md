# RustyKey — spec

RustyKey is a Rust port of the OnlyKey desktop app (`reference/OnlyKey-App`, v6.0.0). It configures OnlyKey and OnlyKey DUO hardware keys. The feature list is `docs/PARITY.md`; this file says how we build it.

## Goals
1. Every feature in `docs/PARITY.md` works, except items marked **[drop]**.
2. All logic and UI are Rust: device protocol, crypto, storage, and screens (Leptos → WebAssembly).
3. One UI for every platform: macOS, Windows, Linux (Tauri) and ChromeOS (web build in Chrome).
4. A menu bar / tray icon with device status and quick actions on macOS, Windows and Linux.

5. 1Password as the source of truth for slot logins (desktop only, one-way push; §1Password sync).

## Non-goals
- No new device features (no sign/decrypt/getpubkey; the original never sends them).
- No migration of the old NW.js app's autostart entries, Login Items or Dock tiles.
- No file-based tray IPC (`tmp/tray-*.json`); Tauri gives us real IPC.
- No S3 update manifest; we use the Tauri updater with GitHub Releases.
- No tray on ChromeOS (the web build runs in a browser tab / installed web app).
- No UI unit tests in wasm. Logic lives in `onlykey-core` and is tested there. Screens are checked by running the app.

## Stack (pin exact versions in `Cargo.lock`)
- Rust stable (1.99), edition 2024. Workspace with resolver 3.
- Tauri **2.12** (not 3.x alpha) + plugins: `single-instance` 2.5, `autostart` 2.7, `store` 2.5, `dialog` 2.8, `opener` 2.7, `updater` 2.14.
- Leptos **0.8** CSR, built with Trunk 0.22, target `wasm32-unknown-unknown`.
- Device I/O: `hidapi` 2.6 (desktop), WebHID via `web-sys` with `--cfg=web_sys_unstable_apis` (web).
- Crypto/parsing: `pgp` 0.21 (OpenPGP), `ssh-key` 0.6 (OpenSSH), `rsa`/`pkcs8`/`sec1`/`p256`/`k256` (bare PEM), `sha2`, `base64`, `rand`/`getrandom` (with the wasm JS backend).
- HTTP (desktop only): `reqwest` with rustls and a custom redirect policy.

## Architecture

```
crates/onlykey-core   pure Rust, no Tauri, builds for native AND wasm32
crates/rustykey-ui    Leptos app; one Backend trait, two impls (tauri | web)
src-tauri             desktop shell: HID driver thread, tray, prefs, updates
```

### onlykey-core
Modules:
- `protocol` — MessageID/FieldID/constants, packet framing, keyboard layouts, slot maps, USB IDs.
- `parser` — ResponseParser port (`Response` enum) and label slot mapping.
- `device_type` — Classic/DUO/Unknown detection and allowed transitions.
- `engine` — the device engine (below).
- `transport` — `MockDevice` test double that answers like firmware (port of `MockTransport.ts`).
- `keys` — OpenPGP + SSH/PEM parsing, key type byte, bundle candidates, Auto Load rules.
- `backup` — parse, verify (hash chain), file name, restore payload.
- `firmware` — firmware file → blocks, version compare, in-app-support rule, release-asset selection and digest extraction (pure; the HTTP lives in src-tauri).
- `password` — password generator (takes an `RngCore`).
- `encoding` — base32→bytes, hex↔modhex, Latin-1 check.
- `api` — serde types shared with the UI (below).
- `onepassword` — 1Password item JSON → slot write plan, limits, otpauth parsing, link tracking (pure; see §1Password sync).

**Engine design: sans-IO.** The engine does no I/O and reads no clock. Drivers feed it events and timestamps:

```rust
/// Device engine: owns protocol state; callers drive it with input reports and time.
pub struct Engine { /* queue, pending step, status state machine, epoch, labels */ }
impl Engine {
    pub fn submit(&mut self, cmd: Command, now: Millis) -> RequestId;
    pub fn on_report(&mut self, report: &[u8; 64], now: Millis);
    pub fn on_connected(&mut self, pid: u16, now: Millis);
    pub fn on_disconnected(&mut self, now: Millis);
    pub fn on_tick(&mut self, now: Millis);          // timeouts and sleeps
    pub fn next_deadline(&self) -> Option<Millis>;   // when to call on_tick next
    pub fn poll_output(&mut self) -> Option<Output>; // packets to write, events, replies
}
pub enum Output { Write([u8; 64]), Event(Event), Reply(RequestId, Result<Reply, DeviceError>) }
```

Why: the same engine runs under a blocking hidapi thread (desktop) and a JS event loop (web), and tests drive time exactly (2500 ms stale echo, 400 ms label quiet, 200 ms error windows) with no sleeps. Each `Command` compiles to a list of steps (`Write`, `ErrorWindow(ms)`, `WaitFor(predicate, timeout)`, `Sleep(ms)`), so chunked flows (OKSETPRIV, OKRESTORE, firmware) are just longer step lists. Timing, matching text and error remapping must match PARITY §1–2 exactly.

### api types (shared by engine, src-tauri and UI)

```rust
pub enum DeviceKind { Unknown, Classic, Duo }
pub enum DeviceState { Disconnected, Bootloader, Uninitialized, Locked, Unlocked, ConfigMode }
pub struct Snapshot {
    pub state: DeviceState, pub kind: DeviceKind,
    pub firmware: Option<String>, pub pin_set: bool,
    pub product_name: String,
    pub labels: [Option<String>; 24],   // empty while locked
    pub session_epoch: u64,             // bumps on unplug and on unlocked→locked
    pub connect_error: Option<String>,  // drives the udev / permission dialog
}
pub enum Event { Snapshot(Snapshot), Message(String), Progress { percent: u8, text: String } }
pub enum Command { /* one variant per PARITY §2 method, e.g. */
    SetTime, RefreshStatus, GetLabels,
    SetSlot { slot: u8, field: u8, value: Vec<u8> }, WipeSlot { slot: u8, field: Option<u8> },
    ClassicPin { which: PinKind, phase: PinPhase }, CancelClassicPin { which: PinKind },
    DuoPin { pins: DuoPins, setup: bool },
    SetPrivateKey { slot: u8, key_type: u8, bytes: Vec<u8> }, WipePrivateKey { slot: u8 },
    SetGlobal { field: u8, value: u8 },  // all PARITY §2 preference setters
    SetYubiAuth { .. }, WipeYubiAuth, Restore { payload: Vec<u8> },
    TriggerBootloader, LoadFirmware { blocks: Vec<Vec<u8>> },
}
```

Higher-level helpers (slot save plan, key import, backup passphrase, Auto Load) live in core as functions that return `Vec<Command>`, so the desktop and web backends behave the same. Errors cross the bridge as a `DeviceError` enum with a display message matching the original text.

### src-tauri
- **HID driver thread** (`device/`): owns `HidApi` and the `Engine`. Loop: read with ~20 ms timeout → `on_report`; drain a command channel → `submit`; call `on_tick` at `next_deadline`; write packets; emit events to the webview (`device://event`) and to the tray. Pick the interface by PARITY §1 rules (never the keyboard interface). Disconnected: rescan every 2 s. Unplug = read/write error. (Pending firmware after a bootloader trigger is held and resumed by the engine on the next connect with PID 0xB001.)
- **Tauri commands** (all `async`; `device` returns `Result<Reply, DeviceError>` as JSON, the rest `Result<_, String>`): `device(cmd: Command) -> Reply`, `snapshot() -> Snapshot`, `prefs_get`, `prefs_set`, `pick_text_file(filters) -> Option<(name, String)>`, `save_text_file(default_name, text) -> bool`, `open_url(url)` (https only), `app_update_check(force)`, `app_update_install`, `fw_check(force)`, `fw_download() -> blocks`.
- **Prefs** (`tauri-plugin-store`, `settings.json` in the app config dir): `autostart`, `auto_update`, `auto_update_fw`, `close_to_tray` (`autostart` mirrors the OS state; the others default `true`), `theme` (`"dark"`), `slot_editor_mode`. Session-only flags stay in memory.
- **Window**: 1024×768, min 800×400, centred, starts hidden; shown unless launched with `--hidden`. Single instance: a second launch shows the window. Close button: hide if `close_to_tray`, else quit. Cmd+Q / tray Quit / logout always quit. macOS: hidden window → `ActivationPolicy::Accessory` (menu-bar only, no Dock icon); shown → `Regular`.
- **Autostart**: `tauri-plugin-autostart` with args `["--hidden"]` (LaunchAgent on macOS). As in the original app, the `autostart` pref mirrors the OS login-item state (`isEnabled()` at start) and only a user toggle changes it; RustyKey never creates a login item on its own.
- **Prefs sync**: `prefs_set(patch)` merges only the keys sent; after any change (UI or tray) the host emits `host://prefs-changed` with the full prefs and the UI replaces its copy. `show_window()` shows and focuses the window (used by update prompts; the tray's Check for Updates also shows it).
- **App updates**: `tauri-plugin-updater`, endpoint `https://github.com/horknfbr/rustykey-app/releases/latest/download/latest.json`, signed with a minisign key (public key in `tauri.conf.json`; private key only in CI secrets). Linux `.deb` installs cannot self-update: show "Open release page" instead.
- **Firmware fetch**: PARITY §5 Firmware rules (host allowlist on every redirect hop, SHA-256 required and checked). Parsing and asset selection come from `onlykey_core::firmware`.

### Tray / menu bar
One tray icon (monochrome template on macOS). Tooltip = status line (macOS/Windows). Menu, rebuilt in full on every change (never edited in place — Linux bug):

```
OnlyKey Duo — Unlocked · v3.0.4p      (disabled; or "No OnlyKey connected" / "Locked" / "Bootloader")
Open RustyKey
Set Device Time Now                   (enabled only when unlocked)
Sync from 1Password                   (enabled when unlocked and `op` found)
Check for Updates…                    (app + firmware, forced)
──────────
✓ Start at Login (in tray)
✓ Check App Updates Automatically
✓ Check Firmware Updates Automatically
✓ Hide to Tray When Window Closes
──────────
Quit RustyKey
```
Left click: Windows/Linux show the window; macOS opens the menu. Two icon variants: connected and not connected.

### rustykey-ui
- `Backend` trait with two impls chosen by cargo feature: `tauri` (calls `invoke` / `listen` through `wasm-bindgen` on `window.__TAURI__`, `withGlobalTauri: true`) and `web` (runs `onlykey-core::Engine` in the page with a WebHID driver, browser file input / download, `localStorage` prefs, `window.open` for links).
- App state: one `Snapshot` signal + messages list (50, newest first) + working/progress signal. Every page, LockScreen, SlotEditor and WorkingDialog is keyed on `session_epoch`, so local secrets drop on remount.
- Screens and dialogs: exactly PARITY §4.

### Web build (ChromeOS)
- Same UI crate with `--features web`; static files, served over HTTPS (GitHub Pages), with a web app manifest so it can be installed to the ChromeOS shelf.
- WebHID: first connect needs a click ("Connect OnlyKey" button → `navigator.hid.requestDevice` with the PARITY USB IDs). Later visits use `navigator.hid.getDevices()` and `connect`/`disconnect` events.
- Not in the web build: tray, autostart, close-to-tray, app updater. Firmware "Download Latest" is hidden (GitHub asset downloads have no CORS); loading a firmware file works.

### 1Password sync (desktop only)
1Password is the source of truth for slot logins. Sync is one way: 1Password → OnlyKey (the device cannot give passwords back).
- **Mechanism:** run the 1Password CLI `op` (2.x) as a child process, no shell, with the desktop-app integration (Touch ID / Windows Hello). No Rust SDK exists; no service-account tokens. Find `op` on `PATH`, then `/opt/homebrew/bin/op`, `/usr/local/bin/op`, `%LOCALAPPDATA%\Microsoft\WinGet\Links\op.exe`, `C:\Program Files\1Password CLI\op.exe`. Timeout 60 s per call (the user may be at the Touch ID prompt). Pref `op_account` (optional) → `--account`.
- **Linking:** an item is linked to a slot by the tag `onlykey/slot-N` (N = 1–24; Classic uses 1–12, shown as 1a–6b). `op item list --tags onlykey --format json` lists candidates; `op item get <id> --format json --reveal` reads one item right before writing it. Two items with the same slot tag → error for that slot, nothing written.
- **Field mapping:** label = custom field named `onlykey label` if present, else item title; username = field with purpose USERNAME; password = purpose PASSWORD; URL = first URL; TOTP = first field of type OTP → secret from its `otpauth://` URI. Sync writes only these fields; delays and tab/return keys set in the slot editor stay on the device.
- **Limits:** label ≤ 16, URL/username/password ≤ 56, Latin-1 only, TOTP ≤ 57 bytes, DUO-without-PIN rules (PARITY §4 SlotEditor): on a DUO without PIN, sync writes label + password only (plus TOTP only if there is no password) and the result says username/URL were left out. An item that breaks a limit is skipped with a reason; others continue.
- **Out-of-date check:** prefs keep `onepassword_links: { slot → { item_id, vault_id, version } }` — no secrets. When the item `version` in 1Password is newer, the slot shows "out of date". A removed tag never wipes the slot (the user wipes by hand).
- **UI:** Slots page: "Sync from 1Password" (all linked slots, shows per-slot result) and a link badge per slot (linked / out of date). Slot editor: "Fill from 1Password" (pick an item, fills the form; the user still clicks Save). Tray: "Sync from 1Password" (enabled when unlocked and `op` found). Needs the device unlocked.
- **Security:** secrets from `op` stdout live only in memory until written, in `Zeroizing` buffers; never logged; stderr is passed to the user only after filtering to the first line.
- Pure parts (item JSON → slot plan, limits, otpauth parsing, link/out-of-date logic) live in `onlykey_core::onepassword`; process running lives in `src-tauri/src/onepassword.rs`.

### Linux packaging
Ship `/etc/udev/rules.d/49-rustykey.rules` covering all USB IDs in PARITY §1 (MODE 0660 + `TAG+="uaccess"`, plus `ID_MM_DEVICE_IGNORE` / `MTP_NO_PROBE`), and a `postinst` that runs `udevadm control --reload-rules && udevadm trigger`. Bundles: `.deb` and AppImage. macOS: universal `.dmg`. Windows: NSIS `.exe`.

## Design
Keep the original layout and wording. Users switching from the official app must find every control where it was.

```
┌──────────────┬──────────────────────────────────────────────┐
│ [logo]   ◐   │  Setup                                       │
│              │                                              │
│ ▸ Setup      │   (page content, max-width 760px)            │
│   Slots      │                                              │
│   Keys       │                                              │
│   Backup     │                                              │
│   Firmware   │                                              │
│   Preferences│                                              │
│   Advanced   │                                              │
│   Tools      │                                              │
│              ├──────────────────────────────────────────────┤
│ RustyKey 0.1 │ > UNLOCKEDv3.0.4p                         ▲  │
│ ● Connected  │ > Successfully set time                   ▼  │
│ OnlyKey Duo  │   (5-line device message terminal)           │
│ Unlocked     │                                              │
└──────────────┴──────────────────────────────────────────────┘
```
- Sidebar 220 px. Active tab: left accent bar + bold. Status dot: green connected, grey not.
- Tokens on `:root`, dark default, `.light` class for light: `--bg #121417 / #f6f7f9`, `--surface #1b1e23 / #ffffff`, `--text #e7e9ec / #1b1e23`, `--muted #9aa1ab / #5b6470`, `--accent #3fa7ff / #0a6ccf`, `--danger #ff5c5c / #c62828`, `--ok #3ecf8e / #1e8e5a`. System font stack. 8 px spacing grid. Radius 6 px.
- Modals: centred card, max 640 px, dim backdrop, Esc closes (except WorkingDialog).
- Device photos and logos: copy from `reference/OnlyKey-App/public/images` and `resources/` (BSD licence; credit in `NOTICE`). RustyKey's own icon goes in the tray and app icon.
- Text says "RustyKey — for OnlyKey devices". Device-facing text (instructions, errors) keeps the original wording.

## Security rules
- No secret (PIN, passphrase, password, key, TOTP seed, backup text) is logged, stored, or kept after the command finishes. Not in prefs, not in Snapshot, not in events.
- External URLs: https only, opened in the system browser.
- Firmware downloads: allowlist + SHA-256 as PARITY §5. Manual files are passed as-is (bootloader checks the signature).
- Tauri capabilities: only the commands above; no shell, no fs plugin exposed to the webview.

## Definition of done (MVP = full parity)
1. `cargo test --workspace` passes; core tests cover parser, device type, engine flows (connect, unlock + auto set-time, stale echo, labels, PIN flows, chunked key/restore/firmware, error remap, disconnect abort), keys, backup verify, firmware parse/compare, password generator.
2. `cargo clippy --workspace --all-targets -- -D warnings` is clean.
3. `cargo tauri build` produces installers on macOS, Windows, Linux (CI).
4. The web build runs in Chrome and connects over WebHID.
5. A person with a real OnlyKey and a real DUO walks the checklist in `docs/PARITY.md` and every item works.
