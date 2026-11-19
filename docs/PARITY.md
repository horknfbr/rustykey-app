# Parity inventory — OnlyKey-App 6.0.0 → RustyKey

Source of truth for "all functionality". Reference checkout: `reference/OnlyKey-App` (upstream commit `6ba3280`, gitignored; re-clone with `git clone https://github.com/trustcrypto/OnlyKey-App reference/OnlyKey-App`). All paths below are relative to that checkout. When this file and the TS source disagree, the TS source wins; fix this file.

Items marked **[drop]** are intentionally not ported (see SPEC.md §Non-goals). Items marked **[changed]** are ported with a different mechanism.

## 1. HID protocol

### MessageID (`src/api/device/types.ts:1-16`)
- 0xE1 OKSETPIN. Classic: an empty packet starts the keypad PIN state machine. DUO: the data carries the PIN.
- 0xE2 OKSETSDPIN, self-destruct PIN, keypad state machine (Classic).
- 0xE3 OKSETPIN2, second-profile PIN (Classic).
- 0xE4 OKSETTIME, 4 bytes of unix seconds, big-endian. Also serves as the lock-status probe.
- 0xE5 OKGETLABELS, streams one label per packet.
- 0xE6 OKSETSLOT, 0xE7 OKWIPESLOT.
- 0xEC OKGETPUBKEY, 0xED OKSIGN, 0xF0 OKDECRYPT: defined but never sent by the app.
- 0xEE OKWIPEPRIV, 0xEF OKSETPRIV (chunked).
- 0xF1 OKRESTORE (chunked), 0xF4 OKFWUPDATE (bootloader trigger and firmware blocks).

### FieldID (`types.ts:18-49`)
- Slot fields: LABEL 1, USERNAME 2, NEXTKEY2 3 (after password), DELAY2 4, PASSWORD 5, NEXTKEY3 6 (after OTP), DELAY3 7, TFATYPE 8, TFAUSERNAME 9 (TOTP secret bytes), YUBIAUTH 10, URL 15, NEXTKEY1 16 (after username), DELAY1 17, NEXTKEY4 18 (before username), NEXTKEY5 19 (before OTP), YUBIANDHMAC 29 (unused).
- Global fields (slot byte 0, "XX"): LOCKOUT 11, WIPEMODE 12, TYPE_SPEED 13, KBD_LAYOUT 14, BACKUPKEYMODE 20, DERIVED_CHALLENGE_MODE 21, STORED_CHALLENGE_MODE 22, SEC_PROFILE_MODE 23, LED_BRIGHTNESS 24, LOCK_BUTTON 25, HMAC_CHALLENGE_MODE 26, MODKEY_MODE 27 (Sysadmin), WEB_AGENT_DERIVE_MODE 30, WEBCRYPT_POLICY 31.
- Constants: MESSAGE_HEADER FF FF FF FF, PACKET_SIZE 64, GLOBAL_SLOT 0 (`types.ts:86-89`).

### firmwareConstants.ts
- KEYBOARD_LAYOUTS 0x01–0x1C, 28 entries, each with a display label (`:9-70`).
- WIPE_MODES: 0 Off, 1 On; WIPE_MODE_FULL = 2 (`:76-81`).
- MFA type byte: 'g' = Google/TOTP, 'Y' = Yubico OTP (`:87-88`).
- NEXTKEY values (`:96-112`): after username/password 0 none, 1 tab, 2 return; before username/OTP 0 none, 1 tab; after OTP adds 3 = tab+return.
- DUO PIDs {0x614C, 0x614E, 0x4211}. `deviceTypeFromProductId`: 0x0486 → Classic, 0xB001 → bootloader; 0x60FC ambiguous (`:115-123`).
- `firmwareAtLeast` compares major.minor.patch (`:127`). `isDuoNoPinVersion` = last char is 'n' (`:136`).
- DUO_PROFILES: green, blue, yellow, purple.
- CLASSIC_SLOT_ROWS: buttons 1–6, "a" = slot 1–6, "b" = slot 7–12.
- DUO_PROFILE_COLUMNS: slots 1–24, 6 per profile, physical column order 1|3|2 (`:150-204`).

### USB IDs (`src/store/useDeviceStore.ts:94-101`), tried in this order
- 1D50:614C, 1D50:614E, 20A0:4211 — DUO
- 16C0:0486 — Classic, pre-Beta 8
- 1D50:60FC — Beta 7+ or DUO; type comes from firmware
- 0000:B001 — bootloader

### HID interface selection (`src/api/transport/ChromeHidTransport.ts:141-159`)
- Bootloader: take the first match.
- Otherwise prefer the interface with usage page 0xFFAB (Beta 8+, serial 1000000000).
- Else any interface whose serial is not 1000000000 and that is not purely a 0x01 keyboard, 0xF1D0 FIDO or 0xFFC9 debug interface. **Never open the keyboard interface** (macOS Input Monitoring prompt).
- Timeouts: connect 4000 ms, send 3000 ms, reconnect grace 400 ms (`:24-28`).
- Continuous receive loop; non-fatal errors retry every 100 ms.
- Error containing "disconnected", "not found" or "invalid connection" = unplug (`:272-278`).
- Report ID 0.

### Packet framing (`OnlyKeyDevice.ts:488-520`)
- `[FF FF FF FF][msgId][slot?][field?][data…]`, zero-padded to 64. Past byte 64 silently dropped (max 57 data bytes with slot+field).
- Strings: one char code per byte. `setSlot` rejects chars above U+00FF (`:40-45,798`).

### Request engine (`OnlyKeyDevice.ts:264-652`)
- FIFO queue, single pending request, per-request timeout (default 10 s), optional match predicate.
- Any 'error' response rejects the pending request.
- Disconnect bumps an epoch, aborts pending, clears queue.
- Helpers: `sendCommandWithoutConfirmation` (waits only for an error, 200–600 ms window), `sendCommandAndWaitFor` (text match), `waitForMessage`.
- Error remap (`:244-257`): "not in config mode" → CONFIG_MODE_FOR_OPERATION; "device locked" while app thinks unlocked → CONFIG_MODE_REQUIRED (fw 3.0.4 workaround); else "OnlyKey is locked…".

### Chunking (57-byte chunks)
- OKSETPRIV (`:969-991`): every chunk repeats slot and type. Intermediate chunks: 200 ms error window, then 30 ms sleep. Final: any reply, 10 s.
- OKRESTORE (`:1009-1089`): slot byte 0xFF = more follow, else last chunk length; no field byte. Intermediate silent (200 ms + 30 ms). Final waits up to 120 s for "successfully loaded backup", "remove and reinsert" or error. Progress ≤92% sending, 95% at final, 100% applied.
- Firmware (`:1217-1270`), per hex line ("block"): non-final chunks slot 0xFF, wait "RECEIVED OKFWUPDATE" (10 s); final chunk slot = length, wait "NEXT BLOCK" or "SUCCESSFULLY LOADED FW" on last block (20 s). Progress per block.
- Bootloader trigger: OKFWUPDATE data 01 02 03 04, no slot/field; waits "REBOOTING" or "SUCCESSFULL" (`:1212`).

### ResponseParser (`src/api/device/ResponseParser.ts`)
- Keep printable bytes 32–126, trim.
- Label packets: byte 0 slot, byte 1 '|'; byte 0 rendered as 2 hex chars (`:68`).
- Order (`:76-176`): "Error"/"ERROR" → error; "UNINITIALIZED" → uninitialized (+version); "BOOTLOADER" (also "UNLOCKED BOOTLOADERv1"); "UNLOCKED-D" → DUO unlocked; "UNLOCKED" → unlocked (type from suffix letter); "INITIALIZED-D" → DUO locked; "INITIALIZED" → Classic locked; "LOCKED"; `^(\w+)\|(.*)` → label; else text.
- Label slot mapping: slots 1–9 raw byte, 10–24 as byte+6 (0x10–0x1E). Hex "10"–"19" read as decimal 10–19, "1a"–"1e" → 20–24 (`:34-56`).

### Device type detection (`src/api/device/deviceTypeFromStatus.ts`)
- Last letter of status/version: c = Classic, p = DUO with PIN, n = DUO without PIN (`:51`).
- "-D" suffix → DUO. Major 2 → Classic, 3 → DUO (weak fallback).
- Labels: any slot > 12 → DUO. Idle stream of ≥12 labels with max ≤12 → Classic, only while UNKNOWN (`:91-109`).
- Transitions (`OnlyKeyDevice.ts:174-204`): Classic→DUO from status or USB; DUO→Classic from USB or status suffix 'c'; labels never demote. Reset on every connect.
- `devicePinSet` false only for DUO suffix 'n'. Product name "OnlyKey Duo" vs "OnlyKey"; bootloader/uninitialized labels (`src/data/deviceProduct.ts`).

### Status state machine (`OnlyKeyDevice.ts:292-442`)
- Locked → UNLOCKED triggers `setTime()` automatically (not in bootloader).
- INITIALIZED within 2500 ms of an unlock ignored (stale echo).
- Config mode inferred: DUO INITIALIZED-D after unlocked; Classic INITIALIZED after unlocked.
- Only messages longer than 1 char and not "OK" are emitted as `messageReceived`.

### Timing
- `connect`: OKSETTIME ×2, 100 ms apart, 2500 ms timeout each, skipped in bootloader (`:656-716`).
- `refreshStatus`: one OKSETTIME. Locked: match only UNLOCKED/UNINITIALIZED/BOOTLOADER, 2500 ms; else any status, 5 s (`:723-762`).
- `getLabels`: 5 s request, then wait until 400 ms with no new label (5 s max) (`:764-796`).
- Store: poll connect every 2 s while disconnected, connect on device-added, 20 s connect watchdog, coalesce reconnects (`useDeviceStore.ts:392-510`).
- LockScreen polls `refreshStatus` every 1500 ms while locked (`src/components/LockScreen.tsx`).

### Config mode text (`src/data/configMode.ts`)
Hold button 6 ≥5 s (OnlyKey) or button 1 ≥10 s (DUO); LED flashes red.

## 2. Device methods (`src/api/device/DeviceClient.ts:5-55`)

Events: `statusChange`, `error`, `labelUpdate`, `labelsRefreshed`, `messageReceived`.

- `connect(filters)`, `disconnect()`, `setTime(timeoutMs)`, `refreshStatus()` (deduplicated), `getLabels()`.
- `setSlot(slot, field, value)` (any reply resolves), `wipeSlot(slot, field?)`, `setSlotTypeSpeed(slot, n)` (slot/13, waits "typespeed").
- `beginClassicPinEntry(which, 'prompt'|'commit')`: empty OKSETPIN/OKSETPIN2/OKSETSDPIN, 300 s timeout. Prompt waits "enter your…pin" or "re-enter"; commit waits "successful pin" or "successfully set pin" (`:823-845`).
- `cancelClassicPinEntry(which)`: abort waiter, send one empty packet (1500 ms) to flush, suppress PIN noise messages, emit "Canceled" (`:852-875`).
- `sendPinDUO(pins, setPin)` (`:895-939`): setup payload `[0xFF][16 B primary][16 B pin2][16 B sd]`, ASCII digits zero-padded, each `/^[1-6]{7,10}$/`, SD ≠ primary. Unlock payload ASCII digits; waits "unlocked", "initialized-d", "incorrect" or "password attempts"; throws "Incorrect PIN" / "…attempts exceeded".
- `setBackupPassphrase(p)` = `setPrivateKey(131, 161, sha256(p))`.
- `setBackupKeyMode(m)`: XX/20, waits "backup key mode".
- `setYubiAuth(pub, priv, secret)`: XX/10, data = modhex→hex(pub[:12]) + priv[:12] + secret[:32] as bytes, waits "set AES Key". `wipeYubiAuth()`: OKWIPESLOT XX/10, 600 ms error window.
- `setPrivateKey(slot, type, bytes)` chunked; `wipePrivateKey(slot)` any reply.
- `restore(hex, onProgress)`.
- `firmwareUpdate(blocks)`, `triggerBootloader()`, `loadFirmwareBlocks(blocks, onProgress)` (requires bootloader).
- Preference setters (OKSETSLOT XX/field [value], 10 s, match text):

  | Method | Field | Match |
  |---|---|---|
  | setLockout | 11 | "idle timeout" / "lockout" |
  | setWipeMode | 12 | "wipe mode" |
  | setLedBrightness | 24 | "led brightness" |
  | setKbdLayout | 14 | "keyboard layout" |
  | setTypeSpeed | 13 | "typespeed" |
  | setLockButton | 25 | "lock button" |
  | setDerivedChallengeMode | 21 | "challenge mode" |
  | setStoredChallengeMode | 22 | "challenge mode" |
  | setHmacChallengeMode | 26 | "hmac" |
  | setWebAgentDeriveMode | 30 | "web and agent derived key mode" |
  | setWebcryptPolicy | 31 | "webcrypt policy" |
  | setModKeyMode | 27 | "sysadmin mode" |
  | setSecProfileMode | 23 | any reply |

## 3. Crypto and keys

- Slots (`src/api/device/keySlots.ts`): RSA 1–4; ECC 101–110; backup 131 (type 161); HMAC 129 (HMAC 2), 130 (HMAC 1). Slot 99 = Auto Load; wiping 99 wipes slot 1 (`src/services/keys/keyService.ts`).
- Type byte (`src/api/device/keyMaterial.ts`): RSA = p.len/64 → 1=1024, 2=2048, 3=3072, 4=4096, else error. ECC 1 = ed25519/x25519/curve25519 (OpenPGP algos 22/25/27), 2 = P-256, 3 = secp256k1, 9 = HMAC-SHA1. Modifiers: +128 backup, +64 signature, +32 decryption. Auto Load: RSA slot 1 +decryption, slot 2 +signature; backup stripped on slots 2 and 102 (`:140-162`).
- Bytes sent: RSA p ‖ q (leading zeros stripped); ECC 32-byte scalar (33-byte MPI → strip leading zero, `:40-47`). OpenPGP: p/q for RSA; seed/d/k for ECC. SSH: p/q for RSA, k for ed25519, d for ECDSA.
- Parsing: contains "-----BEGIN PGP" → OpenPGP (passphrase mandatory); other "-----" → SSH/PEM (`src/api/device/keyParser.ts`).
- Bundle import (`src/services/keyImport/*`): candidates = primary + each subkey ("Subkey N"). Auto Load: one key → RSA slot 2 / ECC 101; ≥2 keys → signing = candidate[2] if exists else [0] → slot 2 (102 ECC); decryption = candidate[1] → slot 1 (101 ECC). Explicit slot with several candidates → KEY_SELECTION_REQUIRED → PrivateKeySelectDialog (radio per candidate, slot dropdown, "Load Key").
- Backup file (`src/utils/backupVerify.ts`, `src/components/Backup.tsx`): device types it into a textarea (hold button 1 ≥5 s). `-----BEGIN ONLYKEY BACKUP-----` … `-----END ONLYKEY BACKUP-----`, base64 lines, optional hash line `--<base64 sha256>` (starts "--", no "BACKUP"). Verify: h = 32 zero bytes; per data line h = sha256(h ‖ bytes(line)); compare. Results: "Successfully verified backup SHA256 hash" / corrupt / "does not support verification". Save as `onlykey-backup-YYYY-MM-DDTHH-mm.txt`.
- Restore (`src/services/backup/backupService.ts`, `src/api/device/utils.ts:53`): drop "--" lines, base64→hex, concat, `device.restore`. Accept .txt/.okb. No app-side crypto.
- Helpers: `base32ToHex` (TOTP), `hexToModhex(reverse)`.

## 4. UI

### Shell (`src/App.tsx`)
- Sidebar: logo, ThemeToggle (dark default, persisted).
- Tabs: Setup, Slots, Keys, Backup, Firmware, Preferences, Advanced, Tools.
- Status block: app version, Connected/Disconnected, device label, one of Bootloader / Config mode / Uninitialized / Locked / Unlocked.
- DeviceMessages: 5-line terminal, 50 stored newest first, wheel/arrow/▲▼ scroll, hover shows full text.
- Disconnected overlay (except Tools): "Please insert your OnlyKey…" plus hint if HID unavailable.
- WorkingDialog: spinner, message, optional progress bar.
- DeviceDialogs: Linux udev dialog (link `https://docs.crp.to/appfaq.html#onlykey-app-on-linux`) when connect error mentions "cannot open device", "access denied", "permission", "failed to open", "unable to connect"; DUO PIN errors.
- Default tab: Setup when locked/bootloader/uninitialized; Slots on first unlock (not on config-mode unlock) (`useDeviceStore.ts:136-145`).

### LockScreen
- Hidden when disconnected, unlocked, uninitialized, bootloader, or on Tools.
- DUO: password field + "Unlock Device"; messages for incorrect PIN / attempts exceeded ("Unplug and replug").
- Classic: "Enter your PIN on the OnlyKey six-button keypad" / "Waiting for PIN on device…".

### Setup (`src/components/Setup.tsx`)
- Step 1: uninitialized → Guided Setup "Next" + "advanced setup" checkbox; uninitialized/bootloader → "Load Firmware"; initialized → ready block with config-mode instructions, "Set Backup Passphrase", and "Change Primary/Secondary/Self-Destruct PIN" (Classic) or "Set or Change OnlyKey Duo PINs" (DUO).
- Classic: 2 primary PIN disclaimer + prompt/commit; 3 re-enter; 4 second-profile PIN (advanced setup sends `setSecProfileMode(1)` first); 5 re-enter; 6 SD PIN (disclaimer required when initialized or guided); 7 re-enter; 8 backup passphrase; 9 PGP backup key instead; 10 restore; 11 firmware.
- DUO: 2 disclaimer, Device PIN + confirm (required), SD PIN + confirm (optional), maxLength 16, 7–10 digits 1–6, `sendPinDUO`; then 8, 9, 10, 11.
- Backup passphrase: non-empty, matches confirm, ≥25 chars. Uninitialized + advanced: radio "Permit future backup key changes" (0) / "Lock backup key on this device" (1) → `setBackupKeyMode`.
- PGP backup: slot dropdown (RSA 1–4, ECC 1–10), armored key + passphrase (required), "Set as signature key", backup-key-mode radio; import with setAsBackup=true then `setBackupKeyMode`.
- Restore step: file (.txt/.okb), Next. Firmware step: file (.okfw/.txt/.hex), "Load Firmware to OnlyKey", "Download Latest Firmware" (uninitialized/bootloader), "Use downloaded vX".
- Cancel sends `cancelClassicPinEntry` on PIN steps. While a step other than 1 or 11 is open, firmware prompts are deferred.

### Slots / SlotEditor (`src/components/SlotGrid.tsx`, `SlotEditor.tsx`, `src/services/slot/slotConfigService.ts`)
- Grid: Classic photo, buttons 1a–6b. DUO: profile colour buttons, photo, 3 columns. Empty → `<empty>`. Notice that only labels can be read back.
- Editor title "OnlyKey Slot N Configuration". Tabs: Basic Login, Multi-factor, Full Configuration (Advanced). DUO without PIN: "Static Password" and Multi-factor only. Last tab persisted.
- Each field has an enable checkbox; only checked fields are written.
- Fields: Label (16, prefilled), URL (56), Tab before UserName (NEXTKEY4), Delay1 (0–9), UserName (56), After UserName (NEXTKEY1), Delay2, Password + Re-enter (56, Generate), After Password (NEXTKEY2; MFA tab only Tab/None), Type Speed 1–10 default 4 (slot field 13), Delay3, Tab before OTP (NEXTKEY5), OATH-TOTP secret (base32), Return after OTP (NEXTKEY3), Yubikey OTP Public/Private/Secret.
- Write order: label, url, username, password, delays, nextkeys, speed, MFA (`slotConfigService.ts:56-117`).
- Validation: passwords match; not both TOTP and Yubico; TOTP ≤57 bytes (TFATYPE 'g' then TFAUSERNAME bytes); Yubico all three required (TFATYPE 'Y' then YUBIAUTH); DUO no-PIN: password and MFA exclusive, username/URL forbidden.
- "Wipe All Slot Data" with confirm → OKWIPESLOT. Save and Wipe refresh labels.

### Password generator (`src/utils/passwordGenerator.ts`)
- Length 6–56, default 20. Sets: upper, lower, digits, special `~!@#$%^&*+=-_` (these four default on); punct `"';:,.?`; braces `(){}[]<>`; space. Omit-chars removed. CSPRNG mod n. With space, first/last re-rolled (≤32 times) to avoid space. ≥1 set required. Generate / Apply fills both password fields.

### Keys (`src/components/Keys.tsx`)
Slot dropdown Auto Load / RSA 1–4 / ECC 1–10, passphrase, PEM textarea, "Set as backup key", "Save to OnlyKey", "Wipe from OnlyKey" (confirm), config-mode notice.

### Backup (`src/components/Backup.tsx`)
Backup tab: steps 1–3, textarea ("DO NOT type…"), "Verify Backup", "Save File". Restore tab: steps 1–4, file input, "Restore to OnlyKey" with progress, then "remove and reinsert".

### Firmware (`src/components/Firmware.tsx`)
"Automatically check for firmware updates" checkbox; instructions by state (bootloader/uninitialized, supported, outdated + docs link); file input, "Load Firmware to OnlyKey", "Download Latest Firmware", "Check now"; current version ("(Bootloader Mode)"). Loading allowed in bootloader, uninitialized, or when in-app update is supported.

### Preferences (`src/components/Preferences.tsx`)
- Standard tab: Type Speed 1–10 (4), Keyboard Layout, LED Brightness 1–10 (8), Inactivity Lockout 0–255 min (30; 0 disables), Lock Button 0–6.
- Advanced tab (config mode): Sysadmin Mode (27), HMAC User Input Mode (26), Set Full Wipe Mode (12 = 2, irreversible), User Input Modes — SSH/GPG derived (21) and Stored (22): 0 challenge code, 1 button press; Web and agent derived (30, fw ≥3.1.0) adds 2 none; only picked groups are written; on failure list what was already saved. Webcrypt Access (31, fw ≥3.1.0): 0x01 stored+derived, 0x00 derived only, 0x02 off. Lock Backup Key (20 = 1, irreversible).
- Feedback "<X> saved." or error; Standard tab config-mode error gets Sysadmin hint.

### Advanced (`src/components/Advanced.tsx`)
- Legacy Yubikey: Public id (17), Private id (17), Secret AES key (47); Save; Wipe (confirm).
- Add Private Key (raw hex): type Curve25519/Ed25519 1, NIST256P1 2, SECP256K1 3, HMACSHA1 9; slot ECC 101–110, HMAC 2 (129), HMAC 1 (130); key 64 hex (ECC) or 40 hex (HMAC); +Backup 128, +Signature 64, +Decryption 32; Save; Wipe (confirm).

### Tools (`src/components/Tools.tsx`)
App update settings (version, auto-check checkbox, "Check now", status). WebCrypt links `https://apps.onlykey.io/app/{encrypt,decrypt,encrypt-file,decrypt-file,vault}`. OnlyKey Agent link. External links open in the system browser.

## 5. Desktop shell

### Tray (`desktopBg.cjs:1048-1160, 1214-1293`) **[changed: see SPEC §Tray]**
Original items: Show, Autostart to tray, Auto app updates, Auto firmware updates, Hide to tray on close, Quit. Click icon (not macOS) shows window. Rebuild the whole menu on change — never edit in place (Linux empty-menu bug). **[drop]** file-based IPC in `tmp/`.

### Close / launch
- Close: closeToTray on (default) → hide; off → quit. Real quit (Cmd+Q, logout) always quits.
- Window starts hidden; shown unless `--hidden`. Second instance shows the window (second `--hidden` launch does not).
- Centred, 1024×768, min 800×400.

### Autostart **[changed: tauri-plugin-autostart, args `--hidden`]**
Original: Windows HKCU Run, macOS LaunchAgent, Linux `~/.config/autostart`. **[drop]** legacy migrations, StartupApproved fixups, Login Item osascript cleanup + consent dialog, Dock tile pruning — those clean up the old NW app's own history.
A stored "off" is never turned back on.

### Preferences (all default true)
autoLaunch, autoUpdate, autoUpdateFW, closeToTray. Also theme, slotEditorConfigMode. Session-only: fw-checked, app-update-checked, pending-firmware blocks.

### App updater **[changed: tauri-plugin-updater + signed latest.json on GitHub Releases]**
Original: S3 manifest with sha256, HTTPS-only, same-host check, launches native installer. Keep: auto-check pref, once per session unless forced, 15 s check timeout, dialog flow Download/Later → progress → Install now/Later → applying; up-to-date and error states; deferred while working or while connected+locked; opening the prompt shows the window.

### Firmware update
- Source `https://api.github.com/repos/trustcrypto/OnlyKey-Firmware/releases/latest`, asset `Signed_OnlyKey_<M>_<m>_<p>_STD.txt` (`src/desktop/firmwareDownload.ts`).
- Allowed hosts: api.github.com, github.com under trustcrypto/OnlyKey-Firmware, objects / release-assets / github-releases.githubusercontent.com. Redirects followed; final URL re-checked.
- Expected SHA-256 from asset `digest`, else a 64-hex string next to the filename in the release body. Missing or mismatch → refuse.
- File: optional "BEGIN SIGNED FIRMWARE" line, then hex lines (one block each); "--" lines ignored. Signature checked by bootloader. Manual files get no hash check.
- Version compare: numeric tuples, c/n/p suffix stripped (`src/desktop/firmwareCheck.ts:30-44`). In-app update supported when char 9 of version ≠ '.' or char 10 > 6 (`:46`).
- Auto-check: only when connected, unlocked, not bootloader, not working, not during Setup PIN steps; once per session; pref gated; 15 s check, 60 s download.
- Apply needs config mode or bootloader. Not in bootloader → trigger bootloader, keep blocks for the session; on reconnect with PID B001 stream them (`useDeviceStore.ts:338-366`). In bootloader → stream directly.
- Disconnect resets the store and aborts fetches.

### Session wipe (`src/store/deviceStateReset.ts`, `src/store/__tests__/sessionWipe.security.test.tsx`)
- Unplug: reset labels, messages, errors, working state, selected slot, DUO profile; tab → Setup; `sessionEpoch`++.
- Unlocked → locked: same wipe; keep current tab only for a config-mode lock.
- Never keep labels while locked; while locked record only status messages.
- `sessionEpoch` keys every page, LockScreen, SlotEditor, WorkingDialog so local secrets drop on remount. A silent empty poll does not bump the epoch.

## 6. Packaging
- Linux udev rules (`resources/linux/49-onlykey.rules`) cover only 1d50:60fc — **[changed]** RustyKey ships rules for every PID in §1 USB IDs. `postinst`: udevadm reload/trigger.
- macOS: universal DMG. Windows: installer, Start menu shortcut.
- CI: typecheck/lint/test; per-OS build; artifacts.

## 7. Library mapping
- openpgp.js → `pgp` (rpgp). sshpk → `ssh-key` (+ `rsa`, `pkcs8`, `sec1`, `p256`, `k256` for bare PEM). js-sha256 → `sha2`. chrome.hid → `hidapi` (desktop) / WebHID via `web-sys` (web). Blob download / file input / confirm / localStorage / openExternal → Tauri dialog, store, opener (desktop) or browser APIs (web).
