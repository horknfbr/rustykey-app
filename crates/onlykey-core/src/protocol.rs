//! MessageID/FieldID/constants, packet framing, keyboard layouts, slot maps, USB IDs.
//!
//! Ports `types.ts`, `firmwareConstants.ts`, `keySlots.ts` (constants), `OnlyKeyDevice.ts:48,488-520`,
//! `src/data/configMode.ts` and `src/data/deviceProduct.ts`.

use crate::device_type::DeviceType;

/// HID message IDs (`types.ts:1-16`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageId {
    /// 0xE1: set PIN (Classic keypad state machine; DUO carries the PIN).
    OkSetPin = 0xE1,
    /// 0xE2: self-destruct PIN (Classic keypad).
    OkSetSdPin = 0xE2,
    /// 0xE3: second-profile PIN (Classic keypad).
    OkSetPin2 = 0xE3,
    /// 0xE4: set time (4 BE unix seconds); also the lock-status probe.
    OkSetTime = 0xE4,
    /// 0xE5: stream slot labels, one per packet.
    OkGetLabels = 0xE5,
    /// 0xE6: write a slot field.
    OkSetSlot = 0xE6,
    /// 0xE7: wipe a slot or one field.
    OkWipeSlot = 0xE7,
    /// 0xEC: defined, never sent.
    OkGetPubKey = 0xEC,
    /// 0xED: defined, never sent.
    OkSign = 0xED,
    /// 0xEE: wipe a private key.
    OkWipePriv = 0xEE,
    /// 0xEF: set a private key (chunked).
    OkSetPriv = 0xEF,
    /// 0xF0: defined, never sent.
    OkDecrypt = 0xF0,
    /// 0xF1: restore a backup (chunked).
    OkRestore = 0xF1,
    /// 0xF4: bootloader trigger and firmware blocks.
    OkFwUpdate = 0xF4,
}

impl MessageId {
    /// The TS enum name, as used in timeout messages (`Request OKSETTIME timed out…`).
    pub fn name(self) -> &'static str {
        match self {
            Self::OkSetPin => "OKSETPIN",
            Self::OkSetSdPin => "OKSETSDPIN",
            Self::OkSetPin2 => "OKSETPIN2",
            Self::OkSetTime => "OKSETTIME",
            Self::OkGetLabels => "OKGETLABELS",
            Self::OkSetSlot => "OKSETSLOT",
            Self::OkWipeSlot => "OKWIPESLOT",
            Self::OkGetPubKey => "OKGETPUBKEY",
            Self::OkSign => "OKSIGN",
            Self::OkWipePriv => "OKWIPEPRIV",
            Self::OkSetPriv => "OKSETPRIV",
            Self::OkDecrypt => "OKDECRYPT",
            Self::OkRestore => "OKRESTORE",
            Self::OkFwUpdate => "OKFWUPDATE",
        }
    }
}

/// Slot and global field IDs (`types.ts:18-49`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    /// Slot label.
    Label = 1,
    /// Username.
    Username = 2,
    /// Key after password.
    NextKey2 = 3,
    /// Delay after password.
    Delay2 = 4,
    /// Password.
    Password = 5,
    /// Key after OTP.
    NextKey3 = 6,
    /// Delay after OTP.
    Delay3 = 7,
    /// MFA type byte (`g` / `Y`).
    TfaType = 8,
    /// TOTP secret bytes.
    TfaUsername = 9,
    /// Yubico OTP auth (also the global legacy Yubikey field).
    YubiAuth = 10,
    /// Global: inactivity lockout minutes.
    Lockout = 11,
    /// Global: wipe mode.
    WipeMode = 12,
    /// Global or per-slot: type speed.
    TypeSpeed = 13,
    /// Global: keyboard layout.
    KbdLayout = 14,
    /// URL.
    Url = 15,
    /// Key after username.
    NextKey1 = 16,
    /// Delay after username.
    Delay1 = 17,
    /// Key before username.
    NextKey4 = 18,
    /// Key before OTP.
    NextKey5 = 19,
    /// Global: backup key mode (lock backup key).
    BackupKeyMode = 20,
    /// Global: SSH/GPG derived-key user input mode.
    DerivedChallengeMode = 21,
    /// Global: stored-key user input mode.
    StoredChallengeMode = 22,
    /// Global: second profile mode.
    SecProfileMode = 23,
    /// Global: LED brightness.
    LedBrightness = 24,
    /// Global: lock button.
    LockButton = 25,
    /// Global: HMAC user input mode.
    HmacChallengeMode = 26,
    /// Global: Sysadmin (mod keys) mode.
    ModKeyMode = 27,
    /// Unused.
    YubiAndHmac = 29,
    /// Global: web and agent derived key mode.
    WebAgentDeriveMode = 30,
    /// Global: webcrypt policy.
    WebcryptPolicy = 31,
}

/// Every packet starts with these four bytes.
pub const MESSAGE_HEADER: [u8; 4] = [0xFF; 4];
/// HID report size.
pub const PACKET_SIZE: usize = 64;
/// Slot byte for global settings (legacy "XX").
pub const GLOBAL_SLOT: u8 = 0;

/// Builds a report: header, message ID, optional slot and field bytes, data, zero padding.
///
/// Data past byte 64 is dropped silently, as the original does.
pub fn frame(
    msg: MessageId,
    slot: Option<u8>,
    field: Option<u8>,
    data: &[u8],
) -> [u8; PACKET_SIZE] {
    let mut packet = [0u8; PACKET_SIZE];
    let head = MESSAGE_HEADER
        .into_iter()
        .chain([msg as u8])
        .chain(slot)
        .chain(field);
    for (dst, src) in packet.iter_mut().zip(head.chain(data.iter().copied())) {
        *dst = src;
    }
    packet
}

/// OKSETTIME payload: the low 32 bits of unix seconds, big-endian.
pub fn set_time_bytes(unix_secs: u64) -> [u8; 4] {
    (unix_secs as u32).to_be_bytes()
}

/// One keyboard layout: firmware value, display label, legacy dropdown label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardLayout {
    /// Firmware value (keylayouts.h).
    pub value: u8,
    /// Display label (`KEYBOARD_LAYOUTS`).
    pub label: &'static str,
    /// Legacy label shown in Preferences (`KEYBOARD_LAYOUT_LABELS`).
    pub legacy_label: &'static str,
}

/// Shorthand to build a [`KeyboardLayout`] row.
const fn kl(value: u8, label: &'static str, legacy_label: &'static str) -> KeyboardLayout {
    KeyboardLayout {
        value,
        label,
        legacy_label,
    }
}

/// All 28 keyboard layouts in dropdown order (`firmwareConstants.ts:9-70`).
pub const KEYBOARD_LAYOUTS: [KeyboardLayout; 28] = [
    kl(0x01, "US English (default)", "US_ENGLISH (default)"),
    kl(0x02, "Canadian French", "CANADIAN_FRENCH"),
    kl(0x03, "Canadian Multilingual", "CANADIAN_MULTILINGUAL"),
    kl(0x04, "Danish", "DANISH"),
    kl(0x1b, "Danish Mac", "DANISH_MAC"),
    kl(0x05, "Finnish", "FINNISH"),
    kl(0x06, "French", "FRENCH"),
    kl(0x07, "French Belgian", "FRENCH_BELGIAN"),
    kl(0x08, "French Swiss", "FRENCH_SWISS"),
    kl(0x09, "German", "GERMAN"),
    kl(0x0a, "German Mac", "GERMAN_MAC"),
    kl(0x0b, "German Swiss", "GERMAN_SWISS"),
    kl(0x0c, "Icelandic", "ICELANDIC"),
    kl(0x0d, "Irish", "IRISH"),
    kl(0x0e, "Italian", "ITALIAN"),
    kl(0x0f, "Norwegian", "NORWEGIAN"),
    kl(0x10, "Portuguese", "PORTUGUESE"),
    kl(0x11, "Portuguese Brazilian", "PORTUGUESE_BRAZILIAN"),
    kl(0x12, "Spanish", "SPANISH"),
    kl(0x13, "Spanish Latin America", "SPANISH_LATIN_AMERICA"),
    kl(0x14, "Swedish", "SWEDISH"),
    kl(0x15, "Turkish", "TURKISH"),
    kl(0x16, "United Kingdom", "UNITED_KINGDOM"),
    kl(0x17, "US International", "US_INTERNATIONAL"),
    kl(0x18, "Czech", "CZECH"),
    kl(0x19, "Serbian Latin Only", "SERBIAN_LATIN_ONLY"),
    kl(0x1a, "Hungarian", "HUNGARIAN"),
    kl(0x1c, "Dvorak", "DVORAK"),
];

/// WIPEMODE options: 0 Off, 1 On (`:76-79`).
pub const WIPE_MODES: [(u8, &str); 2] = [(0, "Off"), (1, "On")];
/// WIPEMODE value for full wipe (irreversible).
pub const WIPE_MODE_FULL: u8 = 2;

/// TFATYPE byte for Google Authenticator / TOTP.
pub const MFA_TYPE_GOOGLE_AUTH: u8 = b'g';
/// TFATYPE byte for Yubico OTP.
pub const MFA_TYPE_YUBI_OTP: u8 = b'Y';

/// NEXTKEY1/NEXTKEY2 (after username/password) options.
pub const NEXTKEY_AFTER_FIELD_OPTIONS: [(u8, &str); 3] = [(0, "None"), (1, "Tab"), (2, "Return")];
/// NEXTKEY4/NEXTKEY5 (before username/OTP) options.
pub const NEXTKEY_BEFORE_FIELD_OPTIONS: [(u8, &str); 2] = [(0, "None"), (1, "Tab")];
/// NEXTKEY3 (after OTP) options.
pub const NEXTKEY_AFTER_OTP_OPTIONS: [(u8, &str); 4] =
    [(0, "None"), (1, "Tab"), (2, "Return"), (3, "Tab + Return")];

/// USB product IDs that are always DUO.
pub const DUO_PRODUCT_IDS: [u16; 3] = [0x614C, 0x614E, 0x4211];
/// Bootloader USB product ID.
pub const BOOTLOADER_PRODUCT_ID: u16 = 0xB001;
/// Supported (vendor, product) IDs in the order connect tries them (`useDeviceStore.ts:94-101`).
pub const USB_IDS: [(u16, u16); 6] = [
    (0x1D50, 0x614C),
    (0x1D50, 0x614E),
    (0x20A0, 0x4211),
    (0x16C0, 0x0486),
    (0x1D50, 0x60FC),
    (0x0000, BOOTLOADER_PRODUCT_ID),
];

/// Type from an unambiguous PID; 0x60FC (Classic Beta 7+ or DUO) gives `None`.
pub fn device_type_from_product_id(pid: u16) -> Option<DeviceType> {
    match pid {
        _ if DUO_PRODUCT_IDS.contains(&pid) => Some(DeviceType::Duo),
        0x0486 => Some(DeviceType::Classic),
        BOOTLOADER_PRODUCT_ID => Some(DeviceType::Bootloader),
        _ => None,
    }
}

/// True when the first `X.Y.Z` in `version` is at least `major.minor.patch`; false if there is none.
pub fn firmware_at_least(version: &str, major: u64, minor: u64, patch: u64) -> bool {
    first_triple(version).is_some_and(|v| v >= (major, minor, patch))
}

/// First `\d+\.\d+\.\d+` in the text, as numbers (saturating).
fn first_triple(text: &str) -> Option<(u64, u64, u64)> {
    let b = text.as_bytes();
    /// Length and value of the digit run at `i`.
    fn digits(b: &[u8], i: usize) -> (usize, u64) {
        let n = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        let v = b[i..i + n].iter().fold(0u64, |acc, c| {
            acc.saturating_mul(10).saturating_add(u64::from(c - b'0'))
        });
        (n, v)
    }
    (0..b.len()).find_map(|i| {
        let (n1, a) = digits(b, i);
        let j = i + n1 + 1;
        if n1 == 0 || b.get(j - 1) != Some(&b'.') {
            return None;
        }
        let (n2, m) = digits(b, j);
        let k = j + n2 + 1;
        if n2 == 0 || b.get(k - 1) != Some(&b'.') {
            return None;
        }
        let (n3, p) = digits(b, k);
        (n3 > 0).then_some((a, m, p))
    })
}

/// DUO with no device PIN: the version's last character is `n` (case-insensitive).
pub fn is_duo_no_pin_version(version: &str) -> bool {
    version
        .trim()
        .chars()
        .last()
        .is_some_and(|c| c.eq_ignore_ascii_case(&'n'))
}

/// DUO profiles: (id, name), in order (`firmwareConstants.ts` DUO_PROFILES; UI colours not ported).
pub const DUO_PROFILES: [(&str, &str); 4] = [
    ("green", "Green"),
    ("blue", "Blue"),
    ("yellow", "Yellow"),
    ("purple", "Purple"),
];

/// One slot button cell: display id (e.g. `1a`) and firmware slot index (1–24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCell {
    /// Display id.
    pub id: &'static str,
    /// Firmware slot index.
    pub index: u8,
}

/// Shorthand to build a [`SlotCell`].
const fn sc(id: &'static str, index: u8) -> SlotCell {
    SlotCell { id, index }
}

/// One Classic grid row: two buttons, each with its short (a) and long (b) press slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassicRow {
    /// Left button cells.
    pub left: [SlotCell; 2],
    /// Right button cells.
    pub right: [SlotCell; 2],
}

/// Classic: buttons 1–6, `a` = slots 1–6, `b` = slots 7–12.
pub const CLASSIC_SLOT_ROWS: [ClassicRow; 3] = [
    ClassicRow {
        left: [sc("1a", 1), sc("1b", 7)],
        right: [sc("2a", 2), sc("2b", 8)],
    },
    ClassicRow {
        left: [sc("3a", 3), sc("3b", 9)],
        right: [sc("4a", 4), sc("4b", 10)],
    },
    ClassicRow {
        left: [sc("5a", 5), sc("5b", 11)],
        right: [sc("6a", 6), sc("6b", 12)],
    },
];

/// DUO grid per profile (same order as [`DUO_PROFILES`]): columns in physical order 1 | 3 | 2.
pub const DUO_PROFILE_COLUMNS: [[[SlotCell; 2]; 3]; 4] = {
    let mut out = [[[sc("", 0); 2]; 3]; 4];
    let ids = [["1a", "1b"], ["3a", "3b"], ["2a", "2b"]];
    let button = [1u8, 3, 2];
    let mut p = 0;
    while p < 4 {
        let mut col = 0;
        while col < 3 {
            let base = p as u8 * 6 + button[col];
            out[p][col] = [sc(ids[col][0], base), sc(ids[col][1], base + 3)];
            col += 1;
        }
        p += 1;
    }
    out
};

/// RSA private key slots.
pub const RSA_SLOTS: [u8; 4] = [1, 2, 3, 4];
/// ECC private key slots.
pub const ECC_SLOTS: [u8; 10] = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110];
/// Backup key slot.
pub const BACKUP_KEY_SLOT: u8 = 131;
/// Backup key type byte.
pub const BACKUP_KEY_TYPE: u8 = 161;

/// Refusal shown when wiping/saving private keys outside config mode.
pub const CONFIG_MODE_REQUIRED: &str =
    "Put your OnlyKey in config mode (flashing red LED) before saving or wiping private keys.";
/// Refusal when firmware names config mode (prefs, restore, firmware, keys).
pub const CONFIG_MODE_FOR_OPERATION: &str =
    "OnlyKey must be in config mode (flashing red LED) for this operation.";
/// Extra line for Standard prefs when Sysadmin Mode blocks writes.
pub const SYSADMIN_MODE_PREF_HINT: &str = "When Sysadmin Mode is on, turn it off (Advanced preferences, in config mode) to change Standard settings while unlocked.";

/// User-facing product name: "OnlyKey Duo" for DUO, else "OnlyKey".
pub fn product_name(ty: DeviceType) -> &'static str {
    if ty == DeviceType::Duo {
        "OnlyKey Duo"
    } else {
        "OnlyKey"
    }
}

/// Sidebar/footer line: product plus firmware version, with bootloader/uninitialized notes.
pub fn connected_device_label(ty: DeviceType, version: &str, is_initialized: bool) -> String {
    let name = product_name(ty);
    if ty == DeviceType::Bootloader {
        let v = remove_ascii_ci(version, "bootloader");
        let v = v.trim();
        return if v.is_empty() {
            format!("{name} (bootloader)")
        } else {
            format!("{name} (bootloader {v})")
        };
    }
    let v = version.trim();
    if !is_initialized || ty == DeviceType::Uninitialized {
        if ty == DeviceType::Uninitialized || v.is_empty() {
            return format!("{name} (uninitialized)");
        }
        return format!("{name} {v} (uninitialized)");
    }
    if v.is_empty() {
        name.to_string()
    } else {
        format!("{name} {v}")
    }
}

/// Removes every ASCII case-insensitive occurrence of `needle` (`/needle/gi`).
fn remove_ascii_ci(text: &str, needle: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while !rest.is_empty() {
        if rest
            .get(..needle.len())
            .is_some_and(|h| h.eq_ignore_ascii_case(needle))
        {
            rest = &rest[needle.len()..];
        } else {
            let c = rest.chars().next().unwrap_or_default();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

/// Button/hold facts for entering config mode: (is DUO, button, seconds).
fn config_mode_hold(ty: DeviceType) -> (bool, u8, u8) {
    if ty == DeviceType::Duo {
        (true, 1, 10)
    } else {
        (false, 6, 5)
    }
}

/// Full how-to for entering config mode; `capitalize` false starts lowercase (after "To do this").
pub fn config_mode_how_to(ty: DeviceType, capitalize: bool) -> String {
    let (is_duo, button, secs) = config_mode_hold(ty);
    let pin = if is_duo {
        "If a PIN was previously set, re-enter the PIN to enter config mode."
    } else {
        "Enter your PIN."
    };
    format!(
        "{} down button #{button} on your {} for {secs}+ seconds and release. The light will turn off. {pin} You will notice the OnlyKey flashes red in config mode.",
        if capitalize { "Hold" } else { "hold" },
        product_name(ty)
    )
}

/// Short tooltip version of the config-mode how-to.
pub fn config_mode_tooltip(ty: DeviceType) -> String {
    let (is_duo, button, secs) = config_mode_hold(ty);
    let pin = if is_duo {
        "If a PIN is set, re-enter it."
    } else {
        "Enter your PIN."
    };
    format!(
        "Hold button #{button} for {secs}+ seconds and release. The light turns off. {pin} The LED flashes red."
    )
}

/// Hint shown before setting a backup passphrase.
pub fn config_mode_passphrase_hint(ty: DeviceType) -> String {
    format!(
        "To set a new passphrase on your OnlyKey put OnlyKey in config mode. {}",
        config_mode_how_to(ty, true)
    )
}

#[cfg(test)]
mod tests {
    //! Ports of `firmwareConstants.test.ts`, `firmwareAtLeast.test.ts`, `keySlots.test.ts` (constants),
    //! `configMode.test.ts`, `deviceProduct.test.ts`, plus framing and slot-map checks.

    use super::*;
    use DeviceType::*;

    /// Finds a layout value by display label.
    fn layout(label: &str) -> Option<u8> {
        KEYBOARD_LAYOUTS
            .iter()
            .find(|l| l.label == label)
            .map(|l| l.value)
    }

    /// firmwareConstants: layout values match keylayouts.h.
    #[test]
    fn firmware_constants_maps_keyboard_layouts_to_keylayouts_h_values() {
        assert_eq!(layout("French"), Some(0x06));
        assert_eq!(layout("German"), Some(0x09));
        assert_eq!(layout("United Kingdom"), Some(0x16));
        assert_eq!(layout("Spanish"), Some(0x12));
        let mut values: Vec<u8> = KEYBOARD_LAYOUTS.iter().map(|l| l.value).collect();
        values.sort_unstable();
        assert_eq!(values, (0x01..=0x1C).collect::<Vec<u8>>());
    }

    /// firmwareConstants: DUO no-PIN from the version suffix.
    #[test]
    fn firmware_constants_detects_duo_no_pin_from_version_suffix() {
        assert!(is_duo_no_pin_version("3.0.0-prod-n"));
        assert!(!is_duo_no_pin_version("3.0.0-prod-p"));
    }

    /// firmwareConstants: NEXTKEY3 after-OTP values 0–3.
    #[test]
    fn firmware_constants_encodes_nextkey3_after_otp_options() {
        let values: Vec<u8> = NEXTKEY_AFTER_OTP_OPTIONS.iter().map(|o| o.0).collect();
        assert_eq!(values, [0, 1, 2, 3]);
    }

    /// firmwareConstants: PID 0xB001 is bootloader.
    #[test]
    fn firmware_constants_maps_usb_pid_0xb001_to_bootloader() {
        assert_eq!(device_type_from_product_id(0xb001), Some(Bootloader));
        assert_eq!(device_type_from_product_id(0x0486), Some(Classic));
    }

    /// firmwareConstants: TFATYPE codes.
    #[test]
    fn firmware_constants_encodes_tfatype_as_firmware_mfa_first_byte_codes() {
        assert_eq!(MFA_TYPE_GOOGLE_AUTH, 103);
        assert_eq!(MFA_TYPE_YUBI_OTP, 89);
    }

    /// firmwareAtLeast: numeric compare ignoring the build keyword.
    #[test]
    fn firmware_at_least_compares_the_numeric_version_and_ignores_the_build_keyword() {
        assert!(firmware_at_least("v3.1.0-prodc", 3, 1, 0));
        assert!(firmware_at_least("v3.1.0-test-9fceea1-37aa531", 3, 1, 0));
        assert!(firmware_at_least("v3.2.0-prod", 3, 1, 0));
        assert!(firmware_at_least("v4.0.0", 3, 1, 0));
        assert!(!firmware_at_least("v3.0.4-prodp", 3, 1, 0));
        assert!(!firmware_at_least("v2.1.2 STD", 3, 1, 0));
        assert!(!firmware_at_least("", 3, 1, 0));
    }

    /// Extra: the first full X.Y.Z wins, even after a partial match.
    #[test]
    fn firmware_at_least_finds_the_first_full_triple() {
        assert_eq!(first_triple("v0.2-beta.6"), None);
        assert_eq!(first_triple("1.2 then 3.4.5"), Some((3, 4, 5)));
        assert_eq!(first_triple("v10.20.30x"), Some((10, 20, 30)));
    }

    /// keySlots: RSA/ECC/backup slot constants.
    #[test]
    fn key_slots_exports_firmware_rsa_and_ecc_slot_ranges() {
        assert_eq!(RSA_SLOTS, [1, 2, 3, 4]);
        assert_eq!(ECC_SLOTS[0], 101);
        assert_eq!(ECC_SLOTS.len(), 10);
        assert_eq!(BACKUP_KEY_SLOT, 131);
        assert_eq!(BACKUP_KEY_TYPE, 161);
    }

    /// configMode: Classic uses button 6 / 5 s.
    #[test]
    fn config_mode_uses_button_6_5_seconds_for_classic() {
        assert_eq!(
            config_mode_how_to(Classic, true),
            "Hold down button #6 on your OnlyKey for 5+ seconds and release. The light will turn off. Enter your PIN. You will notice the OnlyKey flashes red in config mode."
        );
    }

    /// configMode: DUO uses button 1 / 10 s.
    #[test]
    fn config_mode_uses_button_1_10_seconds_for_duo() {
        assert_eq!(
            config_mode_how_to(Duo, true),
            "Hold down button #1 on your OnlyKey Duo for 10+ seconds and release. The light will turn off. If a PIN was previously set, re-enter the PIN to enter config mode. You will notice the OnlyKey flashes red in config mode."
        );
    }

    /// configMode: lowercase variant after "To do this".
    #[test]
    fn config_mode_can_start_lowercase_after_to_do_this() {
        assert!(config_mode_how_to(Classic, false).starts_with("hold down"));
    }

    /// configMode: passphrase hint embeds the how-to.
    #[test]
    fn config_mode_embeds_the_how_to_in_the_passphrase_hint() {
        let hint = config_mode_passphrase_hint(Duo);
        assert!(hint.contains("put OnlyKey in config mode"));
        assert!(hint.contains(&config_mode_how_to(Duo, true)));
    }

    /// configMode: tooltip and error copy match the hold facts.
    #[test]
    fn config_mode_keeps_tooltip_and_error_copy_in_sync_with_hold_facts() {
        assert!(config_mode_tooltip(Duo).contains("button #1"));
        assert!(config_mode_tooltip(Classic).contains("button #6"));
        assert!(CONFIG_MODE_REQUIRED.contains("flashing red LED"));
        assert!(CONFIG_MODE_FOR_OPERATION.contains("flashing red LED"));
        assert!(SYSADMIN_MODE_PREF_HINT.contains("Sysadmin Mode"));
    }

    /// deviceProduct: full-size hardware is "OnlyKey".
    #[test]
    fn device_product_names_full_size_hardware_only_key_not_classic() {
        assert_eq!(product_name(Classic), "OnlyKey");
        assert_eq!(product_name(Unknown), "OnlyKey");
        assert_eq!(product_name(Duo), "OnlyKey Duo");
    }

    /// deviceProduct: connected label variants.
    #[test]
    fn device_product_does_not_print_the_classic_enum_in_the_connected_label() {
        assert_eq!(
            connected_device_label(Classic, "v3.0.4-testc", true),
            "OnlyKey v3.0.4-testc"
        );
        assert_eq!(
            connected_device_label(Duo, "v3.0.4-prodp", true),
            "OnlyKey Duo v3.0.4-prodp"
        );
        assert_eq!(
            connected_device_label(Uninitialized, "v2.1.0-prod", true),
            "OnlyKey (uninitialized)"
        );
        assert_eq!(
            connected_device_label(Classic, "v3.0.4-testc", false),
            "OnlyKey v3.0.4-testc (uninitialized)"
        );
        assert_eq!(
            connected_device_label(Duo, "v3.0.4-testp", false),
            "OnlyKey Duo v3.0.4-testp (uninitialized)"
        );
        assert_eq!(
            connected_device_label(Bootloader, "v1", true),
            "OnlyKey (bootloader v1)"
        );
        assert_eq!(
            connected_device_label(Bootloader, "BOOTLOADERv1", true),
            "OnlyKey (bootloader v1)"
        );
        assert_eq!(
            connected_device_label(Bootloader, " bootloader ", true),
            "OnlyKey (bootloader)"
        );
        assert_eq!(connected_device_label(Classic, "", true), "OnlyKey");
    }

    /// OnlyKeyDevice: OKSETTIME is four big-endian unix-second bytes.
    #[test]
    fn only_key_device_encodes_oksettime_as_four_big_endian_unix_second_bytes() {
        assert_eq!(set_time_bytes(0x6a3d0f80), [0x6a, 0x3d, 0x0f, 0x80]);
        assert_eq!(set_time_bytes(0xff), [0x00, 0x00, 0x00, 0xff]);
        assert_eq!(set_time_bytes(0x1_0000_0001), [0, 0, 0, 1]);
    }

    /// OnlyKeyDevice: packets start with the header and message ID.
    #[test]
    fn only_key_device_should_construct_valid_hid_packets_with_headers() {
        let p = frame(MessageId::OkSetTime, None, None, &[1, 2, 3, 4]);
        assert_eq!(&p[..5], &[0xFF, 0xFF, 0xFF, 0xFF, 0xE4]);
        assert_eq!(&p[5..9], &[1, 2, 3, 4]);
        assert!(p[9..].iter().all(|&b| b == 0));
    }

    /// Extra: slot and field bytes follow the message ID; data comes after.
    #[test]
    fn frame_places_slot_and_field() {
        let p = frame(
            MessageId::OkSetSlot,
            Some(1),
            Some(FieldId::Password as u8),
            b"pw",
        );
        assert_eq!(&p[4..9], &[0xE6, 1, 5, b'p', b'w']);
        let p = frame(MessageId::OkWipeSlot, Some(GLOBAL_SLOT), Some(10), &[]);
        assert_eq!(&p[4..8], &[0xE7, 0, 10, 0]);
        let p = frame(MessageId::OkRestore, Some(0xFF), None, &[9]);
        assert_eq!(&p[4..7], &[0xF1, 0xFF, 9]);
    }

    /// Extra: data past byte 64 is silently truncated (57 data bytes with slot+field).
    #[test]
    fn frame_truncates_past_64_bytes() {
        let data: Vec<u8> = (1..=70).collect();
        let p = frame(MessageId::OkSetSlot, Some(3), Some(5), &data);
        assert_eq!(&p[7..], &data[..57]);
        let p = frame(MessageId::OkFwUpdate, None, None, &data);
        assert_eq!(&p[5..], &data[..59]);
    }

    /// Extra: timeout names match the TS enum.
    #[test]
    fn message_id_names() {
        assert_eq!(MessageId::OkSetTime.name(), "OKSETTIME");
        assert_eq!(MessageId::OkRestore as u8, 0xF1);
    }

    /// Extra: DUO columns are physical 1 | 3 | 2, six slots per profile.
    #[test]
    fn duo_profile_columns_match_firmware_constants() {
        let green = DUO_PROFILE_COLUMNS[0];
        assert_eq!(green[0], [sc("1a", 1), sc("1b", 4)]);
        assert_eq!(green[1], [sc("3a", 3), sc("3b", 6)]);
        assert_eq!(green[2], [sc("2a", 2), sc("2b", 5)]);
        let purple = DUO_PROFILE_COLUMNS[3];
        assert_eq!(purple[0], [sc("1a", 19), sc("1b", 22)]);
        assert_eq!(purple[1], [sc("3a", 21), sc("3b", 24)]);
        assert_eq!(purple[2], [sc("2a", 20), sc("2b", 23)]);
        let mut all: Vec<u8> = DUO_PROFILE_COLUMNS
            .iter()
            .flatten()
            .flatten()
            .map(|c| c.index)
            .collect();
        all.sort_unstable();
        assert_eq!(all, (1..=24).collect::<Vec<u8>>());
    }

    /// Extra: Classic rows cover 1a–6b ↔ 1–12.
    #[test]
    fn classic_slot_rows_map_1a_6b_to_1_12() {
        let cells: Vec<SlotCell> = CLASSIC_SLOT_ROWS
            .iter()
            .flat_map(|r| r.left.into_iter().chain(r.right))
            .collect();
        for c in &cells {
            let button = c.id.as_bytes()[0] - b'0';
            let want = if c.id.ends_with('a') {
                button
            } else {
                button + 6
            };
            assert_eq!(c.index, want, "{}", c.id);
        }
        assert_eq!(cells.len(), 12);
    }

    /// Extra: USB IDs are tried DUO first, bootloader last.
    #[test]
    fn usb_ids_are_in_connect_order() {
        assert_eq!(USB_IDS[0], (0x1D50, 0x614C));
        assert_eq!(USB_IDS[4], (0x1D50, 0x60FC));
        assert_eq!(USB_IDS[5], (0x0000, 0xB001));
    }
}
