//! ResponseParser port (`Response` enum) and label slot mapping.
//!
//! Port of `src/api/device/ResponseParser.ts`; the branch order below is the original's.

use crate::device_type::{self, DeviceType};

/// A status report (UNINITIALIZED / BOOTLOADER / UNLOCKED* / INITIALIZED* / LOCKED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Printable text of the report, trimmed.
    pub text: String,
    /// Version after the status prefix (may be empty); `None` for bare LOCKED.
    pub version: Option<String>,
    /// Hardware type when the text names one.
    pub device_type: Option<DeviceType>,
    /// Whether the status means locked.
    pub is_locked: bool,
    /// `Some(false)` for first-use/bootloader, `Some(true)` for initialized, `None` when unstated.
    pub is_initialized: Option<bool>,
    /// PIN-set flag when the status states it.
    pub device_pin_set: Option<bool>,
}

/// One parsed input report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Text starting with "Error"/"ERROR".
    Error(String),
    /// A device status.
    Status(Status),
    /// One slot label from OKGETLABELS.
    Label {
        /// Logical slot 1–24.
        slot: u8,
        /// Label text after `|`, trimmed.
        label: String,
        /// Full printable text of the report.
        text: String,
    },
    /// Any other text (may be empty).
    Text(String),
}

/// HID label byte for a logical slot: 1–9 as-is, 10–24 as slot+6 (0x10–0x1E).
pub fn hid_label_slot_byte(slot: u8) -> u8 {
    if slot <= 9 { slot } else { slot + 6 }
}

/// Logical slot from the hex-rendered label id: `1a`–`1e` → 20–24, else the leading decimal digits.
///
/// Returns 0 when there are no leading digits (JS `parseInt(id, 10)` → NaN → 0).
pub fn parse_hid_label_slot_id(id: &str) -> u32 {
    match id.to_ascii_lowercase().as_str() {
        "1a" => 20,
        "1b" => 21,
        "1c" => 22,
        "1d" => 23,
        "1e" => 24,
        _ => id
            .bytes()
            .take_while(u8::is_ascii_digit)
            .fold(0u32, |acc, d| {
                acc.saturating_mul(10).saturating_add(u32::from(d - b'0'))
            }),
    }
}

/// `extractVersionAfterPrefix`: text after the last `prefix` when `prefix` + "v" occurs, else
/// the text with the first `prefix` removed; trimmed either way.
fn version_after(text: &str, prefix: &str) -> String {
    if text.contains(&format!("{prefix}v")) {
        text.rsplit(prefix).next().unwrap_or("").trim().to_string()
    } else {
        text.replacen(prefix, "", 1).trim().to_string()
    }
}

/// Parses one input report into a [`Response`], exactly as the original's decision order.
pub fn parse(report: &[u8; 64]) -> Response {
    let mut text = String::new();
    for (i, &b) in report.iter().enumerate() {
        if (32..127).contains(&b) {
            text.push(char::from(b));
        } else if i == 0 && b > 0 && report[1] == b'|' {
            // Label reports carry the slot as a raw byte; render it as two hex digits.
            text.push_str(&format!("{b:02x}"));
        }
    }
    let text = text.trim().to_string();

    if text.starts_with("Error") || text.starts_with("ERROR") {
        return Response::Error(text);
    }

    let status = |version: Option<String>,
                  device_type: Option<DeviceType>,
                  is_locked: bool,
                  is_initialized: Option<bool>,
                  device_pin_set: Option<bool>| {
        Response::Status(Status {
            text: text.clone(),
            version,
            device_type,
            is_locked,
            is_initialized,
            device_pin_set,
        })
    };

    if text.contains("UNINITIALIZED") {
        let ty = device_type::from_status(&text).unwrap_or(DeviceType::Classic);
        return status(
            Some(version_after(&text, "UNINITIALIZED")),
            Some(ty),
            false,
            Some(false),
            Some(false),
        );
    }
    // "UNLOCKED BOOTLOADERv1" is bootloader, not an application unlock.
    if text.contains("BOOTLOADER") {
        return status(
            Some(version_after(&text, "BOOTLOADER")),
            Some(DeviceType::Bootloader),
            false,
            Some(false),
            Some(false),
        );
    }
    let duo_pin_set = !crate::protocol::is_duo_no_pin_version(&text);
    if text.contains("UNLOCKED-D") {
        return status(
            Some(version_after(&text, "UNLOCKED-D")),
            Some(DeviceType::Duo),
            false,
            Some(true),
            Some(duo_pin_set),
        );
    }
    if text.contains("UNLOCKED") {
        let version = version_after(&text, "UNLOCKED");
        let ty = device_type::from_status(&text).or_else(|| device_type::from_version(&version));
        let pin_set = if ty == Some(DeviceType::Duo) {
            duo_pin_set
        } else {
            true
        };
        return status(Some(version), ty, false, Some(true), Some(pin_set));
    }
    if text.contains("INITIALIZED-D") {
        return status(
            Some(version_after(&text, "INITIALIZED-D")),
            Some(DeviceType::Duo),
            true,
            Some(true),
            Some(duo_pin_set),
        );
    }
    if text.contains("INITIALIZED") {
        return status(
            Some(version_after(&text, "INITIALIZED")),
            Some(DeviceType::Classic),
            true,
            Some(true),
            None,
        );
    }
    if text.contains("LOCKED") {
        return status(None, None, true, None, None);
    }

    // `^(\w+)\|(.*)`: a run of word characters, then '|'.
    let word = text
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    if word > 0 && text.as_bytes().get(word) == Some(&b'|') {
        let slot = parse_hid_label_slot_id(&text[..word]);
        if (1..=24).contains(&slot) {
            return Response::Label {
                slot: slot as u8,
                label: text[word + 1..].trim().to_string(),
                text,
            };
        }
    }
    Response::Text(text)
}

#[cfg(test)]
mod tests {
    //! Ports of `ResponseParser.test.ts`, plus decision-order and slot-mapping cases.

    use super::*;

    /// Builds a 64-byte report from ASCII text (`stringToPacket`).
    fn packet(text: &str) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[..text.len()].copy_from_slice(text.as_bytes());
        p
    }

    /// Builds a firmware-coded label report for a logical slot.
    fn label_packet(slot: u8, label: &str) -> [u8; 64] {
        let mut p = [0u8; 64];
        p[0] = hid_label_slot_byte(slot);
        p[1] = b'|';
        p[2..2 + label.len()].copy_from_slice(label.as_bytes());
        p
    }

    /// Unwraps a status response.
    fn status(r: Response) -> Status {
        match r {
            Response::Status(s) => s,
            other => panic!("not a status: {other:?}"),
        }
    }

    /// A wiped device is uninitialized, not locked.
    #[test]
    fn response_parser_treats_a_wiped_device_as_uninitialized_not_locked() {
        let s = status(parse(&packet("UNINITIALIZEDv2.1.0-prod")));
        assert_eq!(s.device_type, Some(DeviceType::Classic));
        assert_eq!(s.is_initialized, Some(false));
        assert!(!s.is_locked);
        assert_eq!(s.device_pin_set, Some(false));
        assert_eq!(s.version.as_deref(), Some("v2.1.0-prod"));
    }

    /// UNINITIALIZED keeps the hardware type from the suffix letter.
    #[test]
    fn response_parser_keeps_duo_hardware_type_on_uninitialized_with_a_p_n_suffix() {
        let duo = status(parse(&packet("UNINITIALIZEDv3.0.4-testp")));
        assert_eq!(duo.device_type, Some(DeviceType::Duo));
        assert_eq!(duo.is_initialized, Some(false));
        assert!(!duo.is_locked);
        assert_eq!(duo.version.as_deref(), Some("v3.0.4-testp"));
        let classic = status(parse(&packet("UNINITIALIZEDv3.0.4-testc")));
        assert_eq!(classic.device_type, Some(DeviceType::Classic));
        assert_eq!(classic.is_initialized, Some(false));
    }

    /// INITIALIZED is a locked Classic.
    #[test]
    fn response_parser_should_parse_only_key_classic_initialization() {
        let s = status(parse(&packet("INITIALIZEDv2.1.0-prod")));
        assert_eq!(s.device_type, Some(DeviceType::Classic));
        assert!(s.is_locked);
        assert_eq!(s.version.as_deref(), Some("v2.1.0-prod"));
    }

    /// INITIALIZED-D is a locked DUO.
    #[test]
    fn response_parser_should_parse_only_key_duo_initialization() {
        let s = status(parse(&packet("INITIALIZED-Dv3.0.0-prod")));
        assert_eq!(s.device_type, Some(DeviceType::Duo));
        assert!(s.is_locked);
    }

    /// UNLOCKED v3 with `c` stays Classic.
    #[test]
    fn response_parser_should_keep_classic_on_unlocked_v3_firmware_with_a_c_suffix() {
        let s = status(parse(&packet("UNLOCKEDv3.0.4-prodc")));
        assert!(!s.is_locked);
        assert_eq!(s.version.as_deref(), Some("v3.0.4-prodc"));
        assert_eq!(s.device_type, Some(DeviceType::Classic));
    }

    /// UNLOCKED v3 with `p` is DUO.
    #[test]
    fn response_parser_should_infer_duo_from_unlocked_v3_firmware_with_a_p_suffix() {
        let s = status(parse(&packet("UNLOCKEDv3.0.4-prodp")));
        assert!(!s.is_locked);
        assert_eq!(s.version.as_deref(), Some("v3.0.4-prodp"));
        assert_eq!(s.device_type, Some(DeviceType::Duo));
    }

    /// UNLOCKED-D is an unlocked DUO.
    #[test]
    fn response_parser_should_parse_duo_unlocked_state_with_d_prefix() {
        let s = status(parse(&packet("UNLOCKED-Dv3.0.0-prod")));
        assert_eq!(s.device_type, Some(DeviceType::Duo));
        assert!(!s.is_locked);
    }

    /// Text labels parse.
    #[test]
    fn response_parser_should_parse_slot_labels_correctly() {
        assert_eq!(
            parse(&packet("01|GitHub Login")),
            Response::Label {
                slot: 1,
                label: "GitHub Login".into(),
                text: "01|GitHub Login".into()
            }
        );
    }

    /// HID hex 1a–1e are slots 20–24.
    #[test]
    fn response_parser_maps_hid_hex_1a_1e_to_slots_20_24_not_classic_buttons() {
        assert!(matches!(
            parse(&packet("1a|Work VPN")),
            Response::Label { slot: 20, ref label, .. } if label == "Work VPN"
        ));
        assert_eq!(parse_hid_label_slot_id("1e"), 24);
        assert_eq!(parse_hid_label_slot_id("10"), 10);
    }

    /// Firmware-coded binary label bytes decode for slots 1, 10, 12, 20, 24.
    #[test]
    fn response_parser_decodes_firmware_coded_binary_label_reports() {
        assert_eq!(hid_label_slot_byte(9), 9);
        assert_eq!(hid_label_slot_byte(10), 0x10);
        assert_eq!(hid_label_slot_byte(12), 0x12);
        assert_eq!(hid_label_slot_byte(20), 0x1a);
        assert_eq!(hid_label_slot_byte(24), 0x1e);
        for (slot, name) in [
            (1, "Gmail"),
            (10, "Slack"),
            (12, "Bank"),
            (20, "Yellow"),
            (24, "Purple"),
        ] {
            assert!(matches!(
                parse(&label_packet(slot, name)),
                Response::Label { slot: s, ref label, .. } if s == slot && label == name
            ));
        }
    }

    /// Extra: every logical slot 1–24 round-trips through the HID byte.
    #[test]
    fn label_slot_mapping_round_trips_1_to_24() {
        for slot in 1..=24u8 {
            match parse(&label_packet(slot, "x")) {
                Response::Label { slot: s, .. } => assert_eq!(s, slot),
                other => panic!("slot {slot}: {other:?}"),
            }
        }
    }

    /// A raw 0x0A byte (slot 10 un-coded) is not a label.
    #[test]
    fn response_parser_does_not_treat_a_raw_slot_10_byte_0x0a_as_a_firmware_label() {
        let mut p = [0u8; 64];
        p[0] = 10;
        p[1] = b'|';
        p[2] = b'X';
        assert_eq!(parse(&p), Response::Text("0a|X".into()));
    }

    /// BOOTLOADER is an unlocked status.
    #[test]
    fn response_parser_treats_bootloader_as_an_unlocked_status_not_free_text() {
        let s = status(parse(&packet("BOOTLOADER")));
        assert_eq!(s.device_type, Some(DeviceType::Bootloader));
        assert!(!s.is_locked);
        assert_eq!(s.text, "BOOTLOADER");
        assert_eq!(s.version.as_deref(), Some(""));
    }

    /// UNLOCKED BOOTLOADERv1 is bootloader, not an unlock.
    #[test]
    fn response_parser_does_not_treat_unlocked_bootloaderv1_as_an_initialized_unlock() {
        let s = status(parse(&packet("UNLOCKED BOOTLOADERv1")));
        assert_eq!(s.device_type, Some(DeviceType::Bootloader));
        assert!(!s.is_locked);
        assert_eq!(s.version.as_deref(), Some("v1"));
        assert_eq!(s.device_pin_set, Some(false));
    }

    /// Error text is an error.
    #[test]
    fn response_parser_should_parse_error_messages() {
        assert_eq!(
            parse(&packet("Error: Not in Config Mode")),
            Response::Error("Error: Not in Config Mode".into())
        );
    }

    /// All-zero report is empty text.
    #[test]
    fn response_parser_should_handle_empty_or_garbage_data_gracefully() {
        assert_eq!(parse(&[0u8; 64]), Response::Text(String::new()));
    }

    /// Extra: decision order — error beats status words, UNINITIALIZED beats BOOTLOADER/INITIALIZED,
    /// BOOTLOADER beats UNLOCKED, status words beat label syntax.
    #[test]
    fn decision_order() {
        assert!(matches!(
            parse(&packet("ERROR UNLOCKED")),
            Response::Error(_)
        ));
        assert!(matches!(parse(&packet("error x")), Response::Text(_)));
        let s = status(parse(&packet("UNINITIALIZED BOOTLOADER")));
        assert_eq!(s.is_initialized, Some(false));
        assert_eq!(s.device_type, Some(DeviceType::Classic));
        let s = status(parse(&packet("UNLOCKED-D INITIALIZED-D")));
        assert!(!s.is_locked);
        let s = status(parse(&packet("LOCKED")));
        assert_eq!(
            s,
            Status {
                text: "LOCKED".into(),
                version: None,
                device_type: None,
                is_locked: true,
                is_initialized: None,
                device_pin_set: None,
            }
        );
        // A label whose text contains a status word parses as that status (original order).
        assert!(matches!(
            parse(&packet("01|LOCKED box")),
            Response::Status(_)
        ));
    }

    /// Extra: INITIALIZED leaves pin-set unstated; DUO `n` suffix clears it.
    #[test]
    fn pin_set_flags() {
        assert_eq!(
            status(parse(&packet("INITIALIZEDv2.1.0-prod"))).device_pin_set,
            None
        );
        assert_eq!(
            status(parse(&packet("INITIALIZED-Dv3.0.0-prodn"))).device_pin_set,
            Some(false)
        );
        assert_eq!(
            status(parse(&packet("UNLOCKEDv3.0.4-prodn"))).device_pin_set,
            Some(false)
        );
        assert_eq!(
            status(parse(&packet("UNLOCKEDv3.0.4-prodc"))).device_pin_set,
            Some(true)
        );
        assert_eq!(status(parse(&packet("UNLOCKED"))).device_type, None);
    }

    /// Extra: non-printable bytes anywhere are dropped; label id parsing mimics parseInt.
    #[test]
    fn printable_filter_and_slot_id_parsing() {
        let mut p = packet("OK");
        p[10] = b'!';
        assert_eq!(parse(&p), Response::Text("OK!".into()));
        assert_eq!(parse_hid_label_slot_id("1f"), 1);
        assert_eq!(parse_hid_label_slot_id("ab"), 0);
        assert!(matches!(parse(&packet("25|x")), Response::Text(_)));
        assert!(matches!(parse(&packet("00|x")), Response::Text(_)));
        assert!(matches!(parse(&packet("|x")), Response::Text(_)));
    }

    /// Extra: version extraction uses the last prefix with `v`, else removes the first prefix.
    #[test]
    fn version_extraction() {
        assert_eq!(
            version_after("UNINITIALIZED-Dv3.0.0", "UNINITIALIZED"),
            "-Dv3.0.0"
        );
        assert_eq!(
            version_after("UNLOCKEDv3.0.4-prodc", "UNLOCKED"),
            "v3.0.4-prodc"
        );
    }
}
