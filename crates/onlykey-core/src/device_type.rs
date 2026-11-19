//! Classic/DUO/Unknown detection and allowed transitions.
//!
//! Port of `src/api/device/deviceTypeFromStatus.ts` and the rules in
//! `OnlyKeyDevice.ts:174-204` (`applyDeviceTypeFromResponse`, `inferDeviceTypeFromLabels`).

use crate::protocol::is_duo_no_pin_version;

/// Engine-side device type, as the TS `DeviceType` (includes bootloader and uninitialized).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    /// Full-size OnlyKey.
    Classic,
    /// OnlyKey DUO.
    Duo,
    /// Not identified yet (reset on every connect).
    #[default]
    Unknown,
    /// Bootloader (PID 0xB001 or a BOOTLOADER status).
    Bootloader,
    /// First-use; kept for parity, the parser reports the hardware type instead.
    Uninitialized,
}

/// Where a type candidate came from; decides which transitions are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSource<'a> {
    /// A firmware status string; carries the full status text (its last letter can demote DUO).
    Status(&'a str),
    /// The USB product ID.
    Usb,
    /// The label stream.
    Labels,
}

/// Type from the last letter of a status/version: `c` Classic, `p`/`n` DUO.
pub fn from_suffix(text: &str) -> Option<DeviceType> {
    match text.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('n' | 'p') => Some(DeviceType::Duo),
        Some('c') => Some(DeviceType::Classic),
        _ => None,
    }
}

/// Hardware type of an `UNINITIALIZED*` status: suffix letter, else `-D` → DUO, else Classic.
pub fn from_uninitialized_status(text: &str) -> DeviceType {
    from_suffix(text).unwrap_or(
        if text.contains("INITIALIZED-D") || text.contains("UNLOCKED-D") {
            DeviceType::Duo
        } else {
            DeviceType::Classic
        },
    )
}

/// Type from firmware status text (`inferDeviceTypeFromStatusText`); major version is a weak fallback.
pub fn from_status(text: &str) -> Option<DeviceType> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if t.contains("UNINITIALIZED") {
        return Some(from_uninitialized_status(t));
    }
    if t.contains("BOOTLOADER") {
        return Some(DeviceType::Bootloader);
    }
    if t.contains("INITIALIZED-D") || t.contains("UNLOCKED-D") {
        return Some(DeviceType::Duo);
    }
    if t.contains("INITIALIZED") {
        return Some(DeviceType::Classic);
    }
    if let Some(ty) = from_suffix(t) {
        return Some(ty);
    }
    match first_major_after_v(t) {
        Some("2") => Some(DeviceType::Classic),
        Some("3") => Some(DeviceType::Duo),
        _ => None,
    }
}

/// Digits of the first `v<digits>.` (case-insensitive `v`), as regex `/v(\d+)\./i`.
fn first_major_after_v(t: &str) -> Option<&str> {
    let b = t.as_bytes();
    (0..b.len()).find_map(|i| {
        if !b[i].eq_ignore_ascii_case(&b'v') {
            return None;
        }
        let digits = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        (digits > 0 && b.get(i + 1 + digits) == Some(&b'.')).then(|| &t[i + 1..i + 1 + digits])
    })
}

/// Type from a version string (`inferDeviceTypeFromVersion`): suffix letter, else `v3.` DUO / `v2.` Classic.
pub fn from_version(version: &str) -> Option<DeviceType> {
    let v = version.trim().to_lowercase();
    if v.is_empty() {
        return None;
    }
    if let Some(ty) = from_suffix(&v) {
        return Some(ty);
    }
    let core = v.strip_prefix('v').unwrap_or(&v);
    if core.starts_with("3.") {
        Some(DeviceType::Duo)
    } else if core.starts_with("2.") {
        Some(DeviceType::Classic)
    } else {
        None
    }
}

/// True for a first-use device: type `Uninitialized` or `is_initialized == Some(false)`.
pub fn is_uninitialized_device(is_initialized: Option<bool>, ty: DeviceType) -> bool {
    ty == DeviceType::Uninitialized || is_initialized == Some(false)
}

/// Highest slot id seen, 0 when none.
pub fn max_label_slot(slot_ids: &[u8]) -> u8 {
    slot_ids.iter().copied().max().unwrap_or(0)
}

/// DUO when any label slot is above 12 (Classic stops at 12).
pub fn from_label_slots(slot_ids: &[u8]) -> Option<DeviceType> {
    slot_ids
        .iter()
        .any(|&id| id > 12)
        .then_some(DeviceType::Duo)
}

/// An idle-ended stream of at least 12 labels with no slot above 12 confirms Classic.
pub fn classic_confirmed_by_labels(
    slot_ids: &[u8],
    label_count: usize,
    ended_by_idle: bool,
) -> bool {
    ended_by_idle && label_count >= 12 && max_label_slot(slot_ids) <= 12
}

/// Applies a type candidate; returns the new type when the transition is allowed and changes it.
///
/// Status/USB may switch Classic ↔ DUO (hot-plug); DUO → Classic from status only with a `c`
/// suffix; labels never move away from a known Classic/DUO.
pub fn apply_transition(
    current: DeviceType,
    candidate: Option<DeviceType>,
    source: TypeSource<'_>,
) -> Option<DeviceType> {
    use DeviceType::*;
    let next = candidate.filter(|&t| t != Unknown && t != current)?;
    let from_usb = source == TypeSource::Usb;
    let status_text = match source {
        TypeSource::Status(text) => Some(text),
        _ => None,
    };
    let can_set = current == Unknown
        || next == Uninitialized
        || next == Bootloader
        || (current == Uninitialized && matches!(next, Classic | Duo))
        || (current == Classic && next == Duo && (status_text.is_some() || from_usb))
        || (current == Duo
            && next == Classic
            && (from_usb || status_text.is_some_and(|t| from_suffix(t) == Some(Classic))));
    can_set.then_some(next)
}

/// Type change after a label stream (`inferDeviceTypeFromLabels`); `slot_ids` are distinct.
///
/// Slot > 12 proposes DUO through [`apply_transition`]; an idle 12-slot stream sets Classic only
/// while the type is still `Unknown`.
pub fn from_labels(
    current: DeviceType,
    slot_ids: &[u8],
    ended_by_idle: bool,
) -> Option<DeviceType> {
    if let Some(duo) = from_label_slots(slot_ids) {
        return apply_transition(current, Some(duo), TypeSource::Labels);
    }
    (classic_confirmed_by_labels(slot_ids, slot_ids.len(), ended_by_idle)
        && current == DeviceType::Unknown)
        .then_some(DeviceType::Classic)
}

/// Whether a device PIN is set: false only for a DUO whose version ends in `n`.
pub fn pin_set(ty: DeviceType, version: &str) -> bool {
    ty != DeviceType::Duo || !is_duo_no_pin_version(version)
}

#[cfg(test)]
mod tests {
    //! Ports of `deviceTypeFromStatus.test.ts` and the type-transition cases in `OnlyKeyDevice.test.ts`.

    use super::DeviceType::*;
    use super::*;
    use crate::protocol::device_type_from_product_id;

    /// UNLOCKED BOOTLOADERv1 and BOOTLOADER are bootloader.
    #[test]
    fn device_type_recognizes_unlocked_bootloaderv1_as_bootloader() {
        assert_eq!(from_status("UNLOCKED BOOTLOADERv1"), Some(Bootloader));
        assert_eq!(from_status("BOOTLOADER"), Some(Bootloader));
    }

    /// UNINITIALIZED is classified by the hardware letter.
    #[test]
    fn device_type_classifies_uninitialized_by_hardware_letter_like_5_6_set_device_type() {
        assert_eq!(from_status("UNINITIALIZEDv2.1.0-prod"), Some(Classic));
        assert_eq!(from_status("UNINITIALIZEDv3.0.4-testc"), Some(Classic));
        assert_eq!(from_status("UNINITIALIZEDv3.0.4-testp"), Some(Duo));
        assert_eq!(from_status("UNINITIALIZEDv3.0.4-testn"), Some(Duo));
        assert_eq!(from_status("UNINITIALIZED-Dv3.0.0-prod"), Some(Duo));
        assert_eq!(
            from_uninitialized_status("UNINITIALIZEDv3.0.4-TEST"),
            Classic
        );
        assert!(is_uninitialized_device(Some(false), Duo));
        assert!(!is_uninitialized_device(Some(true), Duo));
        assert!(is_uninitialized_device(None, Uninitialized));
    }

    /// INITIALIZED-D and UNLOCKED-D are DUO.
    #[test]
    fn device_type_recognizes_duo_from_initialized_d_and_unlocked_d() {
        assert_eq!(from_status("INITIALIZED-Dv3.0.0-prod"), Some(Duo));
        assert_eq!(from_status("UNLOCKED-Dv3.0.0-prod"), Some(Duo));
    }

    /// UNLOCKED is classified by the suffix letter, not the major version.
    #[test]
    fn device_type_classifies_unlocked_by_the_version_suffix_letter_not_the_major_version() {
        assert_eq!(from_status("UNLOCKEDv3.0.4-prodc"), Some(Classic));
        assert_eq!(from_status("UNLOCKEDv3.0.4-prodp"), Some(Duo));
        assert_eq!(from_status("UNLOCKEDv2.1.0-prodc"), Some(Classic));
        assert_eq!(from_version("v3.0.4-prodc"), Some(Classic));
        assert_eq!(from_version("v3.0.4-prodp"), Some(Duo));
        assert_eq!(from_version("v2.1.0-proc"), Some(Classic));
    }

    /// Major version is used only without a suffix letter.
    #[test]
    fn device_type_falls_back_to_major_version_only_when_the_suffix_letter_is_missing() {
        assert_eq!(from_status("UNLOCKEDv3.0.0-prod"), Some(Duo));
        assert_eq!(from_status("UNLOCKEDv2.1.0-prod"), Some(Classic));
        assert_eq!(from_version("v3.0.0-prod"), Some(Duo));
    }

    /// Label slots above 12 mean DUO.
    #[test]
    fn device_type_infers_duo_from_label_slot_indices_above_12() {
        assert_eq!(from_label_slots(&[1, 6, 12]), None);
        assert_eq!(from_label_slots(&[1, 13]), Some(Duo));
    }

    /// 12 idle labels with no slot above 12 confirm Classic.
    #[test]
    fn device_type_confirms_classic_when_12_labels_arrive_with_no_slot_above_12() {
        let slots: Vec<u8> = (1..=12).collect();
        assert_eq!(max_label_slot(&slots), 12);
        assert!(classic_confirmed_by_labels(&slots, 12, true));
        assert!(!classic_confirmed_by_labels(&slots, 12, false));
        assert!(!classic_confirmed_by_labels(&[1, 13], 13, true));
    }

    /// Legacy suffix letters still classify.
    #[test]
    fn device_type_uses_legacy_version_suffix_letters() {
        assert_eq!(from_status("UNLOCKEDv2.1.0-proc"), Some(Classic));
        assert_eq!(from_status("UNLOCKEDv3.0.0-prodp"), Some(Duo));
        assert_eq!(from_status("INITIALIZED-Dv3.0.0-prodn"), Some(Duo));
        assert!(is_duo_no_pin_version("INITIALIZED-Dv3.0.0-prodn"));
    }

    /// A trailing p wins over a v2 major.
    #[test]
    fn device_type_treats_a_trailing_p_as_duo_even_on_a_v2_version_string() {
        assert_eq!(from_status("UNLOCKEDv2.1.0-prodp"), Some(Duo));
    }

    /// Plain INITIALIZED is Classic; empty and bare UNLOCKED are unknown.
    #[test]
    fn device_type_treats_plain_initialized_as_classic_and_empty_text_as_unknown() {
        assert_eq!(from_status(""), None);
        assert_eq!(from_status("   "), None);
        assert_eq!(from_status("INITIALIZED"), Some(Classic));
        assert_eq!(from_status("UNLOCKED"), None);
    }

    /// Suffix letters work without a version number.
    #[test]
    fn device_type_uses_trailing_n_p_c_when_major_version_is_missing() {
        assert_eq!(from_status("UNLOCKEDprodn"), Some(Duo));
        assert_eq!(from_status("UNLOCKEDprodp"), Some(Duo));
        assert_eq!(from_status("UNLOCKEDprodc"), Some(Classic));
        assert_eq!(from_version(""), None);
        assert_eq!(from_version("customn"), Some(Duo));
        assert_eq!(from_version("customc"), Some(Classic));
        assert_eq!(from_version("mystery"), None);
    }

    /// DUO USB product IDs map to DUO; 0x60FC is ambiguous.
    #[test]
    fn device_type_maps_duo_usb_product_ids() {
        assert_eq!(device_type_from_product_id(0x614c), Some(Duo));
        assert_eq!(device_type_from_product_id(0x614e), Some(Duo));
        assert_eq!(device_type_from_product_id(0x4211), Some(Duo));
        assert_eq!(device_type_from_product_id(0x60fc), None);
        assert_eq!(device_type_from_product_id(0x0486), Some(Classic));
    }

    /// OnlyKeyDevice: a wiped DUO/Classic is typed from the UNINITIALIZED suffix, both ways.
    #[test]
    fn only_key_device_classifies_a_wiped_duo_from_uninitialized_suffix_letter() {
        let s = "UNINITIALIZEDv3.0.4-testp";
        assert_eq!(
            apply_transition(Unknown, from_status(s), TypeSource::Status(s)),
            Some(Duo)
        );
        let s = "UNINITIALIZEDv3.0.4-testc";
        assert_eq!(
            apply_transition(Duo, from_status(s), TypeSource::Status(s)),
            Some(Classic)
        );
    }

    /// OnlyKeyDevice: a premature Classic is promoted on UNLOCKEDv3-prodp.
    #[test]
    fn only_key_device_promotes_a_premature_classic_to_duo_on_unlockedv3_prodp() {
        let s = "UNLOCKEDv3.0.4-prodp";
        assert_eq!(
            apply_transition(Classic, from_status(s), TypeSource::Status(s)),
            Some(Duo)
        );
    }

    /// OnlyKeyDevice: UNKNOWN becomes Classic on UNLOCKEDv3.0.4-prodc.
    #[test]
    fn only_key_device_keeps_classic_on_unlockedv3_0_4_prodc() {
        let s = "UNLOCKEDv3.0.4-prodc";
        assert_eq!(
            apply_transition(Unknown, from_status(s), TypeSource::Status(s)),
            Some(Classic)
        );
    }

    /// OnlyKeyDevice: HID `1a` (slot 20) labels do not promote a Classic.
    #[test]
    fn only_key_device_does_not_promote_classic_to_duo_from_hid_1a_slot_20_labels() {
        assert_eq!(from_labels(Classic, &[1, 20], true), None);
    }

    /// OnlyKeyDevice: a leftover DUO is corrected to Classic on a `c` status.
    #[test]
    fn only_key_device_corrects_leftover_duo_to_classic_on_unlockedv3_0_4_prodc() {
        let s = "UNLOCKEDv3.0.4-prodc";
        assert_eq!(
            apply_transition(Duo, from_status(s), TypeSource::Status(s)),
            Some(Classic)
        );
    }

    /// OnlyKeyDevice: 12 idle labels do not demote a DUO.
    #[test]
    fn only_key_device_does_not_demote_a_status_identified_duo_when_12_labels_idle() {
        let slots: Vec<u8> = (1..=12).collect();
        assert_eq!(from_labels(Duo, &slots, true), None);
    }

    /// OnlyKeyDevice: 12 idle labels identify Classic only from UNKNOWN.
    #[test]
    fn only_key_device_identifies_classic_from_a_12_slot_idle_only_while_type_is_still_unknown() {
        let slots: Vec<u8> = (1..=12).collect();
        assert_eq!(from_labels(Unknown, &slots, true), Some(Classic));
        assert_eq!(from_labels(Unknown, &slots, false), None);
    }

    /// OnlyKeyDevice: 24 labels leave a USB DUO alone.
    #[test]
    fn only_key_device_keeps_a_usb_identified_duo_when_24_labels_arrive() {
        let slots: Vec<u8> = (1..=24).collect();
        assert_eq!(from_labels(Duo, &slots, true), None);
        assert_eq!(max_label_slot(&slots), 24);
    }

    /// OnlyKeyDevice: slot 13 promotes UNKNOWN to DUO.
    #[test]
    fn only_key_device_promotes_unknown_to_duo_from_slot_13() {
        assert_eq!(from_labels(Unknown, &[1, 13], true), Some(Duo));
    }

    /// OnlyKeyDevice: a later Classic-looking status without `c` does not demote DUO.
    #[test]
    fn only_key_device_does_not_downgrade_duo_to_classic_on_later_status_messages() {
        let s = "INITIALIZEDv2.1.0-prod";
        assert_eq!(
            apply_transition(Duo, from_status(s), TypeSource::Status(s)),
            None
        );
    }

    /// Extra: the full transition table, incl. USB and bootloader/uninitialized overrides.
    #[test]
    fn apply_transition_rules() {
        let st = TypeSource::Status("UNLOCKEDv3.0.4-prod");
        // No-op candidates.
        assert_eq!(apply_transition(Classic, None, st), None);
        assert_eq!(apply_transition(Classic, Some(Unknown), st), None);
        assert_eq!(apply_transition(Duo, Some(Duo), st), None);
        // USB may switch both ways.
        assert_eq!(
            apply_transition(Classic, Some(Duo), TypeSource::Usb),
            Some(Duo)
        );
        assert_eq!(
            apply_transition(Duo, Some(Classic), TypeSource::Usb),
            Some(Classic)
        );
        // Labels never switch a known type.
        assert_eq!(
            apply_transition(Classic, Some(Duo), TypeSource::Labels),
            None
        );
        assert_eq!(
            apply_transition(Duo, Some(Classic), TypeSource::Labels),
            None
        );
        // Bootloader / uninitialized always apply; uninitialized resolves to hardware.
        assert_eq!(
            apply_transition(Duo, Some(Bootloader), TypeSource::Labels),
            Some(Bootloader)
        );
        assert_eq!(
            apply_transition(Classic, Some(Uninitialized), st),
            Some(Uninitialized)
        );
        assert_eq!(
            apply_transition(Uninitialized, Some(Duo), TypeSource::Labels),
            Some(Duo)
        );
        // Bootloader does not leave on a status (only a reconnect resets it).
        assert_eq!(apply_transition(Bootloader, Some(Classic), st), None);
        // DUO → Classic by status needs the `c` suffix on the status text.
        assert_eq!(apply_transition(Duo, Some(Classic), st), None);
    }

    /// Extra: pin_set is false only for DUO + `n`.
    #[test]
    fn pin_set_rules() {
        assert!(!pin_set(Duo, "v3.0.4-prodn"));
        assert!(pin_set(Duo, "v3.0.4-prodp"));
        assert!(pin_set(Classic, "v3.0.4-prodn"));
    }
}
