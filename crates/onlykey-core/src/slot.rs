//! Slot form → ordered `SetSlot` commands, with the original validation (`slotConfigService.ts`).
//!
//! Pure and UI-free: the slot editor and 1Password sync both build their writes here.

use crate::api::Command;
use crate::encoding::{EncodingError, base32_to_bytes, hex_to_bytes, hex_to_modhex, latin1_bytes};
use crate::protocol::{
    FieldId, MFA_TYPE_GOOGLE_AUTH, MFA_TYPE_YUBI_OTP, NEXTKEY_AFTER_FIELD_OPTIONS,
    NEXTKEY_AFTER_OTP_OPTIONS, NEXTKEY_BEFORE_FIELD_OPTIONS,
};
use std::fmt;

/// Max label length (characters).
pub const LABEL_MAX: usize = 16;
/// Max URL, username and password length (characters).
pub const FIELD_MAX: usize = 56;
/// Max TOTP secret bytes (one HID payload).
pub const TOTP_MAX_BYTES: usize = 57;

/// Yubico OTP inputs: public id (modhex), private id (hex), secret key (hex).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Yubikey {
    /// Public identity, modhex.
    pub public_id: String,
    /// Private identity, hex (first 12 digits used).
    pub private_id: String,
    /// AES secret key, hex (first 32 digits used).
    pub secret_key: String,
}

/// One slot edit. `None` = checkbox off (not written); `Some` = checkbox on.
///
/// Holds secrets: no `Debug`; drop it as soon as the commands are built.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SlotForm {
    /// Label (≤16); empty writes nothing.
    pub label: Option<String>,
    /// URL (≤56); empty writes nothing.
    pub url: Option<String>,
    /// Username (≤56); empty writes nothing.
    pub username: Option<String>,
    /// (password, re-entered password), ≤56; empty password writes nothing.
    pub password: Option<(String, String)>,
    /// Delay after URL, 0–9 s.
    pub delay1: Option<u8>,
    /// Delay after username, 0–9 s.
    pub delay2: Option<u8>,
    /// Delay before MFA, 0–9 s.
    pub delay3: Option<u8>,
    /// Key before username: 0 none, 1 tab.
    pub next_key4: Option<u8>,
    /// Key after username: 0 none, 1 tab, 2 return.
    pub next_key1: Option<u8>,
    /// Key after password: 0 none, 1 tab, 2 return.
    pub next_key2: Option<u8>,
    /// Key before OTP: 0 none, 1 tab.
    pub next_key5: Option<u8>,
    /// Key after OTP: 0 none, 1 tab, 2 return, 3 tab + return.
    pub next_key3: Option<u8>,
    /// Per-slot keyboard type speed, 1–10.
    pub type_speed: Option<u8>,
    /// OATH-TOTP secret, base32; blank sets nothing.
    pub totp: Option<String>,
    /// Yubico OTP; all blank sets nothing.
    pub yubikey: Option<Yubikey>,
}

impl zeroize::Zeroize for SlotForm {
    /// Wipes every text value (secrets included) so a `Zeroizing<SlotForm>` clears on drop.
    fn zeroize(&mut self) {
        for v in [
            &mut self.label,
            &mut self.url,
            &mut self.username,
            &mut self.totp,
        ] {
            v.zeroize();
        }
        if let Some((pw, confirm)) = &mut self.password {
            pw.zeroize();
            confirm.zeroize();
        }
        if let Some(y) = &mut self.yubikey {
            y.public_id.zeroize();
            y.private_id.zeroize();
            y.secret_key.zeroize();
        }
    }
}

/// Why a slot form cannot be written; `Display` is the user-facing text (never the value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// Password and re-entry differ.
    PasswordMismatch,
    /// Both TOTP and Yubico OTP set.
    TotpAndYubikey,
    /// TOTP secret decodes to more than 57 bytes.
    TotpTooLong(usize),
    /// Some Yubico field blank.
    YubikeyBlank,
    /// DUO without PIN: password and MFA together.
    DuoNoPinMixed,
    /// DUO without PIN: username or URL checked.
    DuoNoPinUsernameUrl,
    /// Text outside Latin-1.
    NotLatin1,
    /// Text longer than the field allows.
    TooLong {
        /// Field name as shown in the editor.
        field: &'static str,
        /// Max characters.
        max: usize,
    },
    /// A delay, next-key or type-speed value out of range.
    OutOfRange(&'static str),
    /// Bad base32 / modhex / hex.
    Encoding(EncodingError),
}

impl fmt::Display for SlotError {
    /// Writes the original app's wording (new checks get plain wording of their own).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordMismatch => f.write_str("Password fields do not match."),
            Self::TotpAndYubikey => f.write_str("Set OATH-TOTP or Yubikey OTP per slot — not both."),
            Self::TotpTooLong(n) => write!(
                f,
                "TOTP secret is too long for OnlyKey ({n} bytes). Maximum is 57 bytes (91 Base32 characters)."
            ),
            Self::YubikeyBlank => {
                f.write_str("Yubikey public ID, private ID, and secret cannot be blank.")
            }
            Self::DuoNoPinMixed => f.write_str(
                "OnlyKey Duo without a device PIN supports static password OR MFA per slot — not both. Set a device PIN in Setup to enable full login slots.",
            ),
            Self::DuoNoPinUsernameUrl => {
                f.write_str("Username and URL require a device PIN on OnlyKey Duo.")
            }
            Self::NotLatin1 => f.write_str(
                "OnlyKey slots store Latin-1 (ISO-8859-1) text only; remove characters such as € or emoji",
            ),
            Self::TooLong { field, max } => write!(f, "{field} is longer than {max} characters."),
            Self::OutOfRange(field) => write!(f, "{field} is out of range."),
            Self::Encoding(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SlotError {}

impl From<EncodingError> for SlotError {
    /// Wraps an encoding failure.
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e)
    }
}

/// `SetSlot` for one field.
fn set(slot: u8, field: FieldId, value: Vec<u8>) -> Command {
    Command::SetSlot {
        slot,
        field: field as u8,
        value,
    }
}

/// Latin-1 bytes of `text`, rejecting it when longer than `max` characters.
fn text(text: &str, field: &'static str, max: usize) -> Result<Vec<u8>, SlotError> {
    if text.chars().count() > max {
        return Err(SlotError::TooLong { field, max });
    }
    latin1_bytes(text).ok_or(SlotError::NotLatin1)
}

/// The value as one ASCII digit (the original sends these fields as strings), if `ok`.
fn digit(value: u8, ok: bool, field: &'static str) -> Result<Vec<u8>, SlotError> {
    if ok && value <= 9 {
        Ok(vec![b'0' + value])
    } else {
        Err(SlotError::OutOfRange(field))
    }
}

/// True when `v` is one of the option values.
fn allowed(v: u8, options: &[(u8, &str)]) -> bool {
    options.iter().any(|(o, _)| *o == v)
}

/// (value, field, editor name, allowed options) for one next-key field.
type NextKeyRow<'a> = (Option<u8>, FieldId, &'static str, &'a [(u8, &'static str)]);

/// Text with all whitespace removed.
fn strip(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// First `n` characters.
fn take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Validates `form` and returns the writes for `slot` in device order:
/// label, url, username, password, delays 1–3, next keys 4/1/2/5/3, type speed, MFA.
///
/// `duo_no_pin` applies the DUO-without-PIN rules. Unlike the original, every check runs
/// before anything is returned, so a rejected form writes nothing.
pub fn build_slot_commands(
    slot: u8,
    form: &SlotForm,
    duo_no_pin: bool,
) -> Result<Vec<Command>, SlotError> {
    let setting_password = form.password.as_ref().is_some_and(|(p, _)| !p.is_empty());
    let setting_totp = form.totp.as_ref().is_some_and(|t| !t.trim().is_empty());
    let setting_yubi = form.yubikey.as_ref().is_some_and(|y| {
        !(y.public_id.trim().is_empty()
            && y.private_id.trim().is_empty()
            && y.secret_key.trim().is_empty())
    });

    if duo_no_pin {
        if setting_password && (setting_totp || setting_yubi) {
            return Err(SlotError::DuoNoPinMixed);
        }
        if form.username.is_some() || form.url.is_some() {
            return Err(SlotError::DuoNoPinUsernameUrl);
        }
    }

    let mut out = Vec::new();
    for (value, field, name, max) in [
        (&form.label, FieldId::Label, "Label", LABEL_MAX),
        (&form.url, FieldId::Url, "URL", FIELD_MAX),
        (&form.username, FieldId::Username, "UserName", FIELD_MAX),
    ] {
        if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
            out.push(set(slot, field, text(v, name, max)?));
        }
    }
    if let Some((pw, confirm)) = form.password.as_ref().filter(|_| setting_password) {
        if pw != confirm {
            return Err(SlotError::PasswordMismatch);
        }
        out.push(set(
            slot,
            FieldId::Password,
            text(pw, "Password", FIELD_MAX)?,
        ));
    }

    let delays = [
        (form.delay1, FieldId::Delay1, "Delay after URL"),
        (form.delay2, FieldId::Delay2, "Delay after username"),
        (form.delay3, FieldId::Delay3, "Delay before MFA"),
    ];
    for (value, field, name) in delays {
        if let Some(v) = value {
            out.push(set(slot, field, digit(v, true, name)?));
        }
    }
    let next_keys: [NextKeyRow; 5] = [
        (
            form.next_key4,
            FieldId::NextKey4,
            "Tab before UserName",
            &NEXTKEY_BEFORE_FIELD_OPTIONS,
        ),
        (
            form.next_key1,
            FieldId::NextKey1,
            "After UserName",
            &NEXTKEY_AFTER_FIELD_OPTIONS,
        ),
        (
            form.next_key2,
            FieldId::NextKey2,
            "After Password",
            &NEXTKEY_AFTER_FIELD_OPTIONS,
        ),
        (
            form.next_key5,
            FieldId::NextKey5,
            "Tab before OTP",
            &NEXTKEY_BEFORE_FIELD_OPTIONS,
        ),
        (
            form.next_key3,
            FieldId::NextKey3,
            "Return after OTP",
            &NEXTKEY_AFTER_OTP_OPTIONS,
        ),
    ];
    for (value, field, name, options) in next_keys {
        if let Some(v) = value {
            out.push(set(slot, field, digit(v, allowed(v, options), name)?));
        }
    }
    if let Some(speed) = form.type_speed {
        if !(1..=10).contains(&speed) {
            return Err(SlotError::OutOfRange("Keyboard Type Speed"));
        }
        out.push(Command::SetSlotTypeSpeed { slot, speed });
    }

    if setting_totp && setting_yubi {
        return Err(SlotError::TotpAndYubikey);
    }
    if let Some(secret) = form.totp.as_deref().filter(|_| setting_totp) {
        let bytes = base32_to_bytes(&strip(secret))?;
        if bytes.len() > TOTP_MAX_BYTES {
            return Err(SlotError::TotpTooLong(bytes.len()));
        }
        out.push(set(slot, FieldId::TfaType, vec![MFA_TYPE_GOOGLE_AUTH]));
        out.push(set(slot, FieldId::TfaUsername, bytes));
    } else if let Some(y) = form.yubikey.as_ref().filter(|_| setting_yubi) {
        let (public, private, secret) = (
            strip(&y.public_id),
            strip(&y.private_id),
            strip(&y.secret_key),
        );
        if public.is_empty() || private.is_empty() || secret.is_empty() {
            return Err(SlotError::YubikeyBlank);
        }
        let hex =
            hex_to_modhex(&take(&public, 32), true)? + &take(&private, 12) + &take(&secret, 32);
        out.push(set(slot, FieldId::TfaType, vec![MFA_TYPE_YUBI_OTP]));
        out.push(set(slot, FieldId::YubiAuth, hex_to_bytes(&hex)?));
    }
    Ok(out)
}

/// The command that wipes every field of `slot` ("Wipe All Slot Data").
pub fn wipe_slot_command(slot: u8) -> Command {
    Command::WipeSlot { slot, field: None }
}

#[cfg(test)]
mod tests {
    //! Ports of `slotConfigService.test.ts` plus write-order, limits and Latin-1 checks.

    use super::*;

    /// Field ID and value of a `SetSlot`, or `(13, [speed])` for a type speed.
    fn field_values(cmds: &[Command]) -> Vec<(u8, Vec<u8>)> {
        cmds.iter()
            .map(|c| match c {
                Command::SetSlot { field, value, .. } => (*field, value.clone()),
                Command::SetSlotTypeSpeed { speed, .. } => (FieldId::TypeSpeed as u8, vec![*speed]),
                _ => panic!("unexpected command"),
            })
            .collect()
    }

    /// Yubico inputs with the given values.
    fn yubi(public: &str, private: &str, secret: &str) -> Option<Yubikey> {
        Some(Yubikey {
            public_id: public.into(),
            private_id: private.into(),
            secret_key: secret.into(),
        })
    }

    /// TOTP writes TFATYPE 'g' then the raw secret bytes.
    #[test]
    fn totp_writes_google_type_and_bytes() {
        let form = SlotForm {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        };
        let cmds = build_slot_commands(1, &form, false).unwrap();
        assert_eq!(
            field_values(&cmds),
            vec![
                (FieldId::TfaType as u8, vec![b'g']),
                (
                    FieldId::TfaUsername as u8,
                    base32_to_bytes("JBSWY3DPEHPK3PXP").unwrap()
                ),
            ]
        );
    }

    /// A secret over 57 bytes is rejected and nothing is written.
    #[test]
    fn totp_over_57_bytes_rejected() {
        let form = SlotForm {
            label: Some("x".into()),
            totp: Some("OVTRV4D6OSGWXK6PYUYFSEFQTFCCG6W5C4QMHVH3VM7KGD5YBC4XRKI4DQGPB6RFZA4ZPO2MMZJTRSQ6X2JKK2LCWVAVVZQSUYUURHY".into()),
            ..Default::default()
        };
        let err = build_slot_commands(1, &form, false).unwrap_err();
        assert!(matches!(err, SlotError::TotpTooLong(_)));
        assert!(err.to_string().contains("too long for OnlyKey"));
    }

    /// Yubico writes TFATYPE 'Y' (not the HMAC codes) then modhex→hex + private + secret bytes.
    #[test]
    fn yubikey_writes_yubi_type_and_auth() {
        let form = SlotForm {
            yubikey: yubi(
                "cccccccccccc",
                "001122334455",
                "00112233445566778899aabbccddeeff",
            ),
            ..Default::default()
        };
        let cmds = build_slot_commands(2, &form, false).unwrap();
        let mut auth = vec![0u8; 6];
        auth.extend(hex_to_bytes("001122334455").unwrap());
        auth.extend(hex_to_bytes("00112233445566778899aabbccddeeff").unwrap());
        assert_eq!(
            field_values(&cmds),
            vec![
                (FieldId::TfaType as u8, vec![b'Y']),
                (FieldId::YubiAuth as u8, auth)
            ]
        );
    }

    /// Every enabled field is written, in the original order.
    #[test]
    fn writes_enabled_fields_in_order() {
        let form = SlotForm {
            label: Some("Work".into()),
            url: Some("https://ex.test".into()),
            username: Some("ada".into()),
            password: Some(("secret".into(), "secret".into())),
            delay1: Some(2),
            delay3: Some(0),
            next_key4: Some(1),
            next_key1: Some(1),
            next_key3: Some(3),
            type_speed: Some(4),
            ..Default::default()
        };
        let cmds = build_slot_commands(3, &form, false).unwrap();
        assert!(cmds.iter().all(|c| matches!(
            c,
            Command::SetSlot { slot: 3, .. } | Command::SetSlotTypeSpeed { slot: 3, .. }
        )));
        assert_eq!(
            field_values(&cmds),
            vec![
                (FieldId::Label as u8, b"Work".to_vec()),
                (FieldId::Url as u8, b"https://ex.test".to_vec()),
                (FieldId::Username as u8, b"ada".to_vec()),
                (FieldId::Password as u8, b"secret".to_vec()),
                (FieldId::Delay1 as u8, b"2".to_vec()),
                (FieldId::Delay3 as u8, b"0".to_vec()),
                (FieldId::NextKey4 as u8, b"1".to_vec()),
                (FieldId::NextKey1 as u8, b"1".to_vec()),
                (FieldId::NextKey3 as u8, b"3".to_vec()),
                (FieldId::TypeSpeed as u8, vec![4]),
            ]
        );
    }

    /// Unchecked and empty text fields write nothing.
    #[test]
    fn empty_and_unchecked_write_nothing() {
        let form = SlotForm {
            label: Some(String::new()),
            password: Some((String::new(), "x".into())),
            totp: Some("  ".into()),
            yubikey: yubi(" ", "", ""),
            ..Default::default()
        };
        assert!(build_slot_commands(1, &form, false).unwrap().is_empty());
        assert!(
            build_slot_commands(1, &SlotForm::default(), false)
                .unwrap()
                .is_empty()
        );
    }

    /// Mismatched passwords and TOTP+Yubico are rejected.
    #[test]
    fn rejects_mismatch_and_mixed_mfa() {
        let form = SlotForm {
            password: Some(("a".into(), "b".into())),
            ..Default::default()
        };
        let err = build_slot_commands(1, &form, false).unwrap_err();
        assert!(err.to_string().contains("do not match"));

        let form = SlotForm {
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            yubikey: yubi("cc", "11", "22"),
            ..Default::default()
        };
        let err = build_slot_commands(1, &form, false).unwrap_err();
        assert!(err.to_string().contains("not both"));
    }

    /// Yubico needs all three fields.
    #[test]
    fn rejects_incomplete_yubikey() {
        let form = SlotForm {
            yubikey: yubi("cc", "", ""),
            ..Default::default()
        };
        let err = build_slot_commands(1, &form, false).unwrap_err();
        assert!(err.to_string().contains("cannot be blank"));
    }

    /// DUO-without-PIN rules apply only when asked.
    #[test]
    fn duo_no_pin_rules() {
        let mixed = SlotForm {
            password: Some(("x".into(), "x".into())),
            totp: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        };
        assert!(
            build_slot_commands(1, &mixed, true)
                .unwrap_err()
                .to_string()
                .contains("not both")
        );
        assert!(build_slot_commands(1, &mixed, false).is_ok());

        let user = SlotForm {
            username: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(
            build_slot_commands(1, &user, true).unwrap_err().to_string(),
            "Username and URL require a device PIN on OnlyKey Duo."
        );
        assert!(build_slot_commands(1, &user, false).is_ok());
    }

    /// Latin-1 text is one byte per char; anything above U+00FF is refused without echoing it.
    #[test]
    fn latin1_only() {
        let form = SlotForm {
            password: Some(("pässwörd".into(), "pässwörd".into())),
            ..Default::default()
        };
        assert_eq!(
            field_values(&build_slot_commands(1, &form, false).unwrap())[0].1,
            vec![0x70, 0xe4, 0x73, 0x73, 0x77, 0xf6, 0x72, 0x64]
        );
        for bad in ["pa€€word", "pass\u{1F511}", "Łódź", "secret€"] {
            let form = SlotForm {
                password: Some((bad.into(), bad.into())),
                ..Default::default()
            };
            let err = build_slot_commands(1, &form, false).unwrap_err();
            assert_eq!(err, SlotError::NotLatin1);
            assert!(!err.to_string().contains("secret"));
        }
    }

    /// Length and range limits.
    #[test]
    fn limits() {
        let long_label = SlotForm {
            label: Some("x".repeat(17)),
            ..Default::default()
        };
        assert_eq!(
            build_slot_commands(1, &long_label, false).unwrap_err(),
            SlotError::TooLong {
                field: "Label",
                max: 16
            }
        );
        let ok_url = SlotForm {
            url: Some("ü".repeat(56)),
            ..Default::default()
        };
        assert!(build_slot_commands(1, &ok_url, false).is_ok());
        for bad in [
            SlotForm {
                delay2: Some(10),
                ..Default::default()
            },
            SlotForm {
                next_key4: Some(2),
                ..Default::default()
            },
            SlotForm {
                type_speed: Some(0),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                build_slot_commands(1, &bad, false),
                Err(SlotError::OutOfRange(_))
            ));
        }
    }

    /// Wipe is OKWIPESLOT for the whole slot.
    #[test]
    fn wipe_whole_slot() {
        assert_eq!(
            wipe_slot_command(6),
            Command::WipeSlot {
                slot: 6,
                field: None
            }
        );
    }
}
