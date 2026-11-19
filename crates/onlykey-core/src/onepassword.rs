//! 1Password item JSON to slot write plan, limits, otpauth parsing, link tracking (pure).
//!
//! Models only the subset of `op item list --format json` and `op item get --reveal --format json`
//! that sync needs; unknown fields are ignored. Secret values deserialize straight into
//! [`Zeroizing`] buffers and the slot form built from them is zeroized on drop.

use crate::api::{Command, DeviceKind};
use crate::slot::{LABEL_MAX, SlotError, SlotForm, build_slot_commands};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Tag passed to `op item list --tags`; 1Password also returns items with nested `onlykey/...` tags.
pub const LIST_TAG: &str = "onlykey";
/// Custom field whose value overrides the item title as the slot label.
pub const LABEL_FIELD: &str = "onlykey label";
/// Highest slot number on a DUO (and in the tag).
pub const MAX_SLOT: u8 = 24;
/// Highest slot number on a Classic (shown as 1a–6b).
pub const CLASSIC_MAX_SLOT: u8 = 12;

/// Vault an item lives in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRef {
    /// Vault ID.
    pub id: String,
    /// Vault name.
    #[serde(default)]
    pub name: String,
}

/// One row of `op item list --format json` (no secrets).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ItemSummary {
    /// Item ID.
    pub id: String,
    /// Item title.
    #[serde(default)]
    pub title: String,
    /// Item version; bumps on every edit.
    #[serde(default)]
    pub version: u64,
    /// Vault.
    #[serde(default)]
    pub vault: VaultRef,
    /// Tags, nested ones as `parent/child`.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `op item get --reveal --format json` output. Holds secrets: no `Debug`.
#[derive(Default, Deserialize)]
pub struct ItemDetail {
    /// Item ID.
    pub id: String,
    /// Item title.
    #[serde(default)]
    pub title: String,
    /// Item version.
    #[serde(default)]
    pub version: u64,
    /// Vault.
    #[serde(default)]
    pub vault: VaultRef,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Fields in item order.
    #[serde(default)]
    pub fields: Vec<ItemField>,
    /// Website URLs.
    #[serde(default)]
    pub urls: Vec<ItemUrl>,
}

/// One item field. Holds secrets: no `Debug`.
#[derive(Default, Deserialize)]
pub struct ItemField {
    /// Field type, e.g. `STRING`, `CONCEALED`, `OTP`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// `USERNAME`, `PASSWORD`, `NOTES`, or absent.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Field label as shown in 1Password.
    #[serde(default)]
    pub label: Option<String>,
    /// Field value (revealed); non-string values are dropped.
    #[serde(default, deserialize_with = "secret_value")]
    pub value: Option<Zeroizing<String>>,
}

/// One website URL of an item.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ItemUrl {
    /// The item's main URL.
    #[serde(default)]
    pub primary: bool,
    /// The URL.
    #[serde(default)]
    pub href: String,
}

/// Reads a field value into a zeroizing buffer, mapping non-strings (and null) to `None`.
fn secret_value<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) => Some(Zeroizing::new(s)),
        _ => None,
    })
}

/// One account from `op account list --format json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpAccount {
    /// Sign-in address, e.g. `my.1password.com`.
    #[serde(default)]
    pub url: String,
    /// Account email.
    #[serde(default)]
    pub email: String,
    /// Account ID (accepted by `--account`).
    #[serde(default)]
    pub account_uuid: String,
}

/// What the UI learns about the `op` CLI without unlocking 1Password.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpStatus {
    /// `op` was found and ran.
    pub available: bool,
    /// `op --version` output.
    pub version: Option<String>,
    /// Accounts known to `op`.
    pub accounts: Vec<OpAccount>,
    /// Stored `--account` choice.
    pub account: Option<String>,
    /// Why `op` is not usable, for the user.
    pub error: Option<String>,
}

/// Stored record of the last successful write of a slot. No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// Item written.
    pub item_id: String,
    /// Its vault.
    pub vault_id: String,
    /// Item version written.
    pub version: u64,
}

/// Slot number → last write.
pub type Links = BTreeMap<u8, Link>;

/// Link state of a slot, shown as a badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    /// The device holds this item's current version.
    Synced,
    /// The item changed in 1Password since the last write.
    OutOfDate,
    /// This item was never written to the slot.
    NeverSynced,
    /// More than one item has this slot's tag; sync skips the slot.
    Duplicate,
}

/// One tagged item and its slot, for the Slots page (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedSlot {
    /// Slot number 1–24.
    pub slot: u8,
    /// Item ID.
    pub item_id: String,
    /// Item title.
    pub title: String,
    /// Vault name.
    pub vault: String,
    /// Item version in 1Password.
    pub version: u64,
    /// Link state.
    pub status: LinkStatus,
}

/// Outcome of syncing one slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSyncResult {
    /// Slot number.
    pub slot: u8,
    /// Written.
    pub ok: bool,
    /// What happened, for the user (never a secret).
    pub message: String,
}

/// A Login item for the editor's picker (titles only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpLogin {
    /// Item ID.
    pub id: String,
    /// Item title.
    pub title: String,
    /// Vault name.
    pub vault: String,
}

/// Slot editor values mapped from one item ("Fill from 1Password"). Holds secrets: no `Debug`,
/// zeroized on drop (take fields with `Option::take`).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemFill {
    /// Label: the `onlykey label` field, else the title.
    pub label: Option<String>,
    /// First URL (primary first).
    pub url: Option<String>,
    /// USERNAME field.
    pub username: Option<String>,
    /// PASSWORD field.
    pub password: Option<String>,
    /// Base32 TOTP secret from the first OTP field.
    pub totp: Option<String>,
}

impl Drop for ItemFill {
    /// Wipes every value.
    fn drop(&mut self) {
        for v in [
            &mut self.label,
            &mut self.url,
            &mut self.username,
            &mut self.password,
            &mut self.totp,
        ] {
            v.zeroize();
        }
    }
}

/// Why one slot cannot be synced; `Display` is the user-facing reason (never a value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// The item has no `onlykey/slot-N` tag.
    NoSlotTag,
    /// No item carries this slot's tag.
    NotLinked(u8),
    /// The slot does not exist on this device.
    SlotOutOfRange {
        /// Tagged slot.
        slot: u8,
        /// Highest slot on the device.
        max: u8,
    },
    /// Several items carry the same slot tag.
    Duplicate {
        /// Slot.
        slot: u8,
        /// How many items.
        count: usize,
    },
    /// The one-time password cannot go on an OnlyKey.
    Otp(&'static str),
    /// The slot builder rejected the values (limits, Latin-1, DUO without PIN).
    Slot(SlotError),
}

impl fmt::Display for SyncError {
    /// Plain wording; slot builder errors keep the original app's text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSlotTag => f.write_str("The item has no onlykey/slot-N tag."),
            Self::NotLinked(slot) => {
                write!(f, "No 1Password item is tagged onlykey/slot-{slot}.")
            }
            Self::SlotOutOfRange { slot, max } => {
                write!(
                    f,
                    "This OnlyKey has slots 1–{max}; slot {slot} does not exist."
                )
            }
            Self::Duplicate { slot, count } => write!(
                f,
                "{count} items are tagged onlykey/slot-{slot}; keep the tag on one item. Nothing was written."
            ),
            Self::Otp(why) => f.write_str(why),
            Self::Slot(e @ SlotError::TooLong { field: "Label", .. }) => write!(
                f,
                "{e} Add a custom field named \"{LABEL_FIELD}\" in 1Password with a label of up to {LABEL_MAX} characters."
            ),
            Self::Slot(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<SlotError> for SyncError {
    /// Wraps a slot builder error.
    fn from(e: SlotError) -> Self {
        Self::Slot(e)
    }
}

/// Slot number from one tag: `onlykey/slot-N` or the nested `onlykey/slot/N` (any case), N = 1–24.
pub fn parse_slot_tag(tag: &str) -> Option<u8> {
    let tag = tag.trim().to_ascii_lowercase();
    let rest = tag.strip_prefix("onlykey/slot")?;
    let digits = rest.strip_prefix('-').or_else(|| rest.strip_prefix('/'))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|n| (1..=MAX_SLOT).contains(n))
}

/// The first slot tag among `tags`.
pub fn slot_from_tags(tags: &[String]) -> Option<u8> {
    tags.iter().find_map(|t| parse_slot_tag(t))
}

/// Highest slot number on `kind`.
pub fn max_slot(kind: DeviceKind) -> u8 {
    if kind == DeviceKind::Classic {
        CLASSIC_MAX_SLOT
    } else {
        MAX_SLOT
    }
}

/// Tagged items grouped by slot (items without a valid slot tag are left out).
pub fn group_by_slot(items: &[ItemSummary]) -> BTreeMap<u8, Vec<&ItemSummary>> {
    let mut out: BTreeMap<u8, Vec<&ItemSummary>> = BTreeMap::new();
    for item in items {
        if let Some(slot) = slot_from_tags(&item.tags) {
            out.entry(slot).or_default().push(item);
        }
    }
    out
}

/// Link state of `item` given the stored write for its slot.
pub fn link_status(item: &ItemSummary, stored: Option<&Link>) -> LinkStatus {
    match stored {
        Some(l) if l.item_id == item.id && item.version > l.version => LinkStatus::OutOfDate,
        Some(l) if l.item_id == item.id => LinkStatus::Synced,
        _ => LinkStatus::NeverSynced,
    }
}

/// One row per tagged item, by slot; every item of a duplicated slot is marked `Duplicate`.
pub fn linked_slots(items: &[ItemSummary], links: &Links) -> Vec<LinkedSlot> {
    group_by_slot(items)
        .into_iter()
        .flat_map(|(slot, group)| {
            let dup = group.len() > 1;
            group.into_iter().map(move |item| LinkedSlot {
                slot,
                item_id: item.id.clone(),
                title: item.title.clone(),
                vault: item.vault.name.clone(),
                version: item.version,
                status: if dup {
                    LinkStatus::Duplicate
                } else {
                    link_status(item, links.get(&slot))
                },
            })
        })
        .collect()
}

/// The item to write for each slot: all linked slots, or just `wanted`. Duplicate tags and
/// wanted slots without an item are errors for that slot.
pub fn sync_targets<'a>(
    items: &'a [ItemSummary],
    wanted: Option<&[u8]>,
) -> Vec<(u8, Result<&'a ItemSummary, SyncError>)> {
    let groups = group_by_slot(items);
    let slots: Vec<u8> = match wanted {
        Some(w) => {
            let mut w = w.to_vec();
            w.sort_unstable();
            w.dedup();
            w
        }
        None => groups.keys().copied().collect(),
    };
    slots
        .into_iter()
        .map(|slot| {
            let target = match groups.get(&slot).map(Vec::as_slice) {
                None | Some([]) => Err(SyncError::NotLinked(slot)),
                Some([item]) => Ok(*item),
                Some(group) => Err(SyncError::Duplicate {
                    slot,
                    count: group.len(),
                }),
            };
            (slot, target)
        })
        .collect()
}

/// Decodes `%XX` escapes (bad escapes are kept as typed).
fn percent_decode(s: &str) -> Zeroizing<String> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

/// Base32 secret from an OTP field value: an `otpauth://totp/...?secret=...` URI, or a bare secret.
///
/// Rejects HOTP and non-default algorithm/digits/period: OnlyKey TOTP is SHA-1, 6 digits, 30 s.
pub fn totp_secret(value: &str) -> Result<Zeroizing<String>, SyncError> {
    let value = value.trim();
    let Some(rest) = value
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
        .map(|_| &value[10..])
    else {
        return Ok(Zeroizing::new(value.to_string()));
    };
    let (kind, query) = rest.split_once('?').unwrap_or((rest, ""));
    let kind = kind.split('/').next().unwrap_or_default();
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(SyncError::Otp(
            "Only time-based one-time passwords (TOTP) can be stored on an OnlyKey.",
        ));
    }
    let mut secret = None;
    for pair in query.split('&') {
        let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(percent_decode(val)),
            "algorithm" if !val.eq_ignore_ascii_case("SHA1") => {
                return Err(SyncError::Otp(
                    "OnlyKey TOTP uses SHA-1; this one-time password uses another algorithm.",
                ));
            }
            "digits" if val != "6" => {
                return Err(SyncError::Otp(
                    "OnlyKey TOTP codes have 6 digits; this one-time password uses another length.",
                ));
            }
            "period" if val != "30" => {
                return Err(SyncError::Otp(
                    "OnlyKey TOTP codes change every 30 seconds; this one-time password uses another period.",
                ));
            }
            _ => {}
        }
    }
    secret
        .filter(|s| !s.trim().is_empty())
        .ok_or(SyncError::Otp("The one-time password link has no secret."))
}

/// Non-empty value of the first field matching `pred`.
fn field_value(item: &ItemDetail, pred: impl Fn(&ItemField) -> bool) -> Option<String> {
    item.fields
        .iter()
        .filter(|f| pred(f))
        .find_map(|f| f.value.as_deref().filter(|v| !v.is_empty()).cloned())
}

/// Editor values for `item` per SPEC field mapping (label field or title, USERNAME, PASSWORD,
/// first URL with the primary one first, first OTP field's secret).
pub fn fill_for_item(item: &ItemDetail) -> Result<ItemFill, SyncError> {
    let purpose = |p: &'static str| {
        move |f: &ItemField| {
            f.purpose
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(p))
        }
    };
    let label = field_value(item, |f| {
        f.label
            .as_deref()
            .is_some_and(|l| l.trim().eq_ignore_ascii_case(LABEL_FIELD))
    })
    .or_else(|| Some(item.title.clone()).filter(|t| !t.is_empty()));
    let url = item
        .urls
        .iter()
        .filter(|u| u.primary)
        .chain(&item.urls)
        .map(|u| u.href.trim())
        .find(|h| !h.is_empty())
        .map(String::from);
    let totp = match item
        .fields
        .iter()
        .filter(|f| f.kind.eq_ignore_ascii_case("OTP"))
        .find_map(|f| f.value.as_deref().filter(|v| !v.trim().is_empty()))
    {
        Some(v) => Some(totp_secret(v)?.to_string()),
        None => None,
    };
    Ok(ItemFill {
        label,
        url,
        username: field_value(item, purpose("USERNAME")),
        password: field_value(item, purpose("PASSWORD")),
        totp,
    })
}

/// The slot and the ordered `SetSlot` writes for `item` on a device of `kind`.
///
/// Writes only label, URL, username, password and TOTP (delays and keys stay as set on the
/// device); every limit and the DUO-without-PIN rules are checked before anything is returned.
pub fn plan_for_item(
    item: &ItemDetail,
    kind: DeviceKind,
    pin_set: bool,
) -> Result<(u8, Vec<Command>), SyncError> {
    let slot = slot_from_tags(&item.tags).ok_or(SyncError::NoSlotTag)?;
    let max = max_slot(kind);
    if slot > max {
        return Err(SyncError::SlotOutOfRange { slot, max });
    }
    let mut fill = fill_for_item(item)?;
    let form = Zeroizing::new(SlotForm {
        label: fill.label.take(),
        url: fill.url.take(),
        username: fill.username.take(),
        password: fill.password.take().map(|p| (p.clone(), p)),
        totp: fill.totp.take(),
        ..SlotForm::default()
    });
    let duo_no_pin = kind == DeviceKind::Duo && !pin_set;
    Ok((slot, build_slot_commands(slot, &form, duo_no_pin)?))
}

#[cfg(test)]
mod tests {
    //! Canned `op` JSON with made-up data only.

    use super::*;
    use crate::protocol::FieldId;

    /// `op item list --tags onlykey --format json`, hand-written.
    const LIST: &str = r#"[
      {"id":"aaaa1111","title":"Example Mail","version":4,
       "vault":{"id":"v1","name":"Private"},"category":"LOGIN",
       "tags":["onlykey/slot-1","mail"],"updated_at":"2026-01-01T00:00:00Z"},
      {"id":"bbbb2222","title":"Example Bank","version":2,
       "vault":{"id":"v1","name":"Private"},"tags":["OnlyKey/Slot/3"]},
      {"id":"cccc3333","title":"Dup One","version":1,
       "vault":{"id":"v2","name":"Shared"},"tags":["onlykey/slot-5"]},
      {"id":"dddd4444","title":"Dup Two","version":1,
       "vault":{"id":"v2","name":"Shared"},"tags":["onlykey/slot-5"]},
      {"id":"eeee5555","title":"Just tagged","version":1,
       "vault":{"id":"v1","name":"Private"},"tags":["onlykey"]}
    ]"#;

    /// `op item get --reveal --format json` for a full login, hand-written.
    const ITEM: &str = r#"{
      "id":"aaaa1111","title":"Example Mail","version":4,
      "vault":{"id":"v1","name":"Private"},"category":"LOGIN",
      "tags":["onlykey/slot-1"],
      "fields":[
        {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"user@example.com"},
        {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"hunter2-fake"},
        {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain"},
        {"id":"x1","type":"STRING","label":"OnlyKey Label","value":"Mail"},
        {"id":"x2","type":"DATE","label":"expires","value":1700000000},
        {"id":"x3","type":"OTP","label":"one-time password",
         "value":"otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30&digits=6&algorithm=SHA1",
         "totp":"123456"}
      ],
      "urls":[{"label":"website","href":"https://other.example.org"},
              {"label":"website","primary":true,"href":"https://mail.example.com/login"}]
    }"#;

    /// Parses an item, panicking on bad fixture JSON.
    fn item(json: &str) -> ItemDetail {
        serde_json::from_str(json).expect("fixture parses")
    }

    /// `(field id, value)` of each `SetSlot`.
    fn writes(cmds: &[Command]) -> Vec<(u8, Vec<u8>)> {
        cmds.iter()
            .map(|c| match c {
                Command::SetSlot { field, value, .. } => (*field, value.clone()),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    /// Both tag spellings parse; anything else does not.
    #[test]
    fn slot_tags() {
        assert_eq!(parse_slot_tag("onlykey/slot-1"), Some(1));
        assert_eq!(parse_slot_tag(" OnlyKey/Slot-24 "), Some(24));
        assert_eq!(parse_slot_tag("onlykey/slot/7"), Some(7));
        for bad in [
            "onlykey",
            "onlykey/slot-0",
            "onlykey/slot-25",
            "onlykey/slot-",
            "onlykey/slot-+3",
            "onlykey/slot3",
            "slot-3",
            "onlykey/slot-3a",
            "work/onlykey/slot-3",
        ] {
            assert_eq!(parse_slot_tag(bad), None, "{bad}");
        }
        let tags = vec![
            "mail".to_string(),
            "onlykey/slot-9".into(),
            "onlykey/slot-2".into(),
        ];
        assert_eq!(slot_from_tags(&tags), Some(9));
    }

    /// Full mapping: label field beats title, primary URL first, otpauth secret, write order.
    #[test]
    fn plan_full_login() {
        let (slot, cmds) = plan_for_item(&item(ITEM), DeviceKind::Duo, true).expect("plan");
        assert_eq!(slot, 1);
        assert!(
            cmds.iter()
                .all(|c| matches!(c, Command::SetSlot { slot: 1, .. }))
        );
        let w = writes(&cmds);
        assert_eq!(
            w.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
            [
                FieldId::Label as u8,
                FieldId::Url as u8,
                FieldId::Username as u8,
                FieldId::Password as u8,
                FieldId::TfaType as u8,
                FieldId::TfaUsername as u8,
            ]
        );
        assert_eq!(w[0].1, b"Mail");
        assert_eq!(w[1].1, b"https://mail.example.com/login");
        assert_eq!(w[2].1, b"user@example.com");
        assert_eq!(w[3].1, b"hunter2-fake");
        assert_eq!(
            w[5].1,
            crate::encoding::base32_to_bytes("JBSWY3DPEHPK3PXP").unwrap()
        );
    }

    /// Without a label field the title is the label; missing fields are not written.
    #[test]
    fn plan_minimal_item() {
        let json = r#"{"id":"z","title":"Pw Only","version":1,"tags":["onlykey/slot-2"],
            "fields":[{"type":"CONCEALED","purpose":"PASSWORD","value":"pw"}]}"#;
        let (slot, cmds) = plan_for_item(&item(json), DeviceKind::Classic, true).unwrap();
        assert_eq!(slot, 2);
        assert_eq!(
            writes(&cmds),
            [
                (FieldId::Label as u8, b"Pw Only".to_vec()),
                (FieldId::Password as u8, b"pw".to_vec()),
            ]
        );
    }

    /// Limits, Latin-1, slot range, DUO-without-PIN and OTP checks skip the item with a reason.
    #[test]
    fn plan_rejections() {
        let with = |tags: &str, fields: &str, title: &str| {
            item(&format!(
                r#"{{"id":"z","title":"{title}","tags":[{tags}],"fields":[{fields}]}}"#
            ))
        };
        let slot1 = r#""onlykey/slot-1""#;
        let user = r#"{"type":"STRING","purpose":"USERNAME","value":"me"}"#;
        let pw = r#"{"type":"CONCEALED","purpose":"PASSWORD","value":"pw"}"#;
        let otp = |v: &str| format!(r#"{{"type":"OTP","value":"{v}"}}"#);
        let plan = |i: &ItemDetail, kind, pin| plan_for_item(i, kind, pin).map(|_| ()).unwrap_err();

        assert_eq!(
            plan(&with("", pw, "T"), DeviceKind::Duo, true),
            SyncError::NoSlotTag
        );
        assert_eq!(
            plan(
                &with(r#""onlykey/slot-13""#, pw, "T"),
                DeviceKind::Classic,
                true
            ),
            SyncError::SlotOutOfRange { slot: 13, max: 12 }
        );
        let long = plan(
            &with(slot1, pw, "A title longer than sixteen"),
            DeviceKind::Duo,
            true,
        );
        assert!(long.to_string().contains("onlykey label"), "{long}");
        assert_eq!(
            plan(
                &with(
                    slot1,
                    r#"{"type":"CONCEALED","purpose":"PASSWORD","value":"pässwörd€"}"#,
                    "T"
                ),
                DeviceKind::Duo,
                true
            ),
            SyncError::Slot(SlotError::NotLatin1)
        );
        assert_eq!(
            plan(
                &with(slot1, &format!("{pw},{}", otp("JBSWY3DPEHPK3PXP")), "T"),
                DeviceKind::Duo,
                false
            ),
            SyncError::Slot(SlotError::DuoNoPinMixed)
        );
        assert_eq!(
            plan(
                &with(slot1, &format!("{user},{pw}"), "T"),
                DeviceKind::Duo,
                false
            ),
            SyncError::Slot(SlotError::DuoNoPinUsernameUrl)
        );
        // DUO without PIN: a password-only item is fine.
        assert!(plan_for_item(&with(slot1, pw, "T"), DeviceKind::Duo, false).is_ok());
        assert!(matches!(
            plan(
                &with(slot1, &otp("otpauth://hotp/x?secret=AAAA&counter=1"), "T"),
                DeviceKind::Duo,
                true
            ),
            SyncError::Otp(_)
        ));
        let long_secret = "A".repeat(100);
        assert_eq!(
            plan(&with(slot1, &otp(&long_secret), "T"), DeviceKind::Duo, true),
            SyncError::Slot(SlotError::TotpTooLong(62))
        );
    }

    /// otpauth parsing: bare secrets, escapes, and unsupported parameters.
    #[test]
    fn otpauth() {
        assert_eq!(*totp_secret(" JBSW Y3DP ").unwrap(), "JBSW Y3DP");
        assert_eq!(
            *totp_secret("OTPAUTH://TOTP/a%20b?issuer=x&secret=MZXW6%3D%3D%3D").unwrap(),
            "MZXW6==="
        );
        assert_eq!(
            *totp_secret("otpauth://totp/x?secret=ab%2").unwrap(),
            "ab%2"
        );
        for bad in [
            "otpauth://totp/x?issuer=y",
            "otpauth://totp/x?secret=AAAA&algorithm=SHA256",
            "otpauth://totp/x?secret=AAAA&digits=8",
            "otpauth://totp/x?secret=AAAA&period=60",
            "otpauth://hotp/x?secret=AAAA",
        ] {
            assert!(totp_secret(bad).is_err(), "{bad}");
        }
    }

    /// The editor fill uses the same mapping and carries the base32 secret.
    #[test]
    fn fill() {
        let mut f = fill_for_item(&item(ITEM)).unwrap();
        assert_eq!(f.label.take().as_deref(), Some("Mail"));
        assert_eq!(f.url.as_deref(), Some("https://mail.example.com/login"));
        assert_eq!(f.username.as_deref(), Some("user@example.com"));
        assert_eq!(f.password.as_deref(), Some("hunter2-fake"));
        assert_eq!(f.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        let json = serde_json::to_string(&f).unwrap();
        let back: ItemFill = serde_json::from_str(&json).unwrap();
        assert!(back == f);
    }

    /// Statuses from stored links: synced, out of date, never synced, duplicate.
    #[test]
    fn linked_statuses() {
        let items: Vec<ItemSummary> = serde_json::from_str(LIST).unwrap();
        let mut links = Links::new();
        let link = |id: &str, version| Link {
            item_id: id.into(),
            vault_id: "v1".into(),
            version,
        };
        links.insert(1, link("aaaa1111", 3));
        links.insert(3, link("bbbb2222", 2));
        let rows = linked_slots(&items, &links);
        let got: Vec<(u8, &str, LinkStatus)> = rows
            .iter()
            .map(|r| (r.slot, r.item_id.as_str(), r.status))
            .collect();
        assert_eq!(
            got,
            [
                (1, "aaaa1111", LinkStatus::OutOfDate),
                (3, "bbbb2222", LinkStatus::Synced),
                (5, "cccc3333", LinkStatus::Duplicate),
                (5, "dddd4444", LinkStatus::Duplicate),
            ]
        );
        assert_eq!(rows[0].vault, "Private");
        // Another item now holds the tag: never synced.
        links.insert(3, link("other", 9));
        assert_eq!(
            linked_slots(&items, &links)[1].status,
            LinkStatus::NeverSynced
        );
        let json = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(json["status"], "out_of_date");
    }

    /// Targets: all linked slots, or the wanted ones; duplicates and missing slots are errors.
    #[test]
    fn targets() {
        let items: Vec<ItemSummary> = serde_json::from_str(LIST).unwrap();
        let all = sync_targets(&items, None);
        assert_eq!(all.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [1, 3, 5]);
        assert_eq!(all[0].1.as_ref().unwrap().id, "aaaa1111");
        assert_eq!(all[2].1, Err(SyncError::Duplicate { slot: 5, count: 2 }));
        let some = sync_targets(&items, Some(&[3, 2, 3]));
        assert_eq!(some.len(), 2);
        assert_eq!(some[0].1, Err(SyncError::NotLinked(2)));
        assert_eq!(some[1].1.as_ref().unwrap().id, "bbbb2222");
    }

    /// Stored links round-trip with numeric slot keys.
    #[test]
    fn links_json() {
        let mut links = Links::new();
        links.insert(
            12,
            Link {
                item_id: "i".into(),
                vault_id: "v".into(),
                version: 7,
            },
        );
        let json = serde_json::to_string(&links).unwrap();
        assert_eq!(json, r#"{"12":{"item_id":"i","vault_id":"v","version":7}}"#);
        assert_eq!(serde_json::from_str::<Links>(&json).unwrap(), links);
    }
}
