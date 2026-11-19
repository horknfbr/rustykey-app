//! Serde types shared by the engine, src-tauri and the UI.
//!
//! Enums with data use `{"type": "<snake_case variant>", ...fields}` so JSON over Tauri invoke is stable.

use crate::protocol::{CONFIG_MODE_FOR_OPERATION, CONFIG_MODE_REQUIRED, MessageId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Hardware kind shown to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// Not identified yet.
    #[default]
    Unknown,
    /// Full-size OnlyKey.
    Classic,
    /// OnlyKey DUO.
    Duo,
}

/// Connection/lock state shown to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// No device.
    #[default]
    Disconnected,
    /// In the bootloader.
    Bootloader,
    /// First-use / wiped.
    Uninitialized,
    /// Locked.
    Locked,
    /// Unlocked.
    Unlocked,
    /// Config mode (flashing red LED).
    ConfigMode,
}

/// Full device state, sent on every change.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// Connection/lock state.
    pub state: DeviceState,
    /// Hardware kind.
    pub kind: DeviceKind,
    /// Firmware version text, if known.
    pub firmware: Option<String>,
    /// False only for a DUO without a device PIN.
    pub pin_set: bool,
    /// "OnlyKey" or "OnlyKey Duo".
    pub product_name: String,
    /// Slot labels 1–24 at index 0–23; all `None` while locked.
    pub labels: [Option<String>; 24],
    /// Bumps on unplug and on unlocked → locked.
    pub session_epoch: u64,
    /// Connect failure text (drives the udev / permission dialog).
    pub connect_error: Option<String>,
    /// True while the device reports locked, including a config-mode lock (`state` stays
    /// `ConfigMode` through it); false when disconnected.
    #[serde(default)]
    pub locked: bool,
}

/// Something the engine tells the UI without being asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "sent rarely; boxing would change the SPEC shape"
)]
pub enum Event {
    /// New device state.
    Snapshot(Snapshot),
    /// A device or app message (`messageReceived`).
    Message {
        /// Message text.
        text: String,
    },
    /// Progress of a long operation (restore, firmware).
    Progress {
        /// 0–100.
        percent: u8,
        /// What is running.
        text: String,
    },
    /// A device error (TS `error` event): "Error …" text from firmware, or a refused DUO PIN.
    Error {
        /// Error text.
        text: String,
    },
}

/// Which Classic keypad PIN a PIN command targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinKind {
    /// Primary PIN (OKSETPIN).
    Primary,
    /// Second-profile PIN (OKSETPIN2).
    Second,
    /// Self-destruct PIN (OKSETSDPIN).
    SelfDestruct,
}

impl PinKind {
    /// The message ID that starts this PIN's keypad entry.
    pub fn message_id(self) -> MessageId {
        match self {
            Self::Primary => MessageId::OkSetPin,
            Self::Second => MessageId::OkSetPin2,
            Self::SelfDestruct => MessageId::OkSetSdPin,
        }
    }
}

/// Classic keypad PIN step: wait for the prompt, or for the commit confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinPhase {
    /// Wait for "enter your … PIN" / "re-enter".
    Prompt,
    /// Wait for "successful pin" / "successfully set pin".
    Commit,
}

/// DUO PINs typed in the app (digits 1–6). Unlock uses only `primary`.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DuoPins {
    /// Device PIN.
    pub primary: String,
    /// Second-profile PIN (setup only).
    pub second: Option<String>,
    /// Self-destruct PIN (setup only; must differ from `primary`).
    pub self_destruct: Option<String>,
}

impl fmt::Debug for DuoPins {
    /// Redacted: PINs are secrets and must never reach logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DuoPins { .. }")
    }
}

/// One request to the device; one variant per PARITY §2 method.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    /// Set the device clock (two OKSETTIME).
    SetTime,
    /// Probe lock status (one OKSETTIME).
    RefreshStatus,
    /// Read all slot labels.
    GetLabels,
    /// Write one slot field (any reply resolves).
    SetSlot {
        /// Slot 1–24.
        slot: u8,
        /// Field ID.
        field: u8,
        /// Field bytes (Latin-1 for text).
        value: Vec<u8>,
    },
    /// Wipe a slot, or one field of it.
    WipeSlot {
        /// Slot 1–24.
        slot: u8,
        /// Field ID, or the whole slot.
        field: Option<u8>,
    },
    /// Per-slot type speed (slot/13, waits "typespeed").
    SetSlotTypeSpeed {
        /// Slot 1–24.
        slot: u8,
        /// Speed 1–10.
        speed: u8,
    },
    /// Classic keypad PIN step (300 s).
    ClassicPin {
        /// Which PIN.
        which: PinKind,
        /// Which step.
        phase: PinPhase,
    },
    /// Abort a Classic PIN wait and flush the keypad state machine.
    CancelClassicPin {
        /// Which PIN.
        which: PinKind,
    },
    /// DUO PIN setup (`setup` true) or unlock.
    DuoPin {
        /// The PINs.
        pins: DuoPins,
        /// Setup payload vs unlock payload.
        setup: bool,
    },
    /// Write a private key (chunked OKSETPRIV).
    SetPrivateKey {
        /// Key slot.
        slot: u8,
        /// Type byte incl. modifiers.
        key_type: u8,
        /// Key bytes.
        bytes: Vec<u8>,
    },
    /// Wipe a private key.
    WipePrivateKey {
        /// Key slot.
        slot: u8,
    },
    /// Global setting `OKSETSLOT XX/field [value]`; covers every preference setter and backup key mode (20).
    SetGlobal {
        /// Global field ID.
        field: u8,
        /// Value byte.
        value: u8,
    },
    /// Legacy Yubikey OTP auth (XX/10).
    SetYubiAuth {
        /// Public ID, modhex.
        public_id: String,
        /// Private ID, hex.
        private_id: String,
        /// Secret AES key, hex.
        secret_key: String,
    },
    /// Wipe legacy Yubikey auth.
    WipeYubiAuth,
    /// Restore a backup (chunked OKRESTORE).
    Restore {
        /// Decoded backup bytes.
        payload: Vec<u8>,
    },
    /// Reboot into the bootloader.
    TriggerBootloader,
    /// Stream firmware blocks (bootloader only).
    LoadFirmware {
        /// Hex-decoded blocks, one per file line.
        blocks: Vec<Vec<u8>>,
    },
}

impl fmt::Debug for Command {
    /// Variant name only: payloads may hold PINs, keys, secrets or backup bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SetTime => "SetTime",
            Self::RefreshStatus => "RefreshStatus",
            Self::GetLabels => "GetLabels",
            Self::SetSlot { .. } => "SetSlot",
            Self::WipeSlot { .. } => "WipeSlot",
            Self::SetSlotTypeSpeed { .. } => "SetSlotTypeSpeed",
            Self::ClassicPin { .. } => "ClassicPin",
            Self::CancelClassicPin { .. } => "CancelClassicPin",
            Self::DuoPin { .. } => "DuoPin",
            Self::SetPrivateKey { .. } => "SetPrivateKey",
            Self::WipePrivateKey { .. } => "WipePrivateKey",
            Self::SetGlobal { .. } => "SetGlobal",
            Self::SetYubiAuth { .. } => "SetYubiAuth",
            Self::WipeYubiAuth => "WipeYubiAuth",
            Self::Restore { .. } => "Restore",
            Self::TriggerBootloader => "TriggerBootloader",
            Self::LoadFirmware { .. } => "LoadFirmware",
        };
        write!(f, "Command::{name}")
    }
}

/// Successful result of a [`Command`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "sent rarely; boxing would change the SPEC shape"
)]
pub enum Reply {
    /// Finished; nothing to return.
    Done,
    /// `LoadFirmware` outside the bootloader: the reboot was triggered and the blocks are held;
    /// they stream when the device reconnects as bootloader (TS `pending-reboot`).
    FirmwarePending,
    /// Labels read by `GetLabels` (slot n at index n-1).
    Labels {
        /// Slot labels.
        labels: [Option<String>; 24],
    },
}

/// A failed command; `Display` is the original app's wording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceError {
    /// Firmware said "not in config mode".
    ConfigModeForOperation,
    /// "device locked" while the app thinks it is unlocked (fw 3.0.4 OKWIPEPRIV).
    ConfigModeRequired,
    /// "device locked" while locked.
    Locked,
    /// No reply in time.
    Timeout {
        /// TS message name, e.g. `OKSETTIME`.
        request: String,
        /// Timeout in ms.
        ms: u64,
    },
    /// Unplugged, or not connected.
    Disconnected,
    /// DUO unlock refused.
    IncorrectPin,
    /// DUO unlock attempts exceeded for the session.
    AttemptsExceeded,
    /// A Classic PIN wait was cancelled.
    PinEntryCancelled,
    /// App-side validation failed (message says what).
    InvalidInput {
        /// Message.
        message: String,
    },
    /// Any other device error text, verbatim.
    Device {
        /// Device text.
        message: String,
    },
}

impl DeviceError {
    /// Remaps device error text like `formatDeviceLockedError` (`OnlyKeyDevice.ts:244-257`).
    pub fn from_device_text(message: &str, is_locked: bool) -> Self {
        let lower = message.to_lowercase();
        if lower.contains("not in config mode") {
            Self::ConfigModeForOperation
        } else if lower.contains("device locked") {
            if is_locked {
                Self::Locked
            } else {
                Self::ConfigModeRequired
            }
        } else {
            Self::Device {
                message: message.to_string(),
            }
        }
    }

    /// Timeout error for a request.
    pub fn timeout(msg: MessageId, ms: u64) -> Self {
        Self::Timeout {
            request: msg.name().to_string(),
            ms,
        }
    }
}

impl fmt::Display for DeviceError {
    /// Writes the original error text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigModeForOperation => f.write_str(CONFIG_MODE_FOR_OPERATION),
            Self::ConfigModeRequired => f.write_str(CONFIG_MODE_REQUIRED),
            Self::Locked => f.write_str("OnlyKey is locked. Unlock your device and try again."),
            Self::Timeout { request, ms } => write!(f, "Request {request} timed out after {ms}ms"),
            Self::Disconnected => f.write_str("Device disconnected"),
            Self::IncorrectPin => f.write_str("Incorrect PIN"),
            Self::AttemptsExceeded => {
                f.write_str("Error password attempts for this session exceeded")
            }
            Self::PinEntryCancelled => f.write_str("PIN entry cancelled"),
            Self::InvalidInput { message } | Self::Device { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for DeviceError {}

#[cfg(test)]
mod tests {
    //! Wire format and error wording.

    use super::*;
    use serde_json::json;

    /// Commands serialise as `{"type": snake_case, ...fields}` and round-trip.
    #[test]
    fn command_json_is_tagged_snake_case() {
        let cmd = Command::SetGlobal {
            field: 11,
            value: 30,
        };
        assert_eq!(
            serde_json::to_value(&cmd).unwrap(),
            json!({"type": "set_global", "field": 11, "value": 30})
        );
        assert_eq!(
            serde_json::to_value(Command::SetTime).unwrap(),
            json!({"type": "set_time"})
        );
        let pin = Command::ClassicPin {
            which: PinKind::SelfDestruct,
            phase: PinPhase::Commit,
        };
        assert_eq!(
            serde_json::to_value(&pin).unwrap(),
            json!({"type": "classic_pin", "which": "self_destruct", "phase": "commit"})
        );
        let back: Command =
            serde_json::from_value(json!({"type": "wipe_slot", "slot": 3, "field": null})).unwrap();
        assert_eq!(
            back,
            Command::WipeSlot {
                slot: 3,
                field: None
            }
        );
    }

    /// Events and replies use the same tagging; snapshots carry 24 labels.
    #[test]
    fn event_and_reply_json() {
        let ev = Event::Message { text: "hi".into() };
        assert_eq!(
            serde_json::to_value(&ev).unwrap(),
            json!({"type": "message", "text": "hi"})
        );
        let snap = Snapshot {
            state: DeviceState::ConfigMode,
            kind: DeviceKind::Duo,
            ..Default::default()
        };
        let v = serde_json::to_value(Event::Snapshot(snap.clone())).unwrap();
        assert_eq!(v["type"], "snapshot");
        assert_eq!(v["state"], "config_mode");
        assert_eq!(v["kind"], "duo");
        assert_eq!(v["labels"].as_array().unwrap().len(), 24);
        assert_eq!(
            serde_json::from_value::<Event>(v).unwrap(),
            Event::Snapshot(snap)
        );
        assert_eq!(
            serde_json::to_value(Reply::Done).unwrap(),
            json!({"type": "done"})
        );
    }

    /// Error remap follows `formatDeviceLockedError`.
    #[test]
    fn format_device_locked_error_remaps() {
        assert_eq!(
            DeviceError::from_device_text("Error not in config mode", false),
            DeviceError::ConfigModeForOperation
        );
        assert_eq!(
            DeviceError::from_device_text("Error device locked", false),
            DeviceError::ConfigModeRequired
        );
        assert_eq!(
            DeviceError::from_device_text("Error Device Locked", true),
            DeviceError::Locked
        );
        assert_eq!(
            DeviceError::from_device_text("Error xyz", true).to_string(),
            "Error xyz"
        );
        assert_eq!(
            DeviceError::Locked.to_string(),
            "OnlyKey is locked. Unlock your device and try again."
        );
        assert!(
            DeviceError::ConfigModeRequired
                .to_string()
                .contains("flashing red LED")
        );
    }

    /// Fixed error texts match the original.
    #[test]
    fn error_wording() {
        assert_eq!(
            DeviceError::timeout(MessageId::OkSetTime, 2500).to_string(),
            "Request OKSETTIME timed out after 2500ms"
        );
        assert_eq!(DeviceError::Disconnected.to_string(), "Device disconnected");
        assert_eq!(DeviceError::IncorrectPin.to_string(), "Incorrect PIN");
        assert_eq!(
            DeviceError::AttemptsExceeded.to_string(),
            "Error password attempts for this session exceeded"
        );
        assert_eq!(
            DeviceError::PinEntryCancelled.to_string(),
            "PIN entry cancelled"
        );
    }

    /// Debug output never shows secrets.
    #[test]
    fn debug_redacts_secrets() {
        let pins = DuoPins {
            primary: "1234567".into(),
            ..Default::default()
        };
        let cmd = Command::DuoPin {
            pins: pins.clone(),
            setup: false,
        };
        assert!(!format!("{cmd:?}").contains("1234567"));
        assert!(!format!("{pins:?}").contains("1234567"));
        let cmd = Command::SetSlot {
            slot: 1,
            field: 5,
            value: b"hunter2".to_vec(),
        };
        assert_eq!(format!("{cmd:?}"), "Command::SetSlot");
    }

    /// PIN kinds map to their message IDs.
    #[test]
    fn pin_kind_message_ids() {
        assert_eq!(PinKind::Primary.message_id(), MessageId::OkSetPin);
        assert_eq!(PinKind::Second.message_id(), MessageId::OkSetPin2);
        assert_eq!(PinKind::SelfDestruct.message_id(), MessageId::OkSetSdPin);
    }
}
