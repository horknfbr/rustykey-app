//! `MockDevice` test double that answers like firmware (port of `MockTransport.ts`).
//!
//! Also [`MockRig`]: an [`Engine`] wired to a [`MockDevice`] on a virtual clock, for tests and
//! a demo backend. Only built for tests or with the `mock` feature.
#![cfg(any(test, feature = "mock"))]

use crate::api::{Command, DeviceError, Event, Reply, Snapshot};
use crate::engine::{Engine, Millis, Output, RequestId};
use crate::parser::hid_label_slot_byte;
use crate::protocol::{BOOTLOADER_PRODUCT_ID, FieldId, GLOBAL_SLOT, MessageId};
use std::collections::{BTreeMap, VecDeque};

/// Device profile of a [`MockDevice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockKind {
    /// Full-size OnlyKey.
    Classic,
    /// OnlyKey DUO.
    Duo,
    /// First-use device.
    Uninitialized,
    /// Bootloader.
    Bootloader,
}

/// Global settings that need only an unlocked device, never config mode.
const STANDARD_PREF_FIELDS: [u8; 5] = [11, 13, 14, 24, 25];
/// Settings firmware refuses outside config mode.
const CONFIG_MODE_FIELDS: [u8; 9] = [12, 20, 21, 22, 26, 27, 30, 31, 10];

/// A 64-byte report holding ASCII text.
pub fn text_report(text: &str) -> [u8; 64] {
    let mut report = [0u8; 64];
    for (dst, src) in report.iter_mut().zip(text.bytes()) {
        *dst = src;
    }
    report
}

/// A binary label report: `[slot byte]['|'][label…]`.
pub fn label_report(slot: u8, label: &str) -> [u8; 64] {
    let mut report = [0u8; 64];
    report[0] = hid_label_slot_byte(slot);
    report[1] = b'|';
    for (dst, src) in report[2..].iter_mut().zip(label.bytes()) {
        *dst = src;
    }
    report
}

/// Stateful firmware simulator: give it a packet, get back the reports firmware would send.
#[derive(Debug, Clone)]
pub struct MockDevice {
    /// Device profile.
    pub kind: MockKind,
    /// Firmware version shown in status text.
    pub version: String,
    /// Locked (false for uninitialized and bootloader).
    pub locked: bool,
    /// In config mode.
    pub config_mode: bool,
    /// In the bootloader.
    pub bootloader: bool,
    /// Require config mode for slot, key and advanced writes.
    pub require_config_mode: bool,
    /// A PIN unlock also enters config mode.
    pub unlock_enters_config_mode: bool,
    /// DUO unlock PIN; empty accepts any PIN.
    pub correct_pin: String,
    /// Wrong PINs before "attempts exceeded"; 0 is unlimited.
    pub max_pin_attempts: u32,
    /// Send labels as binary reports (realistic) rather than `NN|text`.
    pub binary_labels: bool,
    /// Answer nothing (a hung or silent device).
    pub silent: bool,
    /// Slot labels.
    pub labels: BTreeMap<u8, String>,
    /// Wrong PINs so far.
    pin_attempts: u32,
    /// Classic PIN setup step per PIN kind (primary, second, self-destruct).
    setup_pin_step: [u32; 3],
}

impl MockDevice {
    /// A device of `kind` with the original mock's defaults: locked unless uninitialized or
    /// bootloader, sample labels, no config-mode requirement.
    pub fn new(kind: MockKind) -> Self {
        let seed: &[(u8, &str)] = match kind {
            MockKind::Classic => &[(1, "Gmail"), (2, "GitHub"), (7, "Work VPN"), (8, "Bank")],
            MockKind::Duo => &[
                (1, "Gmail"),
                (2, "GitHub"),
                (4, "Work VPN"),
                (5, "Bank"),
                (13, "Yellow 1"),
                (19, "Purple 1"),
            ],
            MockKind::Uninitialized | MockKind::Bootloader => &[],
        };
        Self {
            kind,
            version: if kind == MockKind::Duo {
                "v3.0.0-prod"
            } else {
                "v2.1.0-prod"
            }
            .to_string(),
            locked: matches!(kind, MockKind::Classic | MockKind::Duo),
            config_mode: false,
            bootloader: kind == MockKind::Bootloader,
            require_config_mode: false,
            unlock_enters_config_mode: true,
            correct_pin: String::new(),
            max_pin_attempts: 0,
            binary_labels: true,
            silent: false,
            labels: seed
                .iter()
                .map(|&(slot, label)| (slot, label.to_string()))
                .collect(),
            pin_attempts: 0,
            setup_pin_step: [0; 3],
        }
    }

    /// Same device, unlocked.
    pub fn unlocked(mut self) -> Self {
        self.locked = false;
        self
    }

    /// Enters or leaves config mode; entering also locks, as firmware reports it.
    pub fn set_config_mode(&mut self, enabled: bool) {
        self.config_mode = enabled;
        self.locked |= enabled;
    }

    /// USB product ID this device enumerates with.
    pub fn product_id(&self) -> u16 {
        match self.kind {
            MockKind::Duo => 0x614C,
            MockKind::Bootloader => BOOTLOADER_PRODUCT_ID,
            MockKind::Classic | MockKind::Uninitialized => 0x60FC,
        }
    }

    /// The status report sent right after plug-in.
    pub fn connect_report(&self) -> [u8; 64] {
        text_report(&self.status())
    }

    /// Handles one output report and returns the input reports it causes, in order.
    pub fn handle(&mut self, packet: &[u8; 64]) -> Vec<[u8; 64]> {
        /// Message IDs as match patterns.
        mod id {
            use crate::protocol::MessageId;
            /// OKSETTIME.
            pub const SET_TIME: u8 = MessageId::OkSetTime as u8;
            /// OKGETLABELS.
            pub const GET_LABELS: u8 = MessageId::OkGetLabels as u8;
            /// OKSETPIN.
            pub const SET_PIN: u8 = MessageId::OkSetPin as u8;
            /// OKSETPIN2.
            pub const SET_PIN2: u8 = MessageId::OkSetPin2 as u8;
            /// OKSETSDPIN.
            pub const SET_SD_PIN: u8 = MessageId::OkSetSdPin as u8;
            /// OKSETSLOT.
            pub const SET_SLOT: u8 = MessageId::OkSetSlot as u8;
            /// OKWIPESLOT.
            pub const WIPE_SLOT: u8 = MessageId::OkWipeSlot as u8;
            /// OKSETPRIV.
            pub const SET_PRIV: u8 = MessageId::OkSetPriv as u8;
            /// OKWIPEPRIV.
            pub const WIPE_PRIV: u8 = MessageId::OkWipePriv as u8;
            /// OKRESTORE.
            pub const RESTORE: u8 = MessageId::OkRestore as u8;
            /// OKFWUPDATE.
            pub const FW_UPDATE: u8 = MessageId::OkFwUpdate as u8;
        }
        if self.silent {
            return Vec::new();
        }
        let needs_config = self.require_config_mode && !self.config_mode;
        let texts: Vec<String> = match packet[4] {
            // Real firmware answers OKSETTIME with its status, not a bare "OK".
            id::SET_TIME => vec![self.status()],
            id::GET_LABELS => return self.label_reports(),
            id::SET_PIN => vec![self.set_pin(packet)],
            id::SET_PIN2 => vec![self.classic_pin_setup(1)],
            id::SET_SD_PIN => vec![self.classic_pin_setup(2)],
            id::SET_SLOT => vec![self.set_slot(packet)],
            id::WIPE_SLOT => vec![self.wipe_slot(packet)],
            id::SET_PRIV | id::WIPE_PRIV if needs_config => vec!["Error not in config mode".into()],
            // Intermediate restore chunks (flag 0xFF) are silent unless refused.
            id::RESTORE if needs_config && !self.bootloader => {
                vec!["Error not in config mode".into()]
            }
            id::RESTORE if packet[5] == 0xFF => Vec::new(),
            id::RESTORE => vec![
                "Successfully loaded backup".into(),
                "Remove and Reinsert OnlyKey to complete restore".into(),
            ],
            id::FW_UPDATE => self.firmware(packet),
            _ => vec!["OK".into()],
        };
        texts.iter().map(|t| text_report(t)).collect()
    }

    /// Version without its leading `v`.
    fn bare_version(&self) -> &str {
        self.version.strip_prefix('v').unwrap_or(&self.version)
    }

    /// Locked status text: `INITIALIZED-D…` for a DUO, else `INITIALIZED…`.
    fn status_initialized(&self) -> String {
        let duo = if self.kind == MockKind::Duo { "-D" } else { "" };
        format!("INITIALIZED{duo}v{}", self.bare_version())
    }

    /// Unlocked status text. The Classic string: a DUO's type sticks from INITIALIZED-D or USB.
    fn status_unlocked(&self) -> String {
        format!("UNLOCKEDv{}", self.bare_version())
    }

    /// Current status text, as OKSETTIME reports it.
    fn status(&self) -> String {
        if self.bootloader {
            "BOOTLOADER".to_string()
        } else if self.kind == MockKind::Uninitialized {
            format!("UNINITIALIZEDv{}", self.bare_version())
        } else if self.locked {
            self.status_initialized()
        } else {
            self.status_unlocked()
        }
    }

    /// One report per label in slot order, or "OK" when there are none.
    fn label_reports(&self) -> Vec<[u8; 64]> {
        if self.labels.is_empty() {
            return vec![text_report("OK")];
        }
        self.labels
            .iter()
            .map(|(&slot, label)| {
                if self.binary_labels {
                    label_report(slot, label)
                } else {
                    text_report(&format!("{slot:02}|{label}"))
                }
            })
            .collect()
    }

    /// The four-message Classic PIN setup state machine for PIN kind `which` (0, 1, 2).
    fn classic_pin_setup(&mut self, which: usize) -> String {
        self.setup_pin_step[which] += 1;
        let noun = if which == 2 {
            "self-destruct PIN"
        } else {
            "PIN"
        };
        match (self.setup_pin_step[which] - 1) % 4 {
            0 => format!("OnlyKey is ready, enter your {noun}"),
            1 => "Successful PIN entry".to_string(),
            2 => "OnlyKey is ready, re-enter your PIN to confirm".to_string(),
            _ => "Successfully set PIN".to_string(),
        }
    }

    /// OKSETPIN: empty is a Classic setup step; digits are a DUO setup (0xFF prefix) or unlock.
    fn set_pin(&mut self, packet: &[u8; 64]) -> String {
        let payload = &packet[5..];
        let is_setup = payload[0] == 0xFF;
        let digits: String = payload[usize::from(is_setup)..]
            .iter()
            .take_while(|&&b| b != 0)
            .filter(|b| b.is_ascii_digit())
            .map(|&b| char::from(b))
            .collect();
        if digits.is_empty() {
            return self.classic_pin_setup(0);
        }
        if !self.correct_pin.is_empty() && digits != self.correct_pin {
            self.pin_attempts += 1;
            if self.max_pin_attempts > 0 && self.pin_attempts >= self.max_pin_attempts {
                return "Error password attempts for this session exceeded".to_string();
            }
            if self.kind == MockKind::Duo && !is_setup {
                return self.status_initialized();
            }
            return "Error incorrect PIN".to_string();
        }
        self.pin_attempts = 0;
        self.locked = false;
        self.config_mode |= is_setup || self.unlock_enters_config_mode;
        self.status_unlocked()
    }

    /// OKSETSLOT with the original mock's lock and config-mode gates.
    fn set_slot(&mut self, packet: &[u8; 64]) -> String {
        let (slot, field) = (packet[5], packet[6]);
        let standard_pref = slot == GLOBAL_SLOT && STANDARD_PREF_FIELDS.contains(&field);
        let open = self.config_mode || self.bootloader;
        if self.require_config_mode
            && !open
            && !standard_pref
            && (CONFIG_MODE_FIELDS.contains(&field) || slot > 0)
        {
            let refusal = if self.locked {
                "Error device locked"
            } else {
                "Error not in config mode"
            };
            return refusal.to_string();
        }
        let locked_write = !open && !standard_pref && (self.require_config_mode || slot > 0);
        if self.locked && (locked_write || (standard_pref && !self.config_mode)) {
            return "Error device locked".to_string();
        }
        if field == FieldId::Label as u8 && slot > 0 {
            let text: String = packet[7..]
                .iter()
                .take_while(|&&b| b != 0)
                .filter(|&&b| (32..127).contains(&b))
                .map(|&b| char::from(b))
                .collect();
            let label = if text.trim().is_empty() {
                "empty"
            } else {
                text.trim()
            };
            self.labels.insert(slot, label.to_string());
        }
        match field {
            1 => "Successfully set Label",
            2 => "Successfully set Username",
            5 => "Successfully set Password",
            10 => "Successfully set AES Key, Private ID, and Public ID",
            11 => "Successfully set idle timeout",
            12 => "Successfully set Wipe Mode",
            13 => "Successfully set typespeed",
            14 => "Successfully set keyboard layout",
            15 => "Successfully set URL",
            20 => "Successfully set Backup Key Mode",
            21 => "Successfully set derived key challenge mode",
            22 => "Successfully set stored key challenge mode",
            23 => "Successfully set 2nd profile mode",
            24 => "Successfully set LED brightness",
            25 => "Successfully set lock button",
            26 => "Successfully set HMAC Challenge Mode",
            27 => "Successfully set Sysadmin Mode",
            30 => "Successfully set web and agent derived key mode",
            31 => "Successfully set webcrypt policy",
            _ => "Success",
        }
        .to_string()
    }

    /// OKWIPESLOT; the global Yubikey wipe is silent on real firmware.
    fn wipe_slot(&mut self, packet: &[u8; 64]) -> String {
        let (slot, field) = (packet[5], packet[6]);
        if self.require_config_mode && !self.config_mode {
            return "Error not in config mode".to_string();
        }
        if slot == GLOBAL_SLOT && field == FieldId::YubiAuth as u8 {
            return "OK".to_string();
        }
        if slot > 0 && (field == 0 || field == FieldId::Label as u8) {
            self.labels.insert(slot, "empty".to_string());
        }
        "Success".to_string()
    }

    /// OKFWUPDATE: the reboot kick outside the bootloader, block chunks inside it.
    fn firmware(&mut self, packet: &[u8; 64]) -> Vec<String> {
        if !self.bootloader {
            if packet[5..9] != [1, 2, 3, 4] {
                return vec!["Error not in bootloader".into()];
            }
            // The caller reconnects; the device then enumerates as bootloader.
            self.kind = MockKind::Bootloader;
            self.bootloader = true;
            self.locked = false;
            self.config_mode = false;
            return vec!["REBOOTING...".into()];
        }
        // Every chunk is acknowledged; the last chunk of a block (flag = length) also ends it.
        let mut replies = vec!["RECEIVED OKFWUPDATE".to_string()];
        if packet[5] != 0xFF {
            replies.extend([
                "NEXT BLOCK".to_string(),
                "SUCCESSFULLY LOADED FW".to_string(),
            ]);
        }
        replies
    }
}

/// An [`Engine`] driven against a [`MockDevice`] on a virtual clock.
pub struct MockRig {
    /// The engine under test.
    pub engine: Engine,
    /// The simulated device.
    pub device: MockDevice,
    /// Current virtual time.
    pub now: Millis,
    /// Whether the device is plugged in.
    pub plugged: bool,
    /// Every packet the engine wrote, with the time it was written.
    pub written: Vec<(Millis, [u8; 64])>,
    /// Every event the engine emitted.
    pub events: Vec<Event>,
    /// Every reply the engine gave.
    pub replies: Vec<(RequestId, Result<Reply, DeviceError>)>,
}

impl MockRig {
    /// Unix ms at virtual time 0.
    pub const UNIX_ORIGIN_MS: u64 = 1_700_000_000_000;

    /// A rig with the device not yet plugged in.
    pub fn new(device: MockDevice) -> Self {
        Self {
            engine: Engine::new(Self::UNIX_ORIGIN_MS),
            device,
            now: 0,
            plugged: false,
            written: Vec::new(),
            events: Vec::new(),
            replies: Vec::new(),
        }
    }

    /// Plugs the device in: the engine connects and the device sends its status.
    pub fn plug(&mut self) {
        self.plugged = true;
        self.engine.on_connected(self.device.product_id(), self.now);
        if !self.device.silent {
            let report = self.device.connect_report();
            self.engine.on_report(&report, self.now);
        }
        self.settle();
    }

    /// Unplugs the device.
    pub fn unplug(&mut self) {
        self.plugged = false;
        self.engine.on_disconnected(self.now);
        self.settle();
    }

    /// Submits a command and lets the exchange run as far as it can without time passing.
    pub fn submit(&mut self, cmd: Command) -> RequestId {
        let id = self.engine.submit(cmd, self.now);
        self.settle();
        id
    }

    /// Delivers an unsolicited text report from the device.
    pub fn inject(&mut self, text: &str) {
        self.inject_report(&text_report(text));
    }

    /// Delivers an unsolicited raw report from the device.
    pub fn inject_report(&mut self, report: &[u8; 64]) {
        self.engine.on_report(report, self.now);
        self.settle();
    }

    /// Advances virtual time by `ms`, ticking the engine at each deadline on the way.
    pub fn advance(&mut self, ms: u64) {
        let target = self.now + ms;
        self.settle();
        while let Some(deadline) = self.engine.next_deadline().filter(|&d| d <= target) {
            self.now = self.now.max(deadline);
            self.engine.on_tick(self.now);
            self.settle();
        }
        self.now = target;
        self.engine.on_tick(self.now);
        self.settle();
    }

    /// Drains engine outputs: writes go to the device and its answers come straight back.
    pub fn settle(&mut self) {
        let mut reports = VecDeque::new();
        loop {
            while let Some(output) = self.engine.poll_output() {
                match output {
                    Output::Write(packet) => {
                        self.written.push((self.now, packet));
                        if self.plugged {
                            reports.extend(self.device.handle(&packet));
                        }
                    }
                    Output::Event(event) => self.events.push(event),
                    Output::Reply(id, result) => self.replies.push((id, result)),
                }
            }
            let Some(report) = reports.pop_front() else {
                return;
            };
            self.engine.on_report(&report, self.now);
        }
    }

    /// The reply to request `id`, if it has finished.
    pub fn reply(&self, id: RequestId) -> Option<&Result<Reply, DeviceError>> {
        self.replies
            .iter()
            .find(|(rid, _)| *rid == id)
            .map(|(_, result)| result)
    }

    /// The engine's current snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        self.engine.snapshot()
    }

    /// Packets written with message ID `msg`, with their write times.
    pub fn written_of(&self, msg: MessageId) -> Vec<(Millis, [u8; 64])> {
        self.written
            .iter()
            .copied()
            .filter(|(_, p)| p[4] == msg as u8)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! Mock behaviours the engine tests do not reach.

    use super::*;
    use crate::parser::{Response, parse};

    /// Text of the single report a packet causes.
    fn answer(device: &mut MockDevice, msg: MessageId, slot: u8, field: u8) -> String {
        let reports = device.handle(&crate::protocol::frame(msg, Some(slot), Some(field), &[1]));
        assert_eq!(reports.len(), 1);
        match parse(&reports[0]) {
            Response::Error(text) | Response::Text(text) => text,
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Labels in `NN|text` form parse to the same slots as the binary form.
    #[test]
    fn text_labels_match_binary_labels() {
        let mut device = MockDevice::new(MockKind::Duo);
        let get_labels = crate::protocol::frame(MessageId::OkGetLabels, None, None, &[]);
        let binary: Vec<Response> = device.handle(&get_labels).iter().map(parse).collect();
        device.binary_labels = false;
        let text: Vec<Response> = device.handle(&get_labels).iter().map(parse).collect();
        let slots = |responses: &[Response]| -> Vec<(u8, String)> {
            responses
                .iter()
                .map(|r| match r {
                    Response::Label { slot, label, .. } => (*slot, label.clone()),
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        };
        assert_eq!(slots(&binary), slots(&text));
        assert_eq!(slots(&binary)[4], (13, "Yellow 1".to_string()));
    }

    /// Standard preferences need only an unlocked device; advanced ones need config mode when
    /// the mock requires it; nothing is written while locked.
    #[test]
    fn set_slot_gates() {
        let mut device = MockDevice::new(MockKind::Classic);
        device.require_config_mode = true;
        assert_eq!(
            answer(&mut device, MessageId::OkSetSlot, GLOBAL_SLOT, 11),
            "Error device locked"
        );
        assert_eq!(
            answer(&mut device, MessageId::OkSetSlot, 1, 1),
            "Error device locked"
        );
        device.locked = false;
        assert_eq!(
            answer(&mut device, MessageId::OkSetSlot, GLOBAL_SLOT, 11),
            "Successfully set idle timeout"
        );
        assert_eq!(
            answer(&mut device, MessageId::OkSetSlot, GLOBAL_SLOT, 12),
            "Error not in config mode"
        );
        assert_eq!(
            answer(&mut device, MessageId::OkWipeSlot, 1, 0),
            "Error not in config mode"
        );
        device.set_config_mode(true);
        assert!(device.locked);
        assert_eq!(
            answer(&mut device, MessageId::OkSetSlot, GLOBAL_SLOT, 12),
            "Successfully set Wipe Mode"
        );
        assert_eq!(answer(&mut device, MessageId::OkWipeSlot, 1, 0), "Success");
        assert_eq!(device.labels[&1], "empty");
    }
}
