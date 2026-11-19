//! The sans-IO device engine: callers drive it with input reports and time.
//!
//! Port of `OnlyKeyDevice.ts` (request queue, status state machine, labels, PINs, chunked
//! writes) and the device-facing half of `useDeviceStore.ts` (snapshot, session epoch, label
//! refresh, pending firmware). No I/O and no clock: the driver passes `now` and drains
//! [`Engine::poll_output`].
//!
//! Each [`Command`] compiles to a list of [`Step`]s. One job runs at a time; the rest wait in a
//! FIFO queue. Unlike the original, a multi-packet command is never interleaved with another.

use crate::api::{
    Command, DeviceError, DeviceKind, DeviceState, DuoPins, Event, PinPhase, Reply, Snapshot,
};
use crate::device_type::{self, DeviceType, TypeSource};
use crate::encoding;
use crate::parser::{self, Response, Status};
use crate::protocol::{self, GLOBAL_SLOT, MessageId, frame};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;

/// Milliseconds on a monotonic clock whose origin the driver picks.
pub type Millis = u64;

/// Slot labels 1–24 at index 0–23.
type Labels = [Option<String>; 24];

/// Data bytes per chunk of a chunked write (OKSETPRIV, OKRESTORE, OKFWUPDATE).
const CHUNK: usize = 57;
/// Default request timeout.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// Connect-time OKSETTIME timeout: must fail fast so a dead handle is retried.
const CONNECT_SETTIME_TIMEOUT_MS: u64 = 2_500;
/// Status probe timeout while locked.
const LOCK_STATUS_TIMEOUT_MS: u64 = 2_500;
/// Status probe timeout while unlocked.
const STATUS_TIMEOUT_MS: u64 = 5_000;
/// Gap between the two OKSETTIME packets of a set-time.
const SETTIME_GAP_MS: u64 = 100;
/// An INITIALIZED this soon after an unlock is a leftover reply, not a re-lock.
const STALE_LOCK_ECHO_MS: u64 = 2_500;
/// OKGETLABELS request timeout.
const LABEL_REQUEST_TIMEOUT_MS: u64 = 5_000;
/// The label stream ends after this long with no new label.
const LABEL_IDLE_MS: u64 = 400;
/// The label stream is given up after this long.
const LABEL_MAX_WAIT_MS: u64 = 5_000;
/// Error window after an intermediate chunk.
const CHUNK_ERROR_WINDOW_MS: u64 = 200;
/// Pause after an intermediate chunk (the MCU cannot keep up with a tight loop).
const CHUNK_GAP_MS: u64 = 30;
/// Message shown after a cancelled Classic PIN entry was flushed.
pub const PIN_ENTRY_CANCELED_MESSAGE: &str = "Canceled";

/// Handle for one submitted [`Command`]; its [`Output::Reply`] carries the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// Something the driver must act on, in the order polled.
#[derive(Clone, PartialEq, Eq)]
pub enum Output {
    /// Send this report to the device.
    Write([u8; 64]),
    /// Forward this event to the UI.
    Event(Event),
    /// A submitted command finished.
    Reply(RequestId, Result<Reply, DeviceError>),
}

impl fmt::Debug for Output {
    /// Packet payloads are redacted: they may carry PINs, keys or backup bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(p) => write!(f, "Write(msg {:#04x})", p[4]),
            Self::Event(e) => write!(f, "Event({e:?})"),
            Self::Reply(id, r) => write!(f, "Reply({id:?}, {r:?})"),
        }
    }
}

/// Which reply ends a [`Step::WaitFor`]. An error reply always fails the job first.
#[derive(Clone, Copy)]
enum Match {
    /// Any reply.
    Any,
    /// Any firmware status (`isFirmwareStatus`).
    Status,
    /// UNLOCKED / UNINITIALIZED / BOOTLOADER only (`isUnlockStatus`).
    UnlockStatus,
    /// Text contains one of these lowercase needles, ignoring case.
    Contains(&'static [&'static str]),
    /// Text contains one of these, case-sensitive.
    ContainsExact(&'static [&'static str]),
    /// Classic PIN prompt: "enter your … PIN" or "re-enter".
    ClassicPrompt,
    /// Any text longer than one character (the cancel flush).
    Flush,
    /// DUO unlock result; a refusal fails the job.
    DuoUnlock,
    /// Final OKRESTORE reply; "error" in the text fails the job.
    Restore,
    /// "RECEIVED OKFWUPDATE" after an intermediate firmware chunk.
    FwAck,
    /// "NEXT BLOCK", or "SUCCESSFULLY LOADED FW" on the last block.
    FwBlock {
        /// Whether this is the last block.
        last: bool,
    },
}

impl Match {
    /// `None` keeps waiting; `Some(Ok)` moves on; `Some(Err)` fails the job.
    fn verdict(self, resp: &Response, locked: bool) -> Option<Result<(), DeviceError>> {
        let text = response_text(resp);
        let lower = text.to_lowercase();
        let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
        let hit = |ok: bool| ok.then_some(Ok(()));
        // Firmware load: "error" anywhere in the text aborts with that text.
        let firmware = |ack: &str| {
            if lower.contains("error") {
                Some(Err(DeviceError::Device {
                    message: text.to_string(),
                }))
            } else {
                hit(lower.contains(ack))
            }
        };
        match self {
            Self::Any => Some(Ok(())),
            Self::Status => hit(matches!(resp, Response::Status(_))),
            Self::UnlockStatus => hit(["UNLOCKED", "UNINITIALIZED", "BOOTLOADER"]
                .iter()
                .any(|n| text.contains(n))),
            Self::Contains(needles) => hit(has(needles)),
            Self::ContainsExact(needles) => hit(needles.iter().any(|n| text.contains(n))),
            Self::ClassicPrompt => hit((lower.contains("enter your") && lower.contains("pin"))
                || lower.contains("re-enter")),
            Self::Flush => hit(text.len() > 1),
            Self::DuoUnlock => {
                if lower.contains("password attempts") {
                    Some(Err(DeviceError::AttemptsExceeded))
                } else if has(&["initialized-d", "incorrect"]) {
                    Some(Err(DeviceError::IncorrectPin))
                } else {
                    hit(lower.contains("unlocked"))
                }
            }
            Self::Restore => {
                if lower.contains("error") {
                    Some(Err(DeviceError::from_device_text(text, locked)))
                } else {
                    hit(has(&["successfully loaded backup", "remove and reinsert"]))
                }
            }
            Self::FwAck => firmware("received okfwupdate"),
            Self::FwBlock { last: true } => firmware("successfully loaded fw"),
            Self::FwBlock { last: false } => firmware("next block"),
        }
    }
}

/// One step of a job.
#[derive(Clone)]
enum Step {
    /// Send a report; the message ID names a later timeout.
    Write(MessageId, [u8; 64]),
    /// Wait this long; an error reply fails the job, anything else is ignored.
    ErrorWindow(u64),
    /// Wait for a matching reply; an error reply or the timeout (ms) fails the job.
    WaitFor(Match, u64),
    /// Wait this long; replies are not attributed to the job.
    Sleep(u64),
    /// Emit [`Event::Progress`].
    Progress(u8, String),
}

/// What a job is blocked on.
#[derive(Clone, Copy)]
enum WaitOn {
    /// [`Step::ErrorWindow`].
    ErrorWindow,
    /// [`Step::WaitFor`] with its timeout in ms.
    Reply(Match, u64),
    /// [`Step::Sleep`].
    Sleep,
}

/// A blocked job's wait and its deadline.
#[derive(Clone, Copy)]
struct Waiting {
    /// When the wait ends.
    until: Millis,
    /// What ends it sooner.
    on: WaitOn,
}

/// How a finished job is reported.
enum Kind {
    /// Reply `Done` or the error to the submitter.
    Plain,
    /// The connect probe: publish the snapshot, or treat a dead handle as no device.
    Connect,
    /// Set-time after an unlock; nobody is told.
    AutoSetTime,
    /// Shared status probe; answers every `probe_waiters` entry.
    StatusProbe,
    /// OKGETLABELS request; success starts the label collection.
    Labels,
    /// Classic PIN cancel flush; always ends with "Canceled" and `Done`.
    CancelFlush,
    /// Bootloader trigger for `LoadFirmware`; success holds these blocks for the reconnect.
    FwTrigger(Vec<Vec<u8>>),
    /// Held firmware streaming after the bootloader reconnect; a failure becomes [`Event::Error`].
    FwResume,
}

/// One queued or running command.
struct Job {
    /// Request to answer; `None` for engine-internal work and shared waits (probe, labels).
    id: Option<RequestId>,
    /// How to report the result.
    kind: Kind,
    /// Steps still to run.
    steps: VecDeque<Step>,
    /// Message ID of the last packet written.
    last_msg: MessageId,
    /// What the job is blocked on.
    wait: Option<Waiting>,
    /// Timeout error text when it is not the default "Request … timed out".
    timeout_text: Option<&'static str>,
}

impl Job {
    /// A job that has not started.
    fn new(id: Option<RequestId>, kind: Kind, steps: Vec<Step>) -> Self {
        Self {
            id,
            kind,
            steps: steps.into(),
            last_msg: MessageId::OkSetTime,
            wait: None,
            timeout_text: None,
        }
    }
}

/// A label read in progress, from request to the end of the stream.
#[derive(Default)]
struct LabelFetch {
    /// `GetLabels` requests to answer.
    waiters: Vec<RequestId>,
    /// When the request was answered and the stream wait began.
    started: Option<Millis>,
    /// When the last label arrived.
    last_label: Millis,
}

/// Device engine: owns protocol state; callers drive it with input reports and time.
pub struct Engine {
    /// Wall-clock Unix ms at `Millis` 0 (OKSETTIME needs real time).
    unix_origin_ms: u64,
    /// Next [`RequestId`].
    next_id: u64,
    /// Jobs waiting their turn.
    queue: VecDeque<Job>,
    /// The running job.
    active: Option<Job>,
    /// Outputs not yet polled.
    out: VecDeque<Output>,
    /// A HID handle is open.
    connected: bool,
    /// Device reports locked.
    locked: bool,
    /// Config mode inferred (sticky until reconnect).
    config_mode: bool,
    /// Device is in the bootloader.
    bootloader: bool,
    /// False for a first-use device.
    initialized: bool,
    /// Hardware type.
    ty: DeviceType,
    /// Firmware version text.
    version: String,
    /// False only for a DUO without a PIN.
    pin_set: bool,
    /// Labels as last sent by the device.
    labels: Labels,
    /// When UNLOCKED was last seen.
    last_unlocked_at: Option<Millis>,
    /// Hide Classic PIN prompts/errors while a cancel flush runs.
    suppress_pin: bool,
    /// `RefreshStatus` requests sharing the probe in flight.
    probe_waiters: Vec<RequestId>,
    /// Label read in flight.
    label_fetch: Option<LabelFetch>,
    /// Firmware blocks held across the reboot into the bootloader.
    pending_fw: Option<Vec<Vec<u8>>>,
    /// Last snapshot sent to the UI.
    snapshot: Snapshot,
    /// The UI has been told a device is connected.
    published: bool,
    /// Lock state the UI was last told (true before the first status).
    pub_locked: bool,
}

impl Engine {
    /// Creates a disconnected engine; `unix_ms_at_zero` is the wall-clock time (Unix ms) at `Millis` 0.
    pub fn new(unix_ms_at_zero: u64) -> Self {
        Self {
            unix_origin_ms: unix_ms_at_zero,
            next_id: 1,
            queue: VecDeque::new(),
            active: None,
            out: VecDeque::new(),
            connected: false,
            locked: true,
            config_mode: false,
            bootloader: false,
            initialized: true,
            ty: DeviceType::Unknown,
            version: String::new(),
            pin_set: true,
            labels: Labels::default(),
            last_unlocked_at: None,
            suppress_pin: false,
            probe_waiters: Vec::new(),
            label_fetch: None,
            pending_fw: None,
            snapshot: disconnected_snapshot(0, None),
            published: false,
            pub_locked: true,
        }
    }

    /// Re-syncs wall-clock time (after sleep or a clock change) so OKSETTIME stays right.
    pub fn set_unix_origin(&mut self, unix_ms_at_zero: u64) {
        self.unix_origin_ms = unix_ms_at_zero;
    }

    /// The snapshot last sent as [`Event::Snapshot`].
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// True while the engine is using the handle; false after a failed connect probe, so the
    /// driver should close the handle and try again.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Sets or clears the connect failure text and tells the UI.
    pub fn set_connect_error(&mut self, error: Option<String>) {
        let mut snap = self.snapshot.clone();
        snap.connect_error = error;
        self.publish(snap);
    }

    /// Queues a command; the result arrives later as [`Output::Reply`] with the returned id.
    pub fn submit(&mut self, cmd: Command, now: Millis) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        if !self.connected {
            // A cancel has nothing to flush; everything else needs a device.
            let result = if matches!(cmd, Command::CancelClassicPin { .. }) {
                Ok(Reply::Done)
            } else {
                Err(DeviceError::Disconnected)
            };
            self.out.push_back(Output::Reply(id, result));
            return id;
        }
        match self.compile(cmd, id, now) {
            Ok(Some(job)) => self.queue.push_back(job),
            Ok(None) => {}
            Err(e) => self.out.push_back(Output::Reply(id, Err(e))),
        }
        self.pump(now);
        id
    }

    /// Feeds one input report from the device.
    pub fn on_report(&mut self, report: &[u8; 64], now: Millis) {
        if !self.connected {
            return;
        }
        let resp = parser::parse(report);
        let error = match &resp {
            Response::Error(e) => Some(e.as_str()),
            _ => None,
        };
        let msg = error.unwrap_or_else(|| response_text(&resp));
        let noise = self.suppress_pin && is_pin_flush_noise(msg);
        if msg.len() > 1 && msg != "OK" && !noise {
            self.message(msg);
        }

        let changed = match &resp {
            Response::Status(status) => self.apply_status(status, now),
            _ => false,
        };

        let waiting = self.active.as_ref().and_then(|job| job.wait);
        let outcome = match (waiting.map(|w| w.on), error) {
            (None | Some(WaitOn::Sleep), _) => None,
            (Some(on), Some(e)) => Some(Err(self.device_error(e, on))),
            (Some(WaitOn::Reply(m, _)), None) => m.verdict(&resp, self.locked),
            (Some(WaitOn::ErrorWindow), None) => None,
        };

        if let Response::Label { slot, label, .. } = &resp {
            let index = usize::from(*slot) - 1;
            self.labels[index] = Some(label.clone());
            match &mut self.label_fetch {
                Some(fetch) => fetch.last_label = now,
                // An unsolicited label reaches the UI only while unlocked.
                None if self.published && !self.pub_locked => {
                    let mut snap = self.snapshot.clone();
                    snap.labels[index] = Some(label.clone());
                    self.publish(snap);
                }
                None => {}
            }
        }
        if changed {
            self.emit_status();
        }
        if let Some(e) = error.filter(|_| !noise) {
            self.error_event(e);
        }
        match outcome {
            Some(Ok(())) => {
                if let Some(job) = &mut self.active {
                    job.wait = None;
                }
            }
            Some(Err(e)) => {
                // A refused DUO PIN is also an `error` event; an "Error …" reply already was one.
                if error.is_none()
                    && matches!(
                        waiting.map(|w| w.on),
                        Some(WaitOn::Reply(Match::DuoUnlock, _))
                    )
                {
                    self.error_event(&e.to_string());
                }
                self.finish(Err(e), now);
            }
            None => {}
        }
        self.pump(now);
    }

    /// A HID handle was opened for product ID `pid`: reset per-connection state and probe.
    pub fn on_connected(&mut self, pid: u16, now: Millis) {
        // Reconnect without an unplug (TS `connect()`): drop work in flight, keep the session.
        self.abort_all();
        self.connected = true;
        self.locked = true;
        self.config_mode = false;
        self.bootloader = false;
        self.version.clear();
        self.labels = Labels::default();
        self.ty = protocol::device_type_from_product_id(pid).unwrap_or(DeviceType::Unknown);
        if self.ty == DeviceType::Bootloader {
            // No clock in the bootloader, and OKSETTIME waiters would steal OKFWUPDATE replies.
            self.bootloader = true;
            self.locked = false;
            self.connect_done();
        } else {
            let steps = self.set_time_steps(now, CONNECT_SETTIME_TIMEOUT_MS);
            self.queue.push_back(Job::new(None, Kind::Connect, steps));
        }
        self.pump(now);
    }

    /// The device was unplugged: fail everything in flight, wipe the session, bump the epoch.
    pub fn on_disconnected(&mut self, _now: Millis) {
        if self.connected {
            self.reset(true);
        }
    }

    /// Runs timeouts and sleeps that are due; call at [`Engine::next_deadline`].
    pub fn on_tick(&mut self, now: Millis) {
        let due = self.active.as_mut().and_then(|job| {
            let wait = job.wait.take_if(|w| w.until <= now)?;
            Some((wait.on, job.timeout_text, job.last_msg))
        });
        if let Some((WaitOn::Reply(_, ms), timeout_text, last_msg)) = due {
            let err = match timeout_text {
                Some(text) => DeviceError::Device {
                    message: text.to_string(),
                },
                None => DeviceError::timeout(last_msg, ms),
            };
            self.finish(Err(err), now);
        }
        self.pump(now);
        self.finish_labels(now);
    }

    /// When [`Engine::on_tick`] is next needed, if at all.
    pub fn next_deadline(&self) -> Option<Millis> {
        let wait = self
            .active
            .as_ref()
            .and_then(|job| job.wait)
            .map(|w| w.until);
        let labels = self.label_fetch.as_ref().and_then(|fetch| {
            let max = fetch.started? + LABEL_MAX_WAIT_MS;
            let idle = self
                .labels
                .iter()
                .any(Option::is_some)
                .then_some(fetch.last_label + LABEL_IDLE_MS);
            Some(idle.map_or(max, |idle| idle.min(max)))
        });
        [wait, labels].into_iter().flatten().min()
    }

    /// Takes the next thing for the driver to do.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    /// Turns a command into a job, or answers it at once (`Ok(None)`: joined a wait in flight).
    fn compile(
        &mut self,
        cmd: Command,
        id: RequestId,
        now: Millis,
    ) -> Result<Option<Job>, DeviceError> {
        use MessageId::{OkSetPin, OkSetPriv, OkSetSlot, OkWipePriv, OkWipeSlot};
        let invalid = |message: &str| DeviceError::InvalidInput {
            message: message.to_string(),
        };
        let mut kind = Kind::Plain;
        let mut job_id = Some(id);
        let mut timeout_text = None;
        let steps = match cmd {
            Command::SetTime => self.set_time_steps(now, DEFAULT_TIMEOUT_MS),
            Command::RefreshStatus => {
                self.probe_waiters.push(id);
                if self.probe_waiters.len() > 1 {
                    return Ok(None);
                }
                (kind, job_id) = (Kind::StatusProbe, None);
                // While locked, INITIALIZED must not complete the probe: only an unlock does.
                let (m, ms) = if self.locked {
                    (Match::UnlockStatus, LOCK_STATUS_TIMEOUT_MS)
                } else {
                    (Match::Status, STATUS_TIMEOUT_MS)
                };
                vec![self.time_write(now), Step::WaitFor(m, ms)]
            }
            Command::GetLabels => {
                if let Some(fetch) = &mut self.label_fetch {
                    fetch.waiters.push(id);
                    return Ok(None);
                }
                self.label_fetch = Some(LabelFetch {
                    waiters: vec![id],
                    ..LabelFetch::default()
                });
                return Ok(Some(labels_job()));
            }
            Command::SetSlot { slot, field, value } => request(
                OkSetSlot,
                Some(slot),
                Some(field),
                &value,
                Match::Any,
                DEFAULT_TIMEOUT_MS,
            ),
            Command::WipeSlot { slot, field } => request(
                OkWipeSlot,
                Some(slot),
                field,
                &[],
                Match::Any,
                DEFAULT_TIMEOUT_MS,
            ),
            Command::SetSlotTypeSpeed { slot, speed } => request(
                OkSetSlot,
                Some(slot),
                Some(13),
                &[speed],
                Match::Contains(&["typespeed", "type speed"]),
                DEFAULT_TIMEOUT_MS,
            ),
            Command::ClassicPin { which, phase } => {
                let m = match phase {
                    PinPhase::Prompt => Match::ClassicPrompt,
                    PinPhase::Commit => {
                        Match::Contains(&["successful pin", "successfully set pin"])
                    }
                };
                request(which.message_id(), None, None, &[], m, 300_000)
            }
            Command::CancelClassicPin { which } => {
                // Abort whatever reply is being waited for, then flush the keypad state machine.
                if self.active.as_ref().is_some_and(|job| {
                    matches!(
                        job.wait.map(|w| w.on),
                        Some(WaitOn::ErrorWindow | WaitOn::Reply(..))
                    )
                }) {
                    self.finish(Err(DeviceError::PinEntryCancelled), now);
                }
                self.suppress_pin = true;
                kind = Kind::CancelFlush;
                request(which.message_id(), None, None, &[], Match::Flush, 1_500)
            }
            Command::DuoPin { pins, setup } => {
                let m = if setup { Match::Any } else { Match::DuoUnlock };
                request(
                    OkSetPin,
                    None,
                    None,
                    &duo_pin_payload(&pins, setup)?,
                    m,
                    DEFAULT_TIMEOUT_MS,
                )
            }
            Command::SetPrivateKey {
                slot,
                key_type,
                bytes,
            } => {
                // Firmware replies on the final chunk only.
                let count = bytes.chunks(CHUNK).count();
                let mut steps = Vec::new();
                for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
                    steps.push(Step::Write(
                        OkSetPriv,
                        frame(OkSetPriv, Some(slot), Some(key_type), chunk),
                    ));
                    if i + 1 < count {
                        steps.extend([
                            Step::ErrorWindow(CHUNK_ERROR_WINDOW_MS),
                            Step::Sleep(CHUNK_GAP_MS),
                        ]);
                    } else {
                        steps.push(Step::WaitFor(Match::Any, DEFAULT_TIMEOUT_MS));
                    }
                }
                steps
            }
            Command::WipePrivateKey { slot } => request(
                OkWipePriv,
                Some(slot),
                None,
                &[],
                Match::Any,
                DEFAULT_TIMEOUT_MS,
            ),
            Command::SetGlobal { field, value } => request(
                OkSetSlot,
                Some(GLOBAL_SLOT),
                Some(field),
                &[value],
                global_match(field),
                DEFAULT_TIMEOUT_MS,
            ),
            Command::SetYubiAuth {
                public_id,
                private_id,
                secret_key,
            } => {
                timeout_text = Some("Timed out waiting for message containing \"set AES Key\"");
                let data = yubi_auth_bytes(&public_id, &private_id, &secret_key)?;
                request(
                    OkSetSlot,
                    Some(GLOBAL_SLOT),
                    Some(10),
                    &data,
                    Match::Contains(&["set aes key"]),
                    DEFAULT_TIMEOUT_MS,
                )
            }
            // Firmware wipes legacy Yubikey auth silently: only an error is worth waiting for.
            Command::WipeYubiAuth => vec![
                Step::Write(
                    OkWipeSlot,
                    frame(OkWipeSlot, Some(GLOBAL_SLOT), Some(10), &[]),
                ),
                Step::ErrorWindow(600),
            ],
            Command::Restore { payload } => {
                if payload.is_empty() {
                    return Err(invalid("Backup data is empty."));
                }
                restore_steps(&payload)
            }
            Command::TriggerBootloader => trigger_steps(),
            Command::LoadFirmware { blocks } => {
                if blocks.is_empty() {
                    return Err(invalid("Could not parse firmware file."));
                }
                if self.bootloader {
                    // Leftover held blocks would reflash on the next bootloader connect.
                    self.pending_fw = None;
                    firmware_steps(&blocks)
                } else {
                    kind = Kind::FwTrigger(blocks);
                    trigger_steps()
                }
            }
        };
        let mut job = Job::new(job_id, kind, steps);
        job.timeout_text = timeout_text;
        Ok(Some(job))
    }

    /// The OKSETTIME write for the wall-clock time at `now`.
    fn time_write(&self, now: Millis) -> Step {
        let unix_secs = (self.unix_origin_ms + now + 500) / 1000;
        let packet = frame(
            MessageId::OkSetTime,
            None,
            None,
            &protocol::set_time_bytes(unix_secs),
        );
        Step::Write(MessageId::OkSetTime, packet)
    }

    /// Two OKSETTIME requests 100 ms apart (firmware historically needs both).
    fn set_time_steps(&self, now: Millis, timeout_ms: u64) -> Vec<Step> {
        let write = self.time_write(now);
        let wait = Step::WaitFor(Match::Status, timeout_ms);
        vec![
            write.clone(),
            wait.clone(),
            Step::Sleep(SETTIME_GAP_MS),
            write,
            wait,
        ]
    }

    /// Runs the active job until it blocks, starting queued jobs as each one ends.
    fn pump(&mut self, now: Millis) {
        loop {
            if self.active.is_none() {
                let Some(job) = self.queue.pop_front() else {
                    return;
                };
                if matches!(job.kind, Kind::Labels) {
                    self.labels = Labels::default();
                }
                self.active = Some(job);
            }
            let Some(job) = &mut self.active else {
                return;
            };
            if job.wait.is_some() {
                return;
            }
            let wait = |on: WaitOn, ms: u64| {
                Some(Waiting {
                    until: now + ms,
                    on,
                })
            };
            match job.steps.pop_front() {
                None => self.finish(Ok(()), now),
                Some(Step::Write(msg, packet)) => {
                    job.last_msg = msg;
                    self.out.push_back(Output::Write(packet));
                }
                Some(Step::ErrorWindow(ms)) => job.wait = wait(WaitOn::ErrorWindow, ms),
                Some(Step::WaitFor(m, ms)) => job.wait = wait(WaitOn::Reply(m, ms), ms),
                Some(Step::Sleep(ms)) => job.wait = wait(WaitOn::Sleep, ms),
                Some(Step::Progress(percent, text)) => {
                    self.out
                        .push_back(Output::Event(Event::Progress { percent, text }));
                }
            }
        }
    }

    /// Ends the active job and reports the result the way its kind asks.
    fn finish(&mut self, result: Result<(), DeviceError>, now: Millis) {
        let Some(job) = self.active.take() else {
            return;
        };
        let id = job.id;
        let reply = |out: &mut VecDeque<Output>, result: Result<Reply, DeviceError>| {
            if let Some(id) = id {
                out.push_back(Output::Reply(id, result));
            }
        };
        match job.kind {
            Kind::Plain => reply(&mut self.out, result.map(|()| Reply::Done)),
            Kind::AutoSetTime => {}
            Kind::Connect => match result {
                Ok(()) => self.connect_done(),
                // The UI never saw this device, or the handle went quiet: no device. The epoch
                // only moves when a session is lost (a silent empty poll must not remount the UI).
                Err(e) if !self.published || matches!(e, DeviceError::Timeout { .. }) => {
                    self.reset(self.published);
                }
                Err(_) => {}
            },
            Kind::StatusProbe => {
                for id in std::mem::take(&mut self.probe_waiters) {
                    self.out
                        .push_back(Output::Reply(id, result.clone().map(|()| Reply::Done)));
                }
            }
            Kind::Labels => match result {
                Ok(()) => {
                    if let Some(fetch) = &mut self.label_fetch {
                        fetch.started = Some(now);
                    }
                }
                Err(e) => {
                    for id in self
                        .label_fetch
                        .take()
                        .map(|f| f.waiters)
                        .unwrap_or_default()
                    {
                        self.out.push_back(Output::Reply(id, Err(e.clone())));
                    }
                }
            },
            // A timeout is the flush succeeding: firmware may stay silent.
            Kind::CancelFlush => {
                self.suppress_pin = false;
                self.message(PIN_ENTRY_CANCELED_MESSAGE);
                reply(&mut self.out, Ok(Reply::Done));
            }
            Kind::FwTrigger(blocks) => {
                if result.is_ok() {
                    self.pending_fw = Some(blocks);
                }
                reply(&mut self.out, result.map(|()| Reply::FirmwarePending));
            }
            Kind::FwResume => {
                if let Err(e) = result {
                    self.error_event(&e.to_string());
                }
            }
        }
    }

    /// The connect probe passed: tell the UI, then stream held firmware into a bootloader.
    /// A device that came back in normal firmware drops held blocks, so a long-running tray app
    /// never flashes them on some much later bootloader connect.
    fn connect_done(&mut self) {
        self.emit_status();
        if !self.bootloader {
            self.pending_fw = None;
        } else if let Some(blocks) = self.pending_fw.take() {
            self.queue
                .push_back(Job::new(None, Kind::FwResume, firmware_steps(&blocks)));
        }
    }

    /// Ends the label read once the stream went quiet (or never came) and answers its waiters.
    fn finish_labels(&mut self, now: Millis) {
        let Some(started) = self.label_fetch.as_ref().and_then(|fetch| fetch.started) else {
            return;
        };
        let last_label = self
            .label_fetch
            .as_ref()
            .map_or(0, |fetch| fetch.last_label);
        let slots: Vec<u8> = (1..=24u8)
            .filter(|&slot| self.labels[usize::from(slot) - 1].is_some())
            .collect();
        let idle = !slots.is_empty() && now >= last_label + LABEL_IDLE_MS;
        if !idle && now < started + LABEL_MAX_WAIT_MS {
            return;
        }
        if let Some(ty) = device_type::from_labels(self.ty, &slots, idle) {
            self.ty = ty;
            self.emit_status();
        }
        if self.published && !self.pub_locked {
            let mut snap = self.snapshot.clone();
            snap.labels = self.labels.clone();
            self.publish(snap);
        }
        for id in self
            .label_fetch
            .take()
            .map(|f| f.waiters)
            .unwrap_or_default()
        {
            let labels = self.labels.clone();
            self.out
                .push_back(Output::Reply(id, Ok(Reply::Labels { labels })));
        }
    }

    /// The status state machine (`handleReceive`); returns whether anything changed.
    fn apply_status(&mut self, status: &Status, now: Millis) -> bool {
        let text = status.text.as_str();
        let was_locked = self.locked;
        let mut changed = false;
        let stale_echo = self
            .last_unlocked_at
            .is_some_and(|t| now.saturating_sub(t) < STALE_LOCK_ECHO_MS);

        if text.contains("BOOTLOADER") || status.device_type == Some(DeviceType::Bootloader) {
            changed |= !self.bootloader || self.locked;
            self.bootloader = true;
            self.locked = false;
        }
        if text.contains("UNLOCKED") {
            self.last_unlocked_at = Some(now);
            if self.locked {
                self.locked = false;
                changed = true;
                // Firmware ignores OKSETTIME while locked, so TOTP needs the clock set now.
                // "UNLOCKED BOOTLOADERv1" is not an application unlock.
                if !self.bootloader {
                    let steps = self.set_time_steps(now, DEFAULT_TIMEOUT_MS);
                    self.queue
                        .push_back(Job::new(None, Kind::AutoSetTime, steps));
                }
            }
        }
        if text.contains("INITIALIZED-D") {
            // DUO locked. Coming from unlocked it means config mode.
            changed |= !self.locked;
            self.locked = true;
            if !was_locked && !self.config_mode {
                self.config_mode = true;
                changed = true;
            }
        } else if text.contains("INITIALIZED")
            && !text.contains("UNINITIALIZED")
            && !text.contains("UNLOCKED")
            && !stale_echo
        {
            // Classic locked. Coming from unlocked it means config mode.
            changed |= !self.locked;
            self.locked = true;
            if !was_locked && self.ty == DeviceType::Classic {
                self.config_mode = true;
                changed = true;
            }
        }
        if self.locked != status.is_locked && !(status.is_locked && stale_echo) {
            self.locked = status.is_locked;
            changed = true;
        }
        if let Some(ty) =
            device_type::apply_transition(self.ty, status.device_type, TypeSource::Status(text))
        {
            self.ty = ty;
            changed = true;
        }
        if let Some(version) = status
            .version
            .as_deref()
            .filter(|v| !v.is_empty() && *v != self.version)
        {
            self.version = version.to_string();
            changed = true;
        }
        let pin_set = status
            .device_pin_set
            .unwrap_or_else(|| device_type::pin_set(self.ty, &self.version));
        let initialized = status.is_initialized.unwrap_or(self.initialized);
        changed |= self.pin_set != pin_set || self.initialized != initialized;
        self.pin_set = pin_set;
        self.initialized = initialized;
        changed
    }

    /// TS `statusChange` plus the store's listener: publish the snapshot, wipe the session on
    /// unlocked → locked, and refresh labels after an unlock or while there are none.
    fn emit_status(&mut self) {
        let wipe = self.published && !self.pub_locked && self.locked;
        let was_locked = self.pub_locked;
        self.published = true;
        self.pub_locked = self.locked;
        if wipe {
            self.labels = Labels::default();
        }
        let state = if self.bootloader || self.ty == DeviceType::Bootloader {
            DeviceState::Bootloader
        } else if self.config_mode {
            DeviceState::ConfigMode
        } else if device_type::is_uninitialized_device(Some(self.initialized), self.ty) {
            DeviceState::Uninitialized
        } else if self.locked {
            DeviceState::Locked
        } else {
            DeviceState::Unlocked
        };
        let snap = Snapshot {
            state,
            kind: match self.ty {
                DeviceType::Classic => DeviceKind::Classic,
                DeviceType::Duo => DeviceKind::Duo,
                _ => DeviceKind::Unknown,
            },
            firmware: (!self.version.is_empty()).then(|| self.version.clone()),
            pin_set: self.pin_set,
            product_name: protocol::product_name(self.ty).to_string(),
            // Never surface labels while locked: firmware may still return them.
            labels: if self.locked {
                Labels::default()
            } else {
                self.labels.clone()
            },
            session_epoch: self.snapshot.session_epoch + u64::from(wipe),
            connect_error: self.snapshot.connect_error.clone(),
            locked: self.locked,
        };
        let no_labels = snap.labels.iter().all(Option::is_none);
        self.publish(snap);
        if !wipe
            && !self.locked
            && !self.bootloader
            && self.label_fetch.is_none()
            && (was_locked || no_labels)
        {
            self.label_fetch = Some(LabelFetch::default());
            self.queue.push_back(labels_job());
        }
    }

    /// Sends the snapshot to the UI if it differs from the last one.
    fn publish(&mut self, snap: Snapshot) {
        if snap != self.snapshot {
            self.snapshot = snap.clone();
            self.out.push_back(Output::Event(Event::Snapshot(snap)));
        }
    }

    /// Emits a message; while locked only status text passes (the store's `messageReceived` rule).
    fn message(&mut self, text: &str) {
        let status = ["UNLOCKED", "INITIALIZED", "BOOTLOADER"]
            .iter()
            .any(|s| text.contains(s));
        if self.published && (!self.pub_locked || status) {
            self.out.push_back(Output::Event(Event::Message {
                text: text.to_string(),
            }));
        }
    }

    /// Emits a device error to the UI.
    fn error_event(&mut self, text: &str) {
        if self.published {
            self.out.push_back(Output::Event(Event::Error {
                text: text.to_string(),
            }));
        }
    }

    /// Error for a job that got an "Error …" reply while waiting on `on`.
    fn device_error(&self, text: &str, on: WaitOn) -> DeviceError {
        let duo_unlock = matches!(on, WaitOn::Reply(Match::DuoUnlock, _));
        if duo_unlock && text.to_lowercase().contains("password attempts") {
            DeviceError::AttemptsExceeded
        } else {
            DeviceError::from_device_text(text, self.locked)
        }
    }

    /// Fails every job and shared wait with `Disconnected` (a cancel flush just ends).
    fn abort_all(&mut self) {
        for job in self.active.take().into_iter().chain(self.queue.drain(..)) {
            if let Some(id) = job.id {
                let result = match job.kind {
                    Kind::CancelFlush => Ok(Reply::Done),
                    _ => Err(DeviceError::Disconnected),
                };
                self.out.push_back(Output::Reply(id, result));
            }
        }
        let labels = self
            .label_fetch
            .take()
            .map(|f| f.waiters)
            .unwrap_or_default();
        for id in std::mem::take(&mut self.probe_waiters)
            .into_iter()
            .chain(labels)
        {
            self.out
                .push_back(Output::Reply(id, Err(DeviceError::Disconnected)));
        }
        self.suppress_pin = false;
    }

    /// Back to "no device" (`resetDeviceState`); held firmware blocks survive for the reboot.
    fn reset(&mut self, bump_epoch: bool) {
        self.abort_all();
        self.connected = false;
        self.locked = true;
        self.config_mode = false;
        self.bootloader = false;
        self.initialized = true;
        self.ty = DeviceType::Unknown;
        self.version.clear();
        self.pin_set = true;
        self.labels = Labels::default();
        self.last_unlocked_at = None;
        self.published = false;
        self.pub_locked = true;
        let epoch = self.snapshot.session_epoch + u64::from(bump_epoch);
        self.publish(disconnected_snapshot(
            epoch,
            self.snapshot.connect_error.clone(),
        ));
    }
}

/// The snapshot shown while no device is connected.
fn disconnected_snapshot(session_epoch: u64, connect_error: Option<String>) -> Snapshot {
    Snapshot {
        pin_set: true,
        product_name: protocol::product_name(DeviceType::Unknown).to_string(),
        session_epoch,
        connect_error,
        ..Snapshot::default()
    }
}

/// Text a predicate sees: empty for an error reply (TS `r.text` is unset there).
fn response_text(resp: &Response) -> &str {
    match resp {
        Response::Error(_) => "",
        Response::Status(status) => &status.text,
        Response::Label { text, .. } | Response::Text(text) => text,
    }
}

/// Classic PIN prompts, confirmations and errors hidden while a cancel is flushed
/// (`PIN_FLUSH_NOISE`).
fn is_pin_flush_noise(text: &str) -> bool {
    let lower = text.to_lowercase();
    // `/error pins don.?t match/`: any one character, or none, where the apostrophe goes.
    let mismatch = lower.split("error pins don").skip(1).any(|rest| {
        rest.starts_with("t match")
            || rest
                .chars()
                .next()
                .is_some_and(|c| rest[c.len_utf8()..].starts_with("t match"))
    });
    mismatch
        || [
            "error pin is not between",
            "enter your",
            "successful pin",
            "successfully set pin",
        ]
        .iter()
        .any(|n| lower.contains(n))
}

/// One request: write a packet, then wait for a matching reply.
fn request(
    msg: MessageId,
    slot: Option<u8>,
    field: Option<u8>,
    data: &[u8],
    m: Match,
    timeout_ms: u64,
) -> Vec<Step> {
    vec![
        Step::Write(msg, frame(msg, slot, field, data)),
        Step::WaitFor(m, timeout_ms),
    ]
}

/// The OKGETLABELS job; the caller sets `label_fetch` first.
fn labels_job() -> Job {
    let steps = request(
        MessageId::OkGetLabels,
        None,
        None,
        &[],
        Match::Any,
        LABEL_REQUEST_TIMEOUT_MS,
    );
    Job::new(None, Kind::Labels, steps)
}

/// Confirmation text each global setting waits for (PARITY §2 preference table); other fields
/// take any reply.
fn global_match(field: u8) -> Match {
    Match::Contains(match field {
        11 => &["idle timeout", "lockout"],
        12 => &["wipe mode"],
        13 => &["typespeed", "type speed", "keyboard typespeed"],
        14 => &["keyboard layout", "layout"],
        20 => &["backup key mode"],
        21 => &["challenge mode", "derived key challenge"],
        22 => &["challenge mode", "stored key challenge"],
        24 => &["led brightness", "brightness"],
        25 => &["lock button"],
        26 => &["hmac challenge mode", "hmac"],
        27 => &["sysadmin mode", "modkey"],
        30 => &["web and agent derived key mode"],
        31 => &["webcrypt policy"],
        _ => return Match::Any,
    })
}

/// `/^[1-6]{7,10}$/`: what a DUO accepts as a PIN at setup.
fn is_duo_setup_pin(pin: &str) -> bool {
    (7..=10).contains(&pin.len()) && pin.bytes().all(|b| (b'1'..=b'6').contains(&b))
}

/// OKSETPIN payload for a DUO: `[0xFF][primary][second][self-destruct]` (16 bytes each, ASCII
/// digits, zero-padded) at setup, or the bare ASCII digits to unlock.
fn duo_pin_payload(pins: &DuoPins, setup: bool) -> Result<Vec<u8>, DeviceError> {
    if !setup {
        let digit = |c: char| if c.is_ascii_digit() { c as u8 } else { 0 };
        return Ok(pins.primary.chars().map(digit).collect());
    }
    let invalid = |message: &str| {
        Err(DeviceError::InvalidInput {
            message: message.to_string(),
        })
    };
    let second = pins.second.as_deref().unwrap_or("");
    let self_destruct = pins.self_destruct.as_deref().unwrap_or("");
    if !is_duo_setup_pin(&pins.primary) {
        return invalid("Device PIN must be 7–10 digits using only 1–6.");
    }
    if !second.is_empty() && !is_duo_setup_pin(second) {
        return invalid("Second profile PIN must be 7–10 digits using only 1–6.");
    }
    if !self_destruct.is_empty() {
        if !is_duo_setup_pin(self_destruct) {
            return invalid("Self-destruct PIN must be 7–10 digits using only 1–6.");
        }
        if self_destruct == pins.primary {
            return invalid("Self-destruct PIN must be different from the device PIN.");
        }
    }
    let mut payload = vec![0xFF];
    for pin in [pins.primary.as_str(), second, self_destruct] {
        let mut slot = [0u8; 16];
        slot[..pin.len()].copy_from_slice(pin.as_bytes());
        payload.extend(slot);
    }
    Ok(payload)
}

/// Legacy Yubikey auth data: modhex→hex(public[..12]) + private[..12] + secret[..32], as bytes.
fn yubi_auth_bytes(
    public_id: &str,
    private_id: &str,
    secret_key: &str,
) -> Result<Vec<u8>, DeviceError> {
    let head = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    let invalid = |e: encoding::EncodingError| DeviceError::InvalidInput {
        message: e.to_string(),
    };
    let public = encoding::hex_to_modhex(&head(public_id, 12), true).map_err(invalid)?;
    let hex = public + &head(private_id, 12) + &head(secret_key, 32);
    encoding::hex_to_bytes(&hex).map_err(invalid)
}

/// `Math.round(part / total * scale)`.
fn rounded_share(part: usize, total: usize, scale: usize) -> u8 {
    ((2 * part * scale + total) / (2 * total)) as u8
}

/// Chunked OKRESTORE: slot byte 0xFF means more follow, else it is the last chunk's length.
/// Intermediate chunks are silent; the final one applies the backup (up to 120 s).
fn restore_steps(payload: &[u8]) -> Vec<Step> {
    use MessageId::OkRestore;
    let total = payload.chunks(CHUNK).count();
    // The last 8% is the device decrypting and applying.
    let sending = |sent: usize| {
        let percent = rounded_share(sent, total, 92).min(92);
        Step::Progress(percent, format!("Sending backup to OnlyKey… {percent}%"))
    };
    let mut steps = vec![Step::Progress(0, "Preparing restore…".to_string())];
    for (i, chunk) in payload.chunks(CHUNK).enumerate() {
        if i + 1 < total {
            steps.extend([
                Step::Write(OkRestore, frame(OkRestore, Some(0xFF), None, chunk)),
                Step::ErrorWindow(CHUNK_ERROR_WINDOW_MS),
                Step::Sleep(CHUNK_GAP_MS),
                sending(i + 1),
            ]);
        } else {
            steps.extend([
                sending(i + 1),
                Step::Progress(95, "Applying backup on OnlyKey…".to_string()),
                Step::Write(
                    OkRestore,
                    frame(OkRestore, Some(chunk.len() as u8), None, chunk),
                ),
                Step::WaitFor(Match::Restore, 120_000),
                Step::Progress(
                    100,
                    "Restore complete — remove and reinsert OnlyKey".to_string(),
                ),
            ]);
        }
    }
    steps
}

/// Reboot into the bootloader: OKFWUPDATE with data 01 02 03 04 and no slot byte.
fn trigger_steps() -> Vec<Step> {
    request(
        MessageId::OkFwUpdate,
        None,
        None,
        &[1, 2, 3, 4],
        Match::ContainsExact(&["REBOOTING", "SUCCESSFULL"]),
        DEFAULT_TIMEOUT_MS,
    )
}

/// Firmware streaming: each block's non-final chunks (slot 0xFF) are acknowledged one by one,
/// the final chunk (slot = length) ends the block. Progress is per block.
fn firmware_steps(blocks: &[Vec<u8>]) -> Vec<Step> {
    use MessageId::OkFwUpdate;
    let loading = |percent: u8| Step::Progress(percent, format!("Loading firmware… {percent}%"));
    let mut steps = vec![loading(0)];
    let mut shown = 0;
    for (i, block) in blocks.iter().enumerate() {
        let count = block.chunks(CHUNK).count();
        for (j, chunk) in block.chunks(CHUNK).enumerate() {
            let (flag, wait) = if j + 1 < count {
                (0xFF, Step::WaitFor(Match::FwAck, 10_000))
            } else {
                let last = i + 1 == blocks.len();
                (
                    chunk.len() as u8,
                    Step::WaitFor(Match::FwBlock { last }, 20_000),
                )
            };
            steps.extend([
                Step::Write(OkFwUpdate, frame(OkFwUpdate, Some(flag), None, chunk)),
                wait,
            ]);
        }
        let percent = rounded_share(i + 1, blocks.len(), 100);
        if percent != shown {
            shown = percent;
            steps.push(loading(percent));
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    //! Engine behaviour against the mock device on a virtual clock. Ports the device cases of
    //! `OnlyKeyDevice.test.ts` and the store tests (`sessionWipe.security`, `initialize.dip`,
    //! `hotplugConnect`, `connectAnnounce`) that are about the device rather than the UI.

    use super::*;
    use crate::api::PinKind;
    use crate::transport::{MockDevice, MockKind, MockRig, label_report};
    use DeviceError::Disconnected;

    /// A plugged-in rig, one second after plug-in (connect probe and label read finished).
    fn rig(device: MockDevice) -> MockRig {
        let mut rig = MockRig::new(device);
        rig.plug();
        rig.advance(1_000);
        rig
    }

    /// An unlocked Classic.
    fn classic() -> MockRig {
        rig(MockDevice::new(MockKind::Classic).unlocked())
    }

    /// A locked Classic.
    fn locked_classic() -> MockRig {
        rig(MockDevice::new(MockKind::Classic))
    }

    /// An unlocked Classic that has stopped answering.
    fn silent_classic() -> MockRig {
        let mut rig = classic();
        rig.device.silent = true;
        rig
    }

    /// Forgets everything recorded so far.
    fn clear(rig: &mut MockRig) {
        rig.written.clear();
        rig.events.clear();
        rig.replies.clear();
    }

    /// Message events, in order.
    fn messages(rig: &MockRig) -> Vec<&str> {
        rig.events
            .iter()
            .filter_map(|e| match e {
                Event::Message { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Error events, in order.
    fn errors(rig: &MockRig) -> Vec<&str> {
        rig.events
            .iter()
            .filter_map(|e| match e {
                Event::Error { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Progress percentages, in order.
    fn progress(rig: &MockRig) -> Vec<u8> {
        rig.events
            .iter()
            .filter_map(|e| match e {
                Event::Progress { percent, .. } => Some(*percent),
                _ => None,
            })
            .collect()
    }

    /// Snapshot events, in order.
    fn snapshots(rig: &MockRig) -> Vec<&Snapshot> {
        rig.events
            .iter()
            .filter_map(|e| match e {
                Event::Snapshot(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Write times of packets with message ID `msg`.
    fn times(rig: &MockRig, msg: MessageId) -> Vec<Millis> {
        rig.written_of(msg).iter().map(|(t, _)| *t).collect()
    }

    /// The error request `id` failed with.
    fn err(rig: &MockRig, id: RequestId) -> DeviceError {
        rig.reply(id).expect("replied").clone().expect_err("failed")
    }

    /// Asserts request `id` finished with `Done`.
    #[track_caller]
    fn assert_done(rig: &MockRig, id: RequestId) {
        assert_eq!(rig.reply(id), Some(&Ok(Reply::Done)));
    }

    /// `InvalidInput` with this message.
    fn invalid(message: &str) -> DeviceError {
        DeviceError::InvalidInput {
            message: message.to_string(),
        }
    }

    /// A `SetSlot` writing the label of slot 1.
    fn set_label() -> Command {
        Command::SetSlot {
            slot: 1,
            field: 1,
            value: b"Mail".to_vec(),
        }
    }

    // --- connect ---------------------------------------------------------------------------

    /// Locked Classic: two OKSETTIME 100 ms apart carrying wall-clock seconds, then a locked snapshot.
    #[test]
    fn connect_locked_classic() {
        let rig = locked_classic();
        let time = rig.written_of(MessageId::OkSetTime);
        assert_eq!(times(&rig, MessageId::OkSetTime), [0, 100]);
        assert_eq!(time[0].1[..5], [0xFF, 0xFF, 0xFF, 0xFF, 0xE4]);
        assert_eq!(time[0].1[5..9], 1_700_000_000u32.to_be_bytes());
        assert_eq!(rig.written.len(), 2);
        let snap = rig.snapshot();
        assert_eq!(
            (snap.state, snap.kind, snap.locked),
            (DeviceState::Locked, DeviceKind::Classic, true)
        );
        assert_eq!(snap.firmware.as_deref(), Some("v2.1.0-prod"));
        assert_eq!(
            (snap.product_name.as_str(), snap.pin_set, snap.session_epoch),
            ("OnlyKey", true, 0)
        );
        assert!(snap.labels.iter().all(Option::is_none));
        assert!(rig.engine.is_connected());
    }

    /// Unlocked Classic: never shown as connected-and-locked; clock set again for the unlock;
    /// labels read.
    #[test]
    fn connect_unlocked_classic() {
        let rig = classic();
        assert_eq!(snapshots(&rig)[0].state, DeviceState::Unlocked);
        assert_eq!(times(&rig, MessageId::OkSetTime), [0, 100, 100, 200]);
        assert_eq!(times(&rig, MessageId::OkGetLabels), [200]);
        let snap = rig.snapshot();
        assert_eq!((snap.state, snap.locked), (DeviceState::Unlocked, false));
        assert_eq!(snap.labels[0].as_deref(), Some("Gmail"));
        assert_eq!(snap.labels[7].as_deref(), Some("Bank"));
        assert_eq!(snap.labels.iter().flatten().count(), 4);
    }

    /// A wiped device is uninitialized, not locked, with no PIN; its hardware type comes from
    /// the status suffix letter.
    #[test]
    fn connect_uninitialized() {
        let rig = rig(MockDevice::new(MockKind::Uninitialized));
        let snap = rig.snapshot();
        assert_eq!(
            (snap.state, snap.kind),
            (DeviceState::Uninitialized, DeviceKind::Classic)
        );
        assert!(!snap.locked && !snap.pin_set);

        let mut duo = MockDevice::new(MockKind::Uninitialized);
        duo.version = "v3.0.4-prodn".to_string();
        let rig = self::rig(duo);
        let snap = rig.snapshot();
        assert_eq!(
            (snap.state, snap.kind),
            (DeviceState::Uninitialized, DeviceKind::Duo)
        );
        assert_eq!(snap.product_name, "OnlyKey Duo");
    }

    /// Bootloader PID: no OKSETTIME at all, bootloader snapshot at once.
    #[test]
    fn connect_bootloader() {
        let rig = rig(MockDevice::new(MockKind::Bootloader));
        assert!(rig.written.is_empty());
        let snap = rig.snapshot();
        assert_eq!(
            (snap.state, snap.kind, snap.locked),
            (DeviceState::Bootloader, DeviceKind::Unknown, false)
        );
        assert_eq!(snapshots(&rig)[0].state, DeviceState::Bootloader);
    }

    /// "UNLOCKED BOOTLOADERv1" is the bootloader, not an application unlock: no set-time.
    #[test]
    fn unlocked_bootloader_status_is_bootloader() {
        let mut rig = locked_classic();
        clear(&mut rig);
        rig.inject("UNLOCKED BOOTLOADERv1");
        rig.advance(1_000);
        assert_eq!(rig.snapshot().state, DeviceState::Bootloader);
        assert_eq!(rig.snapshot().firmware.as_deref(), Some("v1"));
        assert!(rig.written.is_empty());
    }

    /// A handle that never answers is not a device: no snapshot, no epoch bump (silent poll).
    #[test]
    fn silent_probe_is_not_a_session() {
        let mut device = MockDevice::new(MockKind::Classic);
        device.silent = true;
        let mut rig = MockRig::new(device);
        rig.plug();
        rig.advance(2_499);
        assert!(rig.engine.is_connected());
        rig.advance(1);
        assert!(!rig.engine.is_connected());
        assert!(rig.events.is_empty());
        assert_eq!(rig.snapshot().session_epoch, 0);
        // The driver's later close is a no-op too.
        rig.unplug();
        assert_eq!(rig.snapshot().session_epoch, 0);
    }

    /// A connect OKSETTIME timeout after the UI saw the device ends that session (epoch bump).
    #[test]
    fn probe_timeout_after_status_ends_the_session() {
        let mut rig = MockRig::new(MockDevice::new(MockKind::Classic));
        rig.plug();
        assert_eq!(rig.snapshot().state, DeviceState::Locked);
        rig.device.silent = true;
        rig.advance(2_600);
        assert!(!rig.engine.is_connected());
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().session_epoch),
            (DeviceState::Disconnected, 1)
        );
    }

    /// A second connect on a live handle drops work in flight but is not an unplug.
    #[test]
    fn reconnect_without_unplug_keeps_the_session() {
        let mut rig = silent_classic();
        let pending = rig.submit(set_label());
        rig.written.clear();
        rig.engine.on_connected(0x60FC, rig.now);
        rig.settle();
        assert_eq!(err(&rig, pending), Disconnected);
        assert_eq!(rig.snapshot().session_epoch, 0);
        assert_eq!(rig.snapshot().state, DeviceState::Unlocked);
        assert_eq!(rig.written_of(MessageId::OkSetTime).len(), 1);
    }

    /// The driver's connect error rides in the snapshot and survives an unplug.
    #[test]
    fn connect_error_is_published() {
        let mut rig = MockRig::new(MockDevice::new(MockKind::Classic));
        rig.engine
            .set_connect_error(Some("Permission denied".to_string()));
        rig.settle();
        assert_eq!(
            snapshots(&rig)[0].connect_error.as_deref(),
            Some("Permission denied")
        );
        rig.plug();
        rig.unplug();
        assert_eq!(
            rig.snapshot().connect_error.as_deref(),
            Some("Permission denied")
        );
        rig.engine.set_connect_error(None);
        assert_eq!(rig.snapshot().connect_error, None);
    }

    // --- status state machine --------------------------------------------------------------

    /// Keypad unlock: the engine sets the clock by itself, then reads labels.
    #[test]
    fn unlock_triggers_auto_set_time() {
        let mut rig = locked_classic();
        clear(&mut rig);
        rig.device.locked = false;
        rig.inject("UNLOCKEDv2.1.0-prod");
        assert_eq!(rig.snapshot().state, DeviceState::Unlocked);
        rig.advance(1_000);
        assert_eq!(times(&rig, MessageId::OkSetTime), [1_000, 1_100]);
        assert_eq!(times(&rig, MessageId::OkGetLabels), [1_100]);
        assert_eq!(rig.snapshot().labels[1].as_deref(), Some("GitHub"));
        assert_eq!(rig.snapshot().session_epoch, 0);
    }

    /// INITIALIZED within 2500 ms of an unlock is a leftover reply, not a re-lock.
    #[test]
    fn stale_initialized_echo_ignored() {
        let mut rig = locked_classic();
        rig.device.silent = true;
        rig.inject("UNLOCKEDv2.1.0-prod");
        rig.advance(2_499);
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().locked),
            (DeviceState::Unlocked, false)
        );
        rig.advance(1);
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert!(rig.snapshot().locked);
    }

    /// Classic: INITIALIZED after unlocked means config mode, and it survives the next UNLOCKED.
    #[test]
    fn config_mode_inferred_classic() {
        let mut rig = classic();
        rig.advance(3_000);
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().locked),
            (DeviceState::ConfigMode, true)
        );
        assert_eq!(rig.snapshot().session_epoch, 1);
        rig.inject("UNLOCKEDv2.1.0-prod");
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().locked),
            (DeviceState::ConfigMode, false)
        );
        assert_eq!(rig.snapshot().session_epoch, 1);
    }

    /// DUO: INITIALIZED-D after unlocked means config mode, and it survives the next UNLOCKED.
    #[test]
    fn config_mode_inferred_duo() {
        let mut rig = rig(MockDevice::new(MockKind::Duo).unlocked());
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().kind),
            (DeviceState::Unlocked, DeviceKind::Duo)
        );
        rig.inject("INITIALIZED-Dv3.0.0-prod");
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().locked),
            (DeviceState::ConfigMode, true)
        );
        rig.inject("UNLOCKEDv3.0.0-prod");
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().locked),
            (DeviceState::ConfigMode, false)
        );
        assert_eq!(rig.snapshot().kind, DeviceKind::Duo);
    }

    /// A locked device that reports INITIALIZED again is just locked, not in config mode.
    #[test]
    fn locked_status_while_locked_is_not_config_mode() {
        let mut rig = locked_classic();
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert_eq!(rig.snapshot().state, DeviceState::Locked);
        let mut rig = self::rig(MockDevice::new(MockKind::Duo));
        rig.inject("INITIALIZED-Dv3.0.0-prod");
        assert_eq!(rig.snapshot().state, DeviceState::Locked);
    }

    /// Only messages longer than one character and not "OK" are emitted; errors are both a
    /// message and an error event.
    #[test]
    fn message_filter() {
        let mut rig = classic();
        clear(&mut rig);
        for text in ["OK", "x", "", "hello", "Error unknown failure"] {
            rig.inject(text);
        }
        assert_eq!(messages(&rig), ["hello", "Error unknown failure"]);
        assert_eq!(errors(&rig), ["Error unknown failure"]);
    }

    /// While locked only status messages are recorded; error events still pass.
    #[test]
    fn locked_device_emits_only_status_messages() {
        let mut rig = locked_classic();
        clear(&mut rig);
        rig.inject("slot data");
        rig.inject("Error password attempts for this session exceeded");
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert_eq!(messages(&rig), ["INITIALIZEDv2.1.0-prod"]);
        assert_eq!(
            errors(&rig),
            ["Error password attempts for this session exceeded"]
        );
    }

    // --- session wipe ----------------------------------------------------------------------

    /// Unlocked → locked (idle lock) bumps the epoch and clears labels; the next unlock reads
    /// them again without another bump.
    #[test]
    fn lock_bumps_epoch_and_clears_labels() {
        for kind in [MockKind::Classic, MockKind::Duo] {
            let mut rig = rig(MockDevice::new(kind).unlocked());
            assert!(rig.snapshot().labels.iter().any(Option::is_some));
            rig.advance(3_000);
            rig.device.locked = true;
            rig.inject("LOCKED");
            let snap = rig.snapshot();
            assert_eq!(
                (snap.state, snap.locked, snap.session_epoch),
                (DeviceState::Locked, true, 1)
            );
            assert!(snap.labels.iter().all(Option::is_none));

            rig.device.locked = false;
            rig.inject("UNLOCKEDv2.1.0-prod");
            rig.advance(1_000);
            assert_eq!(rig.snapshot().session_epoch, 1);
            assert!(rig.snapshot().labels.iter().any(Option::is_some));
        }
    }

    /// Labels the device sends while locked never reach the snapshot.
    #[test]
    fn labels_hidden_while_locked() {
        let mut rig = locked_classic();
        rig.inject_report(&label_report(1, "secret-label"));
        let id = rig.submit(Command::GetLabels);
        rig.advance(1_000);
        assert!(rig.snapshot().labels.iter().all(Option::is_none));
        assert!(
            snapshots(&rig)
                .iter()
                .all(|s| s.labels.iter().all(Option::is_none))
        );
        assert!(matches!(rig.reply(id), Some(Ok(Reply::Labels { .. }))));
    }

    /// Unplug: everything in flight fails, the queue is dropped, the session is wiped, the epoch bumps.
    #[test]
    fn disconnect_aborts_pending_clears_queue_bumps_epoch() {
        let mut rig = silent_classic();
        let ids = [
            rig.submit(set_label()),
            rig.submit(Command::WipeSlot {
                slot: 2,
                field: None,
            }),
            rig.submit(Command::RefreshStatus),
            rig.submit(Command::GetLabels),
        ];
        assert!(rig.replies.is_empty());
        let wipes = rig.written_of(MessageId::OkWipeSlot).len();
        rig.unplug();
        for id in ids {
            assert_eq!(err(&rig, id), Disconnected);
        }
        assert_eq!(rig.written_of(MessageId::OkWipeSlot).len(), wipes);
        let snap = rig.snapshot();
        assert_eq!(
            (snap.state, snap.kind, snap.session_epoch),
            (DeviceState::Disconnected, DeviceKind::Unknown, 1)
        );
        assert!(snap.labels.iter().all(Option::is_none) && snap.firmware.is_none() && !snap.locked);
        assert!(!rig.engine.is_connected());
        assert_eq!(rig.engine.next_deadline(), None);

        rig.unplug();
        assert_eq!(rig.snapshot().session_epoch, 1);
        let late = rig.submit(set_label());
        assert_eq!(err(&rig, late), Disconnected);
        assert_eq!(err(&rig, late).to_string(), "Device disconnected");
    }

    // --- labels ----------------------------------------------------------------------------

    /// The label read ends 400 ms after the last label; slots 10–24 arrive as byte + 6.
    #[test]
    fn labels_stream_quiet_timeout_and_slot_mapping() {
        let mut rig = classic();
        let id = rig.submit(Command::GetLabels);
        rig.advance(399);
        rig.inject_report(&label_report(10, "ten"));
        let mut last = label_report(24, "last");
        assert_eq!(last[0], 0x1E);
        last[2..6].copy_from_slice(b"end!");
        rig.inject_report(&last);
        rig.advance(399);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        let Some(Ok(Reply::Labels { labels })) = rig.reply(id) else {
            panic!("no labels reply");
        };
        assert_eq!(labels[0].as_deref(), Some("Gmail"));
        assert_eq!(labels[9].as_deref(), Some("ten"));
        assert_eq!(labels[23].as_deref(), Some("end!"));
        assert_eq!(&rig.snapshot().labels, labels);
    }

    /// With no labels at all the read gives up after 5 s.
    #[test]
    fn labels_max_wait() {
        let mut rig = classic();
        rig.device.labels.clear();
        let id = rig.submit(Command::GetLabels);
        rig.advance(4_999);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_eq!(
            rig.reply(id),
            Some(&Ok(Reply::Labels {
                labels: Labels::default()
            }))
        );
        assert!(rig.snapshot().labels.iter().all(Option::is_none));
    }

    /// Overlapping label reads share one OKGETLABELS; a silent device fails them after 5 s.
    #[test]
    fn labels_requests_are_shared() {
        let mut rig = classic();
        clear(&mut rig);
        let (a, b) = (
            rig.submit(Command::GetLabels),
            rig.submit(Command::GetLabels),
        );
        rig.advance(400);
        assert_eq!(rig.written_of(MessageId::OkGetLabels).len(), 1);
        assert!(rig.reply(a).is_some() && rig.reply(a) == rig.reply(b));

        rig.device.silent = true;
        let c = rig.submit(Command::GetLabels);
        rig.advance(5_000);
        assert_eq!(
            err(&rig, c),
            DeviceError::timeout(MessageId::OkGetLabels, 5_000)
        );
    }

    /// A label sent outside a read updates the snapshot at once.
    #[test]
    fn unsolicited_label_updates_snapshot() {
        let mut rig = classic();
        rig.inject_report(&label_report(7, "unsolicited"));
        assert_eq!(rig.snapshot().labels[6].as_deref(), Some("unsolicited"));
    }

    // --- device type -----------------------------------------------------------------------

    /// Status may move Classic → DUO, and DUO → Classic only on a `c` suffix.
    #[test]
    fn type_transitions_from_status() {
        let mut rig = locked_classic();
        rig.inject("UNLOCKEDv3.0.4-prodc");
        assert_eq!(rig.snapshot().kind, DeviceKind::Classic);
        rig.inject("UNLOCKEDv3.0.4-prodp");
        assert_eq!(rig.snapshot().kind, DeviceKind::Duo);
        assert_eq!(rig.snapshot().product_name, "OnlyKey Duo");
        // A Classic-looking status without the suffix letter does not demote a DUO…
        rig.inject("INITIALIZEDv2.1.0-prod");
        assert_eq!(rig.snapshot().kind, DeviceKind::Duo);
        // …but the suffix letter does.
        rig.inject("UNLOCKEDv3.0.4-prodc");
        assert_eq!(rig.snapshot().kind, DeviceKind::Classic);
    }

    /// The type is forgotten on every connect: a Classic after a DUO is a Classic.
    #[test]
    fn type_resets_on_reconnect() {
        let mut rig = rig(MockDevice::new(MockKind::Duo).unlocked());
        assert_eq!(rig.snapshot().kind, DeviceKind::Duo);
        rig.unplug();
        rig.device = MockDevice::new(MockKind::Classic);
        rig.plug();
        assert_eq!(
            (rig.snapshot().kind, rig.snapshot().state),
            (DeviceKind::Classic, DeviceState::Locked)
        );
    }

    /// Labels never demote or promote a known type; they only settle an unknown one.
    #[test]
    fn labels_never_change_a_known_type() {
        // Classic HID `1a` decodes as slot 20: must not promote.
        let mut rig = classic();
        rig.device.labels.insert(20, "x".to_string());
        rig.submit(Command::GetLabels);
        rig.advance(1_000);
        assert_eq!(rig.snapshot().kind, DeviceKind::Classic);

        // A DUO with only 12 labels must not be demoted.
        let mut duo = MockDevice::new(MockKind::Duo).unlocked();
        duo.labels = (1..=12).map(|slot| (slot, format!("s{slot}"))).collect();
        let rig = self::rig(duo);
        assert_eq!(rig.snapshot().labels.iter().flatten().count(), 12);
        assert_eq!(rig.snapshot().kind, DeviceKind::Duo);
    }

    /// With the type still unknown, 12 idle labels mean Classic and any slot above 12 means DUO.
    #[test]
    fn labels_settle_an_unknown_type() {
        for (slots, kind) in [
            (12, DeviceKind::Classic),
            (13, DeviceKind::Duo),
            (4, DeviceKind::Unknown),
        ] {
            let mut device = MockDevice::new(MockKind::Classic).unlocked();
            device.version = String::new();
            device.labels = (1..=slots).map(|slot| (slot, format!("s{slot}"))).collect();
            let mut rig = MockRig::new(device);
            rig.plug();
            assert_eq!(rig.snapshot().kind, DeviceKind::Unknown);
            rig.advance(1_000);
            assert_eq!(rig.snapshot().kind, kind);
        }
    }

    // --- request engine --------------------------------------------------------------------

    /// One request at a time, in order; a timeout names the request and frees the queue.
    #[test]
    fn timeout_and_fifo() {
        let mut rig = silent_classic();
        clear(&mut rig);
        let first = rig.submit(set_label());
        let second = rig.submit(Command::WipePrivateKey { slot: 101 });
        assert_eq!(rig.written.len(), 1);
        rig.advance(9_999);
        assert!(rig.replies.is_empty());
        rig.advance(1);
        assert_eq!(
            err(&rig, first),
            DeviceError::timeout(MessageId::OkSetSlot, 10_000)
        );
        assert_eq!(
            err(&rig, first).to_string(),
            "Request OKSETSLOT timed out after 10000ms"
        );
        assert_eq!(times(&rig, MessageId::OkWipePriv), [rig.now]);
        assert_eq!(rig.written_of(MessageId::OkWipePriv)[0].1[5], 101);
        rig.inject("OK");
        assert_done(&rig, second);
    }

    /// Any error reply rejects the pending request and is also an error event.
    #[test]
    fn error_reply_rejects_pending() {
        let mut rig = silent_classic();
        clear(&mut rig);
        let id = rig.submit(set_label());
        rig.inject("Error unknown failure");
        assert_eq!(
            err(&rig, id),
            DeviceError::Device {
                message: "Error unknown failure".to_string()
            }
        );
        assert_eq!(errors(&rig), ["Error unknown failure"]);
    }

    /// "not in config mode" → config-mode guidance.
    #[test]
    fn error_remap_not_in_config_mode() {
        let mut device = MockDevice::new(MockKind::Classic).unlocked();
        device.require_config_mode = true;
        let mut rig = rig(device);
        let id = rig.submit(set_label());
        assert_eq!(err(&rig, id), DeviceError::ConfigModeForOperation);
        let id = rig.submit(Command::WipeSlot {
            slot: 1,
            field: None,
        });
        assert_eq!(err(&rig, id), DeviceError::ConfigModeForOperation);
    }

    /// "device locked" while the app thinks it is unlocked → config mode required (fw 3.0.4).
    #[test]
    fn error_remap_device_locked_while_unlocked() {
        let mut rig = silent_classic();
        let id = rig.submit(Command::WipePrivateKey { slot: 101 });
        rig.inject("Error device locked");
        assert_eq!(err(&rig, id), DeviceError::ConfigModeRequired);
    }

    /// "device locked" while locked → unlock guidance.
    #[test]
    fn error_remap_device_locked_while_locked() {
        for kind in [MockKind::Classic, MockKind::Duo] {
            let mut device = MockDevice::new(kind);
            device.require_config_mode = true;
            let mut rig = rig(device);
            let id = rig.submit(set_label());
            assert_eq!(err(&rig, id), DeviceError::Locked);
            assert_eq!(
                err(&rig, id).to_string(),
                "OnlyKey is locked. Unlock your device and try again."
            );
        }
    }

    /// `RefreshStatus` is shared; while locked only an unlock completes it (2500 ms).
    #[test]
    fn refresh_status_locked_rules() {
        let mut rig = locked_classic();
        clear(&mut rig);
        let (a, b) = (
            rig.submit(Command::RefreshStatus),
            rig.submit(Command::RefreshStatus),
        );
        // The mock answered INITIALIZED: that must not finish the probe.
        assert_eq!(rig.written_of(MessageId::OkSetTime).len(), 1);
        assert!(rig.replies.is_empty());
        rig.device.locked = false;
        rig.inject("UNLOCKEDv2.1.0-prod");
        assert_done(&rig, a);
        assert_done(&rig, b);
        assert_eq!(rig.snapshot().state, DeviceState::Unlocked);

        let mut rig = locked_classic();
        let c = rig.submit(Command::RefreshStatus);
        rig.advance(2_499);
        assert_eq!(rig.reply(c), None);
        rig.advance(1);
        assert_eq!(
            err(&rig, c),
            DeviceError::timeout(MessageId::OkSetTime, 2_500)
        );
        // A keypad unlock is seen by the next probe.
        rig.device.locked = false;
        let d = rig.submit(Command::RefreshStatus);
        assert_done(&rig, d);
        assert!(!rig.snapshot().locked);
    }

    /// While unlocked any status completes the probe, and it gets 5 s.
    #[test]
    fn refresh_status_unlocked_rules() {
        let mut rig = classic();
        let id = rig.submit(Command::RefreshStatus);
        assert_done(&rig, id);
        rig.device.silent = true;
        // Two probes in flight are one packet and one answer.
        clear(&mut rig);
        let (a, b) = (
            rig.submit(Command::RefreshStatus),
            rig.submit(Command::RefreshStatus),
        );
        rig.inject("UNLOCKEDv2.1.0-prod");
        assert_done(&rig, a);
        assert_done(&rig, b);
        assert_eq!(rig.written.len(), 1);
        let id = rig.submit(Command::RefreshStatus);
        rig.inject("hello");
        rig.advance(4_999);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_eq!(
            err(&rig, id),
            DeviceError::timeout(MessageId::OkSetTime, 5_000)
        );
    }

    /// `SetTime`: two OKSETTIME 100 ms apart, each waiting for a status.
    #[test]
    fn set_time_sends_two_packets() {
        let mut rig = classic();
        clear(&mut rig);
        let id = rig.submit(Command::SetTime);
        assert_eq!(rig.reply(id), None);
        rig.advance(100);
        assert_done(&rig, id);
        let packets = rig.written_of(MessageId::OkSetTime);
        assert_eq!(times(&rig, MessageId::OkSetTime), [1_000, 1_100]);
        assert_eq!(packets[0].1[5..9], 1_700_000_001u32.to_be_bytes());
    }

    // --- slots and preferences -------------------------------------------------------------

    /// Slot writes and wipes: packet layout, any reply resolves.
    #[test]
    fn slot_write_and_wipe() {
        let mut rig = classic();
        clear(&mut rig);
        let id = rig.submit(set_label());
        assert_done(&rig, id);
        assert_eq!(
            rig.written[0].1[4..11],
            [0xE6, 1, 1, b'M', b'a', b'i', b'l']
        );
        assert_eq!(rig.device.labels[&1], "Mail");

        let id = rig.submit(Command::WipeSlot {
            slot: 1,
            field: None,
        });
        assert_done(&rig, id);
        assert_eq!(rig.written[1].1[4..8], [0xE7, 1, 0, 0]);
        assert_eq!(rig.device.labels[&1], "empty");
        let id = rig.submit(Command::WipeSlot {
            slot: 2,
            field: Some(15),
        });
        assert_done(&rig, id);
        assert_eq!(rig.written[2].1[4..7], [0xE7, 2, 15]);

        let id = rig.submit(Command::SetSlotTypeSpeed { slot: 3, speed: 4 });
        assert_done(&rig, id);
        assert_eq!(rig.written[3].1[4..8], [0xE6, 3, 13, 4]);
    }

    /// Every preference setter writes `OKSETSLOT XX/field [value]` and waits for its own
    /// confirmation text, not just any reply.
    #[test]
    fn every_preference_setter_waits_for_its_match_text() {
        let table = [
            (11, "idle timeout"),
            (11, "lockout"),
            (12, "wipe mode"),
            (24, "led brightness"),
            (14, "keyboard layout"),
            (13, "typespeed"),
            (25, "lock button"),
            (21, "challenge mode"),
            (22, "challenge mode"),
            (26, "hmac"),
            (30, "web and agent derived key mode"),
            (31, "webcrypt policy"),
            (27, "sysadmin mode"),
            (20, "backup key mode"),
        ];
        let mut rig = silent_classic();
        for (field, text) in table {
            clear(&mut rig);
            let id = rig.submit(Command::SetGlobal { field, value: 7 });
            assert_eq!(rig.written[0].1[4..8], [0xE6, GLOBAL_SLOT, field, 7]);
            rig.inject("Success");
            rig.inject("Successfully set something else");
            assert_eq!(rig.reply(id), None, "field {field}");
            rig.inject(&format!("Successfully set {}", text.to_uppercase()));
            assert_done(&rig, id);
        }
        // Second-profile mode takes any reply.
        let id = rig.submit(Command::SetGlobal {
            field: 23,
            value: 1,
        });
        rig.inject("Success");
        assert_done(&rig, id);
    }

    /// The mock's real confirmation strings satisfy every setter.
    #[test]
    fn preference_setters_round_trip_on_the_mock() {
        let mut rig = classic();
        for field in [11, 12, 13, 14, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31] {
            let id = rig.submit(Command::SetGlobal { field, value: 1 });
            assert_done(&rig, id);
        }
    }

    /// Legacy Yubikey auth: modhex public ID decoded, data packed as bytes, waits "set AES Key".
    #[test]
    fn yubi_auth() {
        let mut rig = classic();
        clear(&mut rig);
        let set = |public_id: &str| Command::SetYubiAuth {
            public_id: public_id.to_string(),
            private_id: "aabbccddeeff".to_string(),
            secret_key: "00112233445566778899aabbccddeeff".to_string(),
        };
        let id = rig.submit(set("ccddcceeffcc"));
        assert_done(&rig, id);
        let packet = rig.written[0].1;
        assert_eq!(packet[4..7], [0xE6, GLOBAL_SLOT, 10]);
        assert_eq!(packet[7..13], [0x00, 0x22, 0x00, 0x33, 0x44, 0x00]);
        assert_eq!(packet[13..19], [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(
            packet[19..35],
            [
                0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );

        let id = rig.submit(set("not modhex!!"));
        assert_eq!(
            err(&rig, id),
            invalid("Invalid character sent for hexToModhex conversion")
        );

        rig.device.silent = true;
        let id = rig.submit(set("ccddcceeffcc"));
        rig.advance(10_000);
        assert_eq!(
            err(&rig, id).to_string(),
            "Timed out waiting for message containing \"set AES Key\""
        );
    }

    /// Legacy Yubikey wipe is silent: done after the 600 ms error window, unless an error arrives.
    #[test]
    fn wipe_yubi_auth_error_window() {
        let mut rig = silent_classic();
        clear(&mut rig);
        let id = rig.submit(Command::WipeYubiAuth);
        assert_eq!(rig.written[0].1[4..7], [0xE7, GLOBAL_SLOT, 10]);
        rig.inject("OK");
        rig.advance(599);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_done(&rig, id);

        let id = rig.submit(Command::WipeYubiAuth);
        rig.advance(10);
        rig.inject("Error not in config mode");
        assert_eq!(err(&rig, id), DeviceError::ConfigModeForOperation);
    }

    // --- PINs ------------------------------------------------------------------------------

    /// Classic PIN setup: empty OKSETPIN / PIN2 / SDPIN; prompt and commit each wait for their text.
    #[test]
    fn classic_pin_prompt_and_commit() {
        let mut rig = classic();
        clear(&mut rig);
        let pin = |which, phase| Command::ClassicPin { which, phase };
        for phase in [
            PinPhase::Prompt,
            PinPhase::Commit,
            PinPhase::Prompt,
            PinPhase::Commit,
        ] {
            let id = rig.submit(pin(PinKind::Primary, phase));
            assert_done(&rig, id);
        }
        let id = rig.submit(pin(PinKind::Second, PinPhase::Prompt));
        assert_done(&rig, id);
        // Firmware words the self-destruct prompt differently.
        let id = rig.submit(pin(PinKind::SelfDestruct, PinPhase::Prompt));
        assert_done(&rig, id);
        let ids: Vec<u8> = rig.written.iter().map(|(_, p)| p[4]).collect();
        assert_eq!(ids, [0xE1, 0xE1, 0xE1, 0xE1, 0xE3, 0xE2]);
        assert!(
            rig.written
                .iter()
                .all(|(_, p)| p[5..].iter().all(|&b| b == 0))
        );
        assert_eq!(
            messages(&rig).last(),
            Some(&"OnlyKey is ready, enter your self-destruct PIN")
        );
    }

    /// A PIN step ignores other text and waits up to 300 s for the user at the keypad.
    #[test]
    fn classic_pin_waits_for_the_keypad() {
        let mut rig = silent_classic();
        let pin = |phase| Command::ClassicPin {
            which: PinKind::Primary,
            phase,
        };
        let prompt = rig.submit(pin(PinPhase::Prompt));
        rig.inject("Successful PIN entry");
        assert_eq!(rig.reply(prompt), None);
        rig.inject("OnlyKey is ready, re-enter your PIN to confirm");
        assert_done(&rig, prompt);

        let commit = rig.submit(pin(PinPhase::Commit));
        rig.inject("OnlyKey is ready, enter your PIN");
        rig.advance(299_999);
        assert_eq!(rig.reply(commit), None);
        rig.advance(1);
        assert_eq!(
            err(&rig, commit),
            DeviceError::timeout(MessageId::OkSetPin, 300_000)
        );
    }

    /// Cancel aborts the waiting PIN step, sends one empty packet to flush the keypad state
    /// machine (1500 ms, silence is fine) and reports "Canceled".
    #[test]
    fn classic_pin_cancel_flush() {
        let mut rig = silent_classic();
        clear(&mut rig);
        let prompt = rig.submit(Command::ClassicPin {
            which: PinKind::SelfDestruct,
            phase: PinPhase::Prompt,
        });
        rig.advance(20);
        let cancel = rig.submit(Command::CancelClassicPin {
            which: PinKind::SelfDestruct,
        });
        assert_eq!(err(&rig, prompt), DeviceError::PinEntryCancelled);
        assert_eq!(err(&rig, prompt).to_string(), "PIN entry cancelled");
        assert_eq!(times(&rig, MessageId::OkSetSdPin), [1_000, 1_020]);
        rig.advance(1_499);
        assert_eq!(rig.reply(cancel), None);
        rig.advance(1);
        assert_done(&rig, cancel);
        assert_eq!(messages(&rig), [PIN_ENTRY_CANCELED_MESSAGE]);
    }

    /// The keypad chatter caused by the flush is hidden; the user just sees "Canceled".
    #[test]
    fn classic_pin_cancel_hides_flush_noise() {
        let mut rig = classic();
        clear(&mut rig);
        let prompt = rig.submit(Command::ClassicPin {
            which: PinKind::Primary,
            phase: PinPhase::Prompt,
        });
        assert_done(&rig, prompt);
        let cancel = rig.submit(Command::CancelClassicPin {
            which: PinKind::Primary,
        });
        assert_done(&rig, cancel);
        assert_eq!(
            messages(&rig),
            ["OnlyKey is ready, enter your PIN", "Canceled"]
        );
        // Suppression ends with the flush.
        rig.inject("Error PIN is not between 7 - 10 digits");
        assert_eq!(errors(&rig), ["Error PIN is not between 7 - 10 digits"]);
        for noise in [
            "Error PINs Don't Match",
            "error pins dont match",
            "Re-enter your PIN",
            "Successfully set PIN",
        ] {
            assert!(is_pin_flush_noise(noise), "{noise}");
        }
        assert!(!is_pin_flush_noise("UNLOCKEDv2.1.0-prod"));
    }

    /// A cancel with no device is a no-op, not an error.
    #[test]
    fn classic_pin_cancel_while_disconnected() {
        let mut rig = MockRig::new(MockDevice::new(MockKind::Classic));
        let id = rig.submit(Command::CancelClassicPin {
            which: PinKind::Primary,
        });
        assert_done(&rig, id);
        assert!(rig.events.is_empty() && rig.written.is_empty());
    }

    /// DUO setup payload: `[0xFF][primary @6][second @22][self-destruct @38]`, ASCII digits, zero-padded.
    #[test]
    fn duo_pin_setup_payload_layout() {
        let mut rig = rig(MockDevice::new(MockKind::Duo).unlocked());
        clear(&mut rig);
        let pins = |primary: &str, second: Option<&str>, sd: Option<&str>| Command::DuoPin {
            pins: DuoPins {
                primary: primary.to_string(),
                second: second.map(str::to_string),
                self_destruct: sd.map(str::to_string),
            },
            setup: true,
        };
        let id = rig.submit(pins("3253614", None, Some("6543216")));
        assert_done(&rig, id);
        let packet = rig.written[0].1;
        assert_eq!(packet[4..6], [0xE1, 0xFF]);
        assert_eq!(&packet[6..13], b"3253614");
        assert_eq!(packet[13..38], [0; 25]);
        assert_eq!(&packet[38..45], b"6543216");
        assert_eq!(packet[45..54], [0; 9]);

        let id = rig.submit(pins("1234561", Some("6543216123"), None));
        assert_done(&rig, id);
        let packet = rig.written[1].1;
        assert_eq!(&packet[22..32], b"6543216123");
        assert_eq!(packet[32..54], [0; 22]);
    }

    /// DUO setup PINs must be 7–10 digits of 1–6, and the self-destruct PIN must differ.
    #[test]
    fn duo_pin_setup_validation() {
        let mut rig = rig(MockDevice::new(MockKind::Duo).unlocked());
        clear(&mut rig);
        let digits = "Device PIN must be 7–10 digits using only 1–6.";
        let cases = [
            ("123", None, None, digits),
            ("1234568", None, None, digits),
            ("12345612345", None, None, digits),
            (
                "3253614",
                None,
                Some("3253614"),
                "Self-destruct PIN must be different from the device PIN.",
            ),
            (
                "3253614",
                None,
                Some("12"),
                "Self-destruct PIN must be 7–10 digits using only 1–6.",
            ),
            (
                "3253614",
                Some("7777777"),
                None,
                "Second profile PIN must be 7–10 digits using only 1–6.",
            ),
        ];
        for (primary, second, sd, message) in cases {
            let pins = DuoPins {
                primary: primary.to_string(),
                second: second.map(str::to_string),
                self_destruct: sd.map(str::to_string),
            };
            let id = rig.submit(Command::DuoPin { pins, setup: true });
            assert_eq!(err(&rig, id), invalid(message));
        }
        assert!(rig.written.is_empty());
    }

    /// DUO unlock: bare ASCII digits; INITIALIZED-D back means the PIN was wrong.
    #[test]
    fn duo_pin_unlock_incorrect() {
        let mut device = MockDevice::new(MockKind::Duo);
        device.correct_pin = "3253614".to_string();
        let mut rig = rig(device);
        clear(&mut rig);
        let unlock = |pin: &str| Command::DuoPin {
            pins: DuoPins {
                primary: pin.to_string(),
                ..DuoPins::default()
            },
            setup: false,
        };
        let id = rig.submit(unlock("1111111"));
        assert_eq!(err(&rig, id), DeviceError::IncorrectPin);
        assert_eq!(errors(&rig), ["Incorrect PIN"]);
        assert_eq!(&rig.written[0].1[4..13], b"\xE11111111\0");
        assert_eq!(rig.snapshot().state, DeviceState::Locked);

        let id = rig.submit(unlock("3253614"));
        assert_done(&rig, id);
        assert_eq!(rig.written[1].1[5], b'3');
        assert_eq!(
            (rig.snapshot().state, rig.snapshot().kind),
            (DeviceState::Unlocked, DeviceKind::Duo)
        );
    }

    /// DUO unlock: too many wrong PINs ends the session's attempts.
    #[test]
    fn duo_pin_unlock_attempts_exceeded() {
        let mut device = MockDevice::new(MockKind::Duo);
        device.correct_pin = "3253614".to_string();
        device.max_pin_attempts = 1;
        let mut rig = rig(device);
        clear(&mut rig);
        let pins = DuoPins {
            primary: "1111111".to_string(),
            ..DuoPins::default()
        };
        let id = rig.submit(Command::DuoPin { pins, setup: false });
        assert_eq!(err(&rig, id), DeviceError::AttemptsExceeded);
        assert_eq!(
            err(&rig, id).to_string(),
            "Error password attempts for this session exceeded"
        );
        assert_eq!(
            errors(&rig),
            ["Error password attempts for this session exceeded"]
        );

        // Firmware that words it as plain text, not an "Error …" reply.
        rig.device.silent = true;
        let pins = DuoPins {
            primary: "1111111".to_string(),
            ..DuoPins::default()
        };
        let id = rig.submit(Command::DuoPin { pins, setup: false });
        rig.inject("Too many password attempts");
        assert_eq!(err(&rig, id), DeviceError::AttemptsExceeded);
    }

    // --- chunked writes --------------------------------------------------------------------

    /// OKSETPRIV: 57-byte chunks, each repeating slot and type; intermediates get a 200 ms
    /// error window and a 30 ms gap; only the final chunk waits for a reply.
    #[test]
    fn set_private_key_chunking() {
        let mut rig = classic();
        clear(&mut rig);
        let bytes: Vec<u8> = (1..=120).collect();
        let id = rig.submit(Command::SetPrivateKey {
            slot: 101,
            key_type: 0x61,
            bytes: bytes.clone(),
        });
        rig.advance(459);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_done(&rig, id);
        let packets = rig.written_of(MessageId::OkSetPriv);
        assert_eq!(times(&rig, MessageId::OkSetPriv), [1_000, 1_230, 1_460]);
        for (i, (_, packet)) in packets.iter().enumerate() {
            assert_eq!(packet[4..7], [0xEF, 101, 0x61]);
            let chunk = &bytes[i * 57..bytes.len().min((i + 1) * 57)];
            assert_eq!(&packet[7..7 + chunk.len()], chunk);
        }
        assert_eq!(packets[2].1[13..], [0; 51]);
    }

    /// OKSETPRIV edge cases: exactly one chunk, no bytes at all, an error on an intermediate chunk.
    #[test]
    fn set_private_key_edges() {
        let mut rig = classic();
        clear(&mut rig);
        let key = |bytes: Vec<u8>| Command::SetPrivateKey {
            slot: 1,
            key_type: 2,
            bytes,
        };
        let id = rig.submit(key(vec![9; 57]));
        assert_done(&rig, id);
        assert_eq!(rig.written.len(), 1);
        let id = rig.submit(key(Vec::new()));
        assert_done(&rig, id);
        assert_eq!(rig.written.len(), 1);

        rig.device.require_config_mode = true;
        let id = rig.submit(key(vec![9; 58]));
        assert_eq!(err(&rig, id), DeviceError::ConfigModeForOperation);
        assert_eq!(rig.written.len(), 2);
    }

    /// OKRESTORE: slot byte 0xFF while more follow, then the last chunk's length; no field byte;
    /// progress 0 → ≤92 while sending, 95 at the final chunk, 100 once applied.
    #[test]
    fn restore_chunking_and_progress() {
        let mut rig = classic();
        clear(&mut rig);
        let payload: Vec<u8> = (1..=120).collect();
        let id = rig.submit(Command::Restore {
            payload: payload.clone(),
        });
        assert_eq!(progress(&rig), [0]);
        rig.advance(460);
        assert_done(&rig, id);
        let packets = rig.written_of(MessageId::OkRestore);
        assert_eq!(times(&rig, MessageId::OkRestore), [1_000, 1_230, 1_460]);
        assert_eq!(
            packets.iter().map(|(_, p)| p[5]).collect::<Vec<_>>(),
            [0xFF, 0xFF, 6]
        );
        assert_eq!(packets[0].1[6..63], payload[..57]);
        assert_eq!(packets[2].1[6..12], payload[114..]);
        assert_eq!(progress(&rig), [0, 31, 61, 92, 95, 100]);
        let texts: Vec<&str> = rig
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Progress { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(texts[1], "Sending backup to OnlyKey… 31%");
        assert_eq!(texts[4], "Applying backup on OnlyKey…");
        assert_eq!(texts[5], "Restore complete — remove and reinsert OnlyKey");
    }

    /// The final OKRESTORE chunk waits up to 120 s for the device to apply the backup.
    #[test]
    fn restore_final_wait() {
        let mut rig = silent_classic();
        clear(&mut rig);
        let id = rig.submit(Command::Restore {
            payload: vec![1, 2, 3, 4],
        });
        assert_eq!(rig.written[0].1[4..10], [0xF1, 4, 1, 2, 3, 4]);
        assert_eq!(progress(&rig), [0, 92, 95]);
        rig.inject("OK");
        rig.advance(119_999);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_eq!(
            err(&rig, id),
            DeviceError::timeout(MessageId::OkRestore, 120_000)
        );

        let id = rig.submit(Command::Restore { payload: vec![1] });
        rig.inject("Remove and Reinsert OnlyKey to complete restore");
        assert_done(&rig, id);
    }

    /// Restore failures: empty data, a refusal on an intermediate or final chunk, "error" in
    /// plain text, and an unplug (never a success).
    #[test]
    fn restore_failures() {
        let mut device = MockDevice::new(MockKind::Classic).unlocked();
        device.require_config_mode = true;
        let mut rig = rig(device);
        let id = rig.submit(Command::Restore {
            payload: Vec::new(),
        });
        assert_eq!(err(&rig, id), invalid("Backup data is empty."));
        for len in [4, 60] {
            let id = rig.submit(Command::Restore {
                payload: vec![0xAA; len],
            });
            assert_eq!(err(&rig, id), DeviceError::ConfigModeForOperation);
        }

        rig.device.silent = true;
        let id = rig.submit(Command::Restore { payload: vec![1] });
        rig.inject("Backup error: bad key");
        assert_eq!(
            err(&rig, id),
            DeviceError::Device {
                message: "Backup error: bad key".to_string()
            }
        );
        let id = rig.submit(Command::Restore { payload: vec![1] });
        rig.unplug();
        assert_eq!(err(&rig, id), Disconnected);
        assert_ne!(progress(&rig).last(), Some(&100));
    }

    // --- firmware --------------------------------------------------------------------------

    /// `TriggerBootloader`: OKFWUPDATE with data 01 02 03 04 and no slot byte.
    #[test]
    fn trigger_bootloader() {
        let mut rig = classic();
        clear(&mut rig);
        let id = rig.submit(Command::TriggerBootloader);
        assert_done(&rig, id);
        assert_eq!(rig.written[0].1[4..10], [0xF4, 1, 2, 3, 4, 0]);
    }

    /// Firmware apply outside the bootloader: trigger the reboot and hold the blocks; when the
    /// device comes back with the bootloader PID, stream them with progress per block.
    #[test]
    fn firmware_trigger_then_stream_on_bootloader_reconnect() {
        let mut rig = classic();
        clear(&mut rig);
        let blocks = vec![vec![0xAA, 0xBB, 0xCC, 0xDD], vec![0xAB; 58]];
        let id = rig.submit(Command::LoadFirmware { blocks });
        assert_eq!(rig.reply(id), Some(&Ok(Reply::FirmwarePending)));
        assert_eq!(rig.written_of(MessageId::OkFwUpdate).len(), 1);
        assert!(progress(&rig).is_empty());

        rig.unplug();
        clear(&mut rig);
        rig.plug();
        assert_eq!(rig.snapshot().state, DeviceState::Bootloader);
        let packets = rig.written_of(MessageId::OkFwUpdate);
        // Block 1 in one final chunk (slot = 4); block 2 as 57 bytes (0xFF) + 1 byte (slot = 1).
        assert_eq!(
            packets.iter().map(|(_, p)| p[5]).collect::<Vec<_>>(),
            [4, 0xFF, 1]
        );
        assert_eq!(packets[0].1[6..10], [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(packets[1].1[6..63], [0xAB; 57]);
        assert_eq!(rig.written.len(), 3);
        assert_eq!(progress(&rig), [0, 50, 100]);
        assert!(rig.events.contains(&Event::Progress {
            percent: 50,
            text: "Loading firmware… 50%".to_string()
        }));
        for text in [
            "RECEIVED OKFWUPDATE",
            "NEXT BLOCK",
            "SUCCESSFULLY LOADED FW",
        ] {
            assert!(messages(&rig).contains(&text), "{text}");
        }
        assert!(errors(&rig).is_empty());

        // The held blocks are used once.
        rig.unplug();
        clear(&mut rig);
        rig.plug();
        assert!(rig.written.is_empty());
    }

    /// Already in the bootloader: stream directly; `Done` means the last block was accepted.
    #[test]
    fn firmware_stream_in_bootloader() {
        let mut rig = rig(MockDevice::new(MockKind::Bootloader));
        clear(&mut rig);
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![0xDE, 0xAD, 0xBE, 0xEF]; 3],
        });
        assert_done(&rig, id);
        assert_eq!(
            rig.written_of(MessageId::OkFwUpdate)
                .iter()
                .map(|(_, p)| p[5])
                .collect::<Vec<_>>(),
            [4, 4, 4]
        );
        assert_eq!(progress(&rig), [0, 33, 67, 100]);

        let id = rig.submit(Command::LoadFirmware { blocks: Vec::new() });
        assert_eq!(err(&rig, id), invalid("Could not parse firmware file."));
    }

    /// Each firmware wait takes only its own acknowledgement: RECEIVED for a 0xFF chunk, NEXT
    /// BLOCK between blocks, SUCCESSFULLY LOADED FW at the end; "error" text aborts.
    #[test]
    fn firmware_acknowledgements() {
        let mut rig = rig(MockDevice::new(MockKind::Bootloader));
        rig.device.silent = true;
        clear(&mut rig);
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 58], vec![2; 4]],
        });
        let flags = |rig: &MockRig| rig.written.iter().map(|(_, p)| p[5]).collect::<Vec<_>>();
        rig.inject("NEXT BLOCK");
        assert_eq!(flags(&rig), [0xFF]);
        rig.inject("RECEIVED OKFWUPDATE");
        assert_eq!(flags(&rig), [0xFF, 1]);
        rig.inject("RECEIVED OKFWUPDATE");
        rig.inject("SUCCESSFULLY LOADED FW");
        assert_eq!(flags(&rig), [0xFF, 1]);
        rig.inject("NEXT BLOCK");
        assert_eq!(flags(&rig), [0xFF, 1, 4]);
        rig.inject("NEXT BLOCK");
        assert_eq!(rig.reply(id), None);
        rig.inject("SUCCESSFULLY LOADED FW");
        assert_done(&rig, id);

        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        rig.inject("Signature error");
        assert_eq!(
            err(&rig, id),
            DeviceError::Device {
                message: "Signature error".to_string()
            }
        );
    }

    /// Firmware timeouts: 10 s for a 0xFF chunk, 20 s for the end of a block; an unplug is
    /// never taken for success.
    #[test]
    fn firmware_timeouts_and_unplug() {
        let mut rig = rig(MockDevice::new(MockKind::Bootloader));
        rig.device.silent = true;
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 58]],
        });
        rig.advance(10_000);
        assert_eq!(
            err(&rig, id),
            DeviceError::timeout(MessageId::OkFwUpdate, 10_000)
        );
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        rig.advance(19_999);
        assert_eq!(rig.reply(id), None);
        rig.advance(1);
        assert_eq!(
            err(&rig, id),
            DeviceError::timeout(MessageId::OkFwUpdate, 20_000)
        );
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        rig.unplug();
        assert_eq!(err(&rig, id), Disconnected);
    }

    /// A failed trigger holds nothing; a failed resumed stream is reported as an error event.
    #[test]
    fn firmware_trigger_and_resume_failures() {
        let mut rig = silent_classic();
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        rig.advance(10_000);
        assert_eq!(
            err(&rig, id),
            DeviceError::timeout(MessageId::OkFwUpdate, 10_000)
        );
        rig.unplug();
        rig.device = MockDevice::new(MockKind::Bootloader);
        clear(&mut rig);
        rig.plug();
        assert!(rig.written.is_empty());

        let mut rig = classic();
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        assert_eq!(rig.reply(id), Some(&Ok(Reply::FirmwarePending)));
        rig.unplug();
        rig.device.silent = true;
        clear(&mut rig);
        rig.plug();
        assert_eq!(rig.written.len(), 1);
        rig.advance(20_000);
        assert_eq!(errors(&rig), ["Request OKFWUPDATE timed out after 20000ms"]);
        assert_eq!(progress(&rig), [0]);
    }

    /// Streaming directly in the bootloader drops blocks held from an earlier trigger, so they
    /// cannot reflash on a later bootloader connect.
    #[test]
    fn direct_stream_clears_held_firmware() {
        let mut rig = classic();
        let held = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        assert_eq!(rig.reply(held), Some(&Ok(Reply::FirmwarePending)));
        // Same handle, now reporting bootloader: the next apply streams directly.
        rig.inject("BOOTLOADER");
        let id = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![2; 4]],
        });
        assert_done(&rig, id);
        rig.unplug();
        clear(&mut rig);
        rig.plug();
        assert!(rig.written.is_empty());
    }

    /// Held blocks are dropped when the device reconnects in normal firmware instead of the bootloader.
    #[test]
    fn normal_reconnect_drops_held_firmware() {
        let mut rig = classic();
        let held = rig.submit(Command::LoadFirmware {
            blocks: vec![vec![1; 4]],
        });
        assert_eq!(rig.reply(held), Some(&Ok(Reply::FirmwarePending)));
        rig.unplug();
        rig.device = MockDevice::new(MockKind::Classic).unlocked();
        rig.plug();
        rig.advance(5_000);
        rig.unplug();
        rig.device = MockDevice::new(MockKind::Bootloader);
        clear(&mut rig);
        rig.plug();
        assert!(rig.written.is_empty());
    }

    /// Packets are never printed: they can carry PINs and key bytes.
    #[test]
    fn output_debug_redacts_packets() {
        let packet = frame(MessageId::OkSetPin, None, None, b"1234567");
        assert_eq!(format!("{:?}", Output::Write(packet)), "Write(msg 0xe1)");
    }
}
