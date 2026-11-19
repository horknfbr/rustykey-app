//! HID driver thread: owns the device handle and the sans-IO [`Engine`], and serves commands.
//!
//! One std thread runs [`run`]: read (≤ 20 ms, less if the engine has a sooner deadline) →
//! `on_report`; drain the command channel → `submit`; `on_tick` when due; then act on every
//! engine output (write packets, answer callers, fan events out). While disconnected it rescans
//! every 2 s. Only state transitions are logged, never commands, reports or replies.

pub mod hid;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod select;

use onlykey_core::api::{Command, DeviceError, DeviceState, Event, Reply, Snapshot};
use onlykey_core::engine::{Engine, Millis, Output, RequestId};
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;

/// Longest single read; bounds how long a queued command waits.
const READ_MS: u64 = 20;
/// Unplug-looking errors this soon after opening are retried, not treated as an unplug
/// (TS `HID_RECONNECT_GRACE_MS`: a fresh handle can report a false "disconnected").
const RECONNECT_GRACE_MS: u64 = 400;
/// Pause before reading again after a read error that is not an unplug.
const READ_RETRY_MS: u64 = 100;
/// A write still running after this long means a hung handle: close it (TS `HID_SEND_TIMEOUT_MS`).
const WRITE_TIMEOUT_MS: u64 = 3_000;
/// Rescan interval while no device is open.
const RESCAN_MS: u64 = 2_000;
/// A connect that has not produced a status by now is torn down and retried.
const CONNECT_WATCHDOG_MS: u64 = 20_000;

/// An opened device: its USB product ID and handle.
pub type Opened = (u16, Box<dyn Link>);

/// Finds and opens a device: `Ok(None)` when none is plugged in.
pub trait Bus {
    /// Opens the device to use, returning its USB product ID and handle.
    fn open(&mut self) -> Result<Option<Opened>, String>;
}

/// An open device handle; errors are judged by [`is_gone_error`] (unplug) or retried.
pub trait Link {
    /// One 64-byte input report, or `None` after `timeout_ms` of silence.
    fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String>;
    /// Sends one 64-byte output report.
    fn write(&mut self, packet: &[u8; 64]) -> Result<(), String>;
    /// True when a write has been running for [`WRITE_TIMEOUT_MS`] or more (hung handle).
    fn write_stuck(&self) -> bool {
        false
    }
}

/// Result of one command.
type Answer = Result<Reply, DeviceError>;
/// A command plus where its answer goes.
type Request = (Command, oneshot::Sender<Answer>);

/// State shared between the driver thread and its callers.
#[derive(Default)]
struct Shared {
    /// Last snapshot the engine published.
    snapshot: Mutex<Snapshot>,
    /// In-process event subscribers (tray); dropped receivers are pruned on send.
    subscribers: Mutex<Vec<Sender<Event>>>,
}

/// Handle to the driver thread; kept in Tauri managed state.
pub struct DeviceService {
    /// Command channel into the thread.
    tx: Sender<Request>,
    /// Snapshot and subscribers.
    shared: Arc<Shared>,
}

impl DeviceService {
    /// Starts the driver thread over the bus `make_bus` builds (on that thread); `sink` gets
    /// every event (the webview). The thread ends when the service is dropped.
    pub fn spawn(
        make_bus: impl FnOnce() -> Box<dyn Bus> + Send + 'static,
        sink: impl Fn(&Event) + Send + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Shared::default());
        let thread_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("rustykey-hid".into())
            .spawn(move || run(make_bus(), &rx, &thread_shared, &sink))
            .expect("spawn HID thread");
        Self { tx, shared }
    }

    /// Runs one command on the device.
    pub async fn send(&self, cmd: Command) -> Answer {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send((cmd, tx))
            .map_err(|_| DeviceError::Disconnected)?;
        rx.await.unwrap_or(Err(DeviceError::Disconnected))
    }

    /// The current device snapshot.
    pub fn snapshot(&self) -> Snapshot {
        lock(&self.shared.snapshot).clone()
    }

    /// A receiver of every future event (for the tray status line).
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = mpsc::channel();
        lock(&self.shared.subscribers).push(tx);
        rx
    }
}

/// Locks, ignoring poisoning (the data is plain state).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Wall-clock Unix ms now.
fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// True for open failures that point at missing OS permissions (udev rule, Input Monitoring).
fn is_permission_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "cannot open device",
        "access denied",
        "permission",
        "failed to open",
        "unable to connect",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// True for read/write error text that means the device is gone. The TS words ("disconnected",
/// "not found", "invalid connection") plus hidapi's: Linux/macOS "No such device" (ENODEV) and
/// Windows "The device is not connected." (ERROR_DEVICE_NOT_CONNECTED). hidapi's own unplug texts
/// ("hid_read_timeout: device disconnected", "Device is disconnected") hit the first word.
fn is_gone_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "disconnected",
        "not found",
        "invalid connection",
        "no such device",
        "not connected",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// True when an error `ms_since_open` after opening is an unplug: a gone error past the grace.
fn is_unplug(text: &str, ms_since_open: Millis) -> bool {
    is_gone_error(text) && ms_since_open >= RECONNECT_GRACE_MS
}

/// Driver-loop state: everything the thread owns.
struct Driver<'a> {
    /// Protocol engine.
    engine: Engine,
    /// Monotonic origin of [`Millis`].
    start: Instant,
    /// Open handle, if any.
    link: Option<Box<dyn Link>>,
    /// Callers waiting for a reply.
    waiting: HashMap<RequestId, oneshot::Sender<Answer>>,
    /// When to scan next while disconnected.
    next_scan: Millis,
    /// When the current handle was opened, until its first status.
    connecting_since: Option<Millis>,
    /// When the current handle was opened (reconnect grace).
    opened_at: Millis,
    /// No reads before this time (pause after a transient read error).
    read_retry_at: Millis,
    /// Last transient I/O error, so a repeating one is logged once.
    last_io_error: Option<String>,
    /// Last open error, so a repeating one is logged once.
    last_open_error: Option<String>,
    /// Last state logged.
    last_state: DeviceState,
    /// Snapshot and subscribers.
    shared: &'a Shared,
    /// Webview event sink.
    sink: &'a dyn Fn(&Event),
}

/// The driver thread body; returns when every [`DeviceService`] handle is gone.
fn run(mut bus: Box<dyn Bus>, rx: &Receiver<Request>, shared: &Shared, sink: &dyn Fn(&Event)) {
    let start = Instant::now();
    let mut d = Driver {
        engine: Engine::new(unix_now_ms()),
        start,
        link: None,
        waiting: HashMap::new(),
        next_scan: 0,
        connecting_since: None,
        opened_at: 0,
        read_retry_at: 0,
        last_io_error: None,
        last_open_error: None,
        last_state: DeviceState::Disconnected,
        shared,
        sink,
    };
    loop {
        if d.link.is_none() && d.now() >= d.next_scan {
            d.scan(bus.as_mut());
        }
        let now = d.now();
        let until_deadline = d.engine.next_deadline().map(|t| t.saturating_sub(now));
        if let Some(link) = d.link.as_mut().filter(|_| now >= d.read_retry_at) {
            let timeout = until_deadline.map_or(READ_MS, |t| t.min(READ_MS));
            match link.read(timeout) {
                Ok(Some(report)) => d.engine.on_report(&report, d.now()),
                Ok(None) => {}
                Err(e) => d.io_error(&e),
            }
            if d.link.as_ref().is_some_and(|l| l.write_stuck()) {
                d.close("write timed out");
            }
            loop {
                match rx.try_recv() {
                    Ok(req) => d.submit(req),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        } else {
            // Nothing to read (no handle, or pausing after a read error): sleep on the command
            // channel until the next scan, read retry or deadline.
            let until = if d.link.is_some() {
                d.read_retry_at
            } else {
                d.next_scan
            };
            let wait = until.saturating_sub(now);
            let wait = until_deadline.map_or(wait, |t| t.min(wait));
            match rx.recv_timeout(Duration::from_millis(wait)) {
                Ok(req) => d.submit(req),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        if d.engine.next_deadline().is_some_and(|t| t <= d.now()) {
            d.engine.on_tick(d.now());
        }
        d.watchdog();
        d.drain();
        if d.link.is_some() && !d.engine.is_connected() {
            // The engine gave up on the connect probe: close and rescan.
            d.close("connect probe failed");
        }
    }
}

impl Driver<'_> {
    /// Milliseconds since the driver started.
    fn now(&self) -> Millis {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Looks for a device and opens it; permission-like failures reach the UI as `connect_error`.
    fn scan(&mut self, bus: &mut dyn Bus) {
        self.next_scan = self.now() + RESCAN_MS;
        match bus.open() {
            Ok(Some((pid, link))) => {
                eprintln!("device: opened {pid:04x}");
                self.last_open_error = None;
                self.link = Some(link);
                let now = self.now();
                self.engine
                    .set_unix_origin(unix_now_ms().saturating_sub(now));
                if self.engine.snapshot().connect_error.is_some() {
                    self.engine.set_connect_error(None);
                }
                self.engine.on_connected(pid, now);
                self.connecting_since = Some(now);
                self.opened_at = now;
                self.read_retry_at = 0;
                self.last_io_error = None;
            }
            Ok(None) => self.last_open_error = None,
            Err(text) => {
                if self.last_open_error.as_ref() != Some(&text) {
                    eprintln!("device: open failed: {text}");
                }
                let shown = is_permission_error(&text).then(|| text.clone());
                if self.engine.snapshot().connect_error != shown {
                    self.engine.set_connect_error(shown);
                }
                self.last_open_error = Some(text);
            }
        }
    }

    /// Queues a command and remembers who is waiting for it.
    fn submit(&mut self, (cmd, reply): Request) {
        let id = self.engine.submit(cmd, self.now());
        self.waiting.insert(id, reply);
    }

    /// A read or write failed: an unplug (see [`is_unplug`]) closes the handle; anything else
    /// keeps it and pauses reads for [`READ_RETRY_MS`] (TS `ChromeHidTransport` receive/send).
    fn io_error(&mut self, text: &str) {
        if is_unplug(text, self.now().saturating_sub(self.opened_at)) {
            self.close(text);
            return;
        }
        if self.last_io_error.as_deref() != Some(text) {
            eprintln!("device: I/O error, retrying: {text}");
            self.last_io_error = Some(text.to_string());
        }
        self.read_retry_at = self.now() + READ_RETRY_MS;
    }

    /// Closes the handle; the engine wipes the session if it was using it.
    fn close(&mut self, reason: &str) {
        if self.link.take().is_some() {
            eprintln!("device: closed ({reason})");
        }
        self.connecting_since = None;
        self.engine.on_disconnected(self.now());
        self.next_scan = self.now() + RESCAN_MS;
    }

    /// Tears down a connect that never produced a status (hung handle).
    fn watchdog(&mut self) {
        if self.engine.snapshot().state != DeviceState::Disconnected {
            self.connecting_since = None;
        }
        if self
            .connecting_since
            .is_some_and(|t| self.now() >= t + CONNECT_WATCHDOG_MS)
        {
            self.close("connect watchdog");
        }
    }

    /// Acts on every pending engine output.
    fn drain(&mut self) {
        while let Some(output) = self.engine.poll_output() {
            match output {
                Output::Write(packet) => {
                    // With no handle the engine has already failed the work; drop the packet. A
                    // failed write that is not an unplug drops it too (the command times out).
                    let result = self.link.as_mut().map(|link| link.write(&packet));
                    if let Some(Err(e)) = result {
                        self.io_error(&e);
                    }
                }
                Output::Reply(id, answer) => {
                    if let Some(tx) = self.waiting.remove(&id) {
                        let _ = tx.send(answer);
                    }
                }
                Output::Event(event) => self.publish(&event),
            }
        }
    }

    /// Records snapshots and sends `event` to the webview and every subscriber.
    fn publish(&mut self, event: &Event) {
        if let Event::Snapshot(snap) = event {
            if snap.state != self.last_state {
                eprintln!("device: {:?} -> {:?}", self.last_state, snap.state);
                self.last_state = snap.state;
            }
            *lock(&self.shared.snapshot) = snap.clone();
        }
        (self.sink)(event);
        lock(&self.shared.subscribers).retain(|tx| tx.send(event.clone()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    //! Driver loop against the simulated device, plus the permission heuristic.

    use super::mock::{MockBus, MockLink};
    use super::*;
    use onlykey_core::api::DeviceKind;
    use onlykey_core::transport::{MockDevice, MockKind};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Polls `cond` for up to 3 s.
    fn wait_for(cond: impl Fn() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Permission-looking open errors are recognised; "not found" is not.
    #[test]
    fn permission_heuristic() {
        assert!(is_permission_error(
            "hidapi error: Failed to open a device with path '/dev/hidraw3': Permission denied"
        ));
        assert!(is_permission_error("Access denied"));
        assert!(!is_permission_error("Device not found"));
    }

    /// Unplug texts from the TS app and from hidapi on each OS are recognised; others are not.
    #[test]
    fn gone_error_classification() {
        for gone in [
            "Device disconnected",
            "Device not found",
            "Invalid connection id",
            "hidapi error: hid_read_timeout: device disconnected",
            "hidapi error: Device is disconnected",
            "hidapi error: hid_read_timeout: unexpected poll error (device disconnected)",
            "hidapi error: No such device",
            "The device is not connected. (os error 1167)",
        ] {
            assert!(is_gone_error(gone), "{gone}");
        }
        for transient in [
            "hidapi error: hid_read_timeout: error waiting for more data",
            "hidapi error: Input/output error",
            "WinError: WaitTimedOut",
            "Transfer failed",
        ] {
            assert!(!is_gone_error(transient), "{transient}");
        }
    }

    /// A gone error inside the 400 ms reconnect grace is retried; after it, it is an unplug.
    #[test]
    fn reconnect_grace() {
        assert!(!is_unplug("device disconnected", 0));
        assert!(!is_unplug("device disconnected", RECONNECT_GRACE_MS - 1));
        assert!(is_unplug("device disconnected", RECONNECT_GRACE_MS));
        assert!(!is_unplug(
            "error waiting for more data",
            10 * RECONNECT_GRACE_MS
        ));
    }

    /// Link scripted by the test: transient read errors, an early false unplug, or a hung write.
    struct FlakyLink {
        /// The simulated device behind the faults.
        inner: MockLink,
        /// Errors to return from the next reads, in order.
        read_errors: VecDeque<&'static str>,
        /// Report a hung write once this flag is set.
        stuck: Arc<AtomicBool>,
    }

    impl Link for FlakyLink {
        /// The next scripted error, else the mock's report.
        fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String> {
            match self.read_errors.pop_front() {
                Some(e) => Err(e.into()),
                None => self.inner.read(timeout_ms),
            }
        }

        /// Writes to the mock.
        fn write(&mut self, packet: &[u8; 64]) -> Result<(), String> {
            self.inner.write(packet)
        }

        /// Hung once the test says so.
        fn write_stuck(&self) -> bool {
            self.stuck.load(Ordering::SeqCst)
        }
    }

    /// Bus that opens one [`FlakyLink`] (then nothing), so a close stays closed.
    struct FlakyBus(Option<FlakyLink>);

    impl Bus for FlakyBus {
        /// Hands out the link once.
        fn open(&mut self) -> Result<Option<Opened>, String> {
            Ok(self
                .0
                .take()
                .map(|l| (0x60FC, Box::new(l) as Box<dyn Link>)))
        }
    }

    /// Spawns a driver over a Classic [`FlakyLink`] with `read_errors`; returns it and the stuck flag.
    fn flaky(read_errors: &[&'static str]) -> (DeviceService, Arc<AtomicBool>) {
        let device = MockDevice::new(MockKind::Classic);
        let pending = [device.connect_report()].into();
        let stuck = Arc::new(AtomicBool::new(false));
        let link = FlakyLink {
            inner: MockLink { device, pending },
            read_errors: read_errors.iter().copied().collect(),
            stuck: Arc::clone(&stuck),
        };
        let svc = DeviceService::spawn(move || Box::new(FlakyBus(Some(link))), |_| {});
        (svc, stuck)
    }

    /// Transient read errors and a false unplug right after open keep the device connected.
    #[test]
    fn transient_errors_keep_device() {
        let (svc, _) = flaky(&[
            "device disconnected",
            "error waiting for more data",
            "Transfer failed",
        ]);
        assert!(wait_for(|| svc.snapshot().state == DeviceState::Locked));
        let answer = tauri::async_runtime::block_on(svc.send(Command::SetTime));
        assert_eq!(answer, Ok(Reply::Done));
        assert_eq!(svc.snapshot().state, DeviceState::Locked);
    }

    /// A write that never finishes closes the device.
    #[test]
    fn hung_write_disconnects() {
        let (svc, stuck) = flaky(&[]);
        assert!(wait_for(|| svc.snapshot().state == DeviceState::Locked));
        stuck.store(true, Ordering::SeqCst);
        assert!(wait_for(
            || svc.snapshot().state == DeviceState::Disconnected
        ));
    }

    /// A DUO connects, reports locked, answers a command, and reaches subscribers.
    #[test]
    fn mock_duo_connects_and_answers() {
        let svc = DeviceService::spawn(|| Box::new(MockBus(MockKind::Duo)), |_| {});
        let events = svc.subscribe();
        assert!(wait_for(|| svc.snapshot().state == DeviceState::Locked));
        let snap = svc.snapshot();
        assert_eq!(snap.kind, DeviceKind::Duo);
        assert_eq!(snap.product_name, "OnlyKey Duo");
        let answer = tauri::async_runtime::block_on(svc.send(Command::SetTime));
        assert_eq!(answer, Ok(Reply::Done));
        assert!(events.try_iter().count() > 0);
    }

    /// Bus whose link starts failing once `plugged` goes false.
    struct UnplugBus(Arc<AtomicBool>);

    /// Mock link that errors after an unplug.
    struct UnplugLink(MockLink, Arc<AtomicBool>);

    impl Bus for UnplugBus {
        /// Opens a Classic while plugged.
        fn open(&mut self) -> Result<Option<Opened>, String> {
            if !self.0.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let device = MockDevice::new(MockKind::Classic);
            let pending = [device.connect_report()].into();
            let link = MockLink { device, pending };
            Ok(Some((
                0x60FC,
                Box::new(UnplugLink(link, Arc::clone(&self.0))),
            )))
        }
    }

    impl Link for UnplugLink {
        /// Reads from the mock, or fails like hidapi after an unplug.
        fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String> {
            if self.1.load(Ordering::SeqCst) {
                self.0.read(timeout_ms)
            } else {
                Err("device disconnected".into())
            }
        }

        /// Writes to the mock.
        fn write(&mut self, packet: &[u8; 64]) -> Result<(), String> {
            self.0.write(packet)
        }
    }

    /// A read error is an unplug: snapshot goes Disconnected and the session epoch bumps.
    #[test]
    fn read_error_disconnects() {
        let plugged = Arc::new(AtomicBool::new(true));
        let bus_flag = Arc::clone(&plugged);
        let svc = DeviceService::spawn(move || Box::new(UnplugBus(bus_flag)), |_| {});
        assert!(wait_for(|| svc.snapshot().state == DeviceState::Locked));
        let epoch = svc.snapshot().session_epoch;
        plugged.store(false, Ordering::SeqCst);
        assert!(wait_for(
            || svc.snapshot().state == DeviceState::Disconnected
        ));
        assert!(svc.snapshot().session_epoch > epoch);
        let answer = tauri::async_runtime::block_on(svc.send(Command::RefreshStatus));
        assert_eq!(answer, Err(DeviceError::Disconnected));
    }

    /// A permission failure on open shows as `connect_error`.
    #[test]
    fn permission_error_sets_connect_error() {
        /// Bus that always fails to open with a permission error.
        struct Denied;
        impl Bus for Denied {
            /// Fails like hidraw without a udev rule.
            fn open(&mut self) -> Result<Option<Opened>, String> {
                Err("Failed to open: Permission denied".into())
            }
        }
        let svc = DeviceService::spawn(|| Box::new(Denied), |_| {});
        assert!(wait_for(|| svc.snapshot().connect_error.is_some()));
    }
}
