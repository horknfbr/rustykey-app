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

/// An open device handle; any error means the device is gone.
pub trait Link {
    /// One 64-byte input report, or `None` after `timeout_ms` of silence.
    fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String>;
    /// Sends one 64-byte output report.
    fn write(&mut self, packet: &[u8; 64]) -> Result<(), String>;
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
    #[allow(dead_code, reason = "used by the tray (task 6)")]
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
        if let Some(link) = &mut d.link {
            let timeout = until_deadline.map_or(READ_MS, |t| t.min(READ_MS));
            match link.read(timeout) {
                Ok(Some(report)) => d.engine.on_report(&report, d.now()),
                Ok(None) => {}
                Err(e) => d.close(&e),
            }
            loop {
                match rx.try_recv() {
                    Ok(req) => d.submit(req),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
        } else {
            // Nothing to read: sleep on the command channel until the next scan or deadline.
            let wait = d.next_scan.saturating_sub(now);
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
                    // With no handle the engine has already failed the work; drop the packet.
                    let result = self.link.as_mut().map(|link| link.write(&packet));
                    if let Some(Err(e)) = result {
                        self.close(&e);
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
