//! Real devices through hidapi.

use super::select::{Candidate, select};
use super::{Bus, Link, Opened};
use hidapi::{HidApi, HidDevice};
use std::ffi::CString;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Enumerates and opens OnlyKeys; hidapi is created lazily so a failed init is retried.
#[derive(Default)]
pub struct HidBus {
    /// hidapi context, once it initialised.
    api: Option<HidApi>,
}

impl Bus for HidBus {
    /// Re-enumerates and opens the interface [`select`] picks.
    fn open(&mut self) -> Result<Option<Opened>, String> {
        let api = match &mut self.api {
            Some(api) => {
                api.refresh_devices().map_err(|e| e.to_string())?;
                api
            }
            None => self.api.insert(HidApi::new().map_err(|e| e.to_string())?),
        };
        let candidates = candidates(api);
        let Some(pick) = select(&candidates) else {
            return Ok(None);
        };
        let path = CString::new(pick.path.clone()).map_err(|e| e.to_string())?;
        let device = api.open_path(&path).map_err(|e| e.to_string())?;
        Ok(Some((pick.pid, Box::new(HidLink::spawn(device)?))))
    }
}

/// Every HID collection hidapi currently sees, as selection input.
pub fn candidates(api: &HidApi) -> Vec<Candidate> {
    api.device_list()
        .map(|d| Candidate {
            vid: d.vendor_id(),
            pid: d.product_id(),
            usage_page: d.usage_page(),
            usage: d.usage(),
            serial: d.serial_number().unwrap_or_default().to_string(),
            interface: d.interface_number(),
            path: d.path().to_string_lossy().into_owned(),
        })
        .collect()
}

/// How long the I/O thread waits for a report before checking for packets to write.
const IO_READ_MS: i32 = 10;
/// Pause of the I/O thread after a read error, so a failing handle does not spin.
const IO_RETRY: Duration = Duration::from_millis(super::READ_RETRY_MS);
/// [`super::WRITE_TIMEOUT_MS`] as a `Duration`.
const WRITE_TIMEOUT: Duration = Duration::from_millis(super::WRITE_TIMEOUT_MS);

/// A report or a read/write error text from the I/O thread.
type IoResult = Result<[u8; 64], String>;

/// An open OnlyKey interface. hidapi writes block with no timeout we can set (macOS
/// `IOHIDDeviceSetReport`, Linux hidraw `write`), so the device lives on its own I/O thread and
/// the driver loop only talks to channels: a hung write can never stall the loop or its watchdog,
/// it just shows up as [`Link::write_stuck`]. Non-blocking mode would not help: it only affects
/// reads. One thread does both reads and writes because `HidDevice` is `Send` but not `Sync`.
struct HidLink {
    /// Packets for the I/O thread to write, in order.
    packets: Sender<[u8; 64]>,
    /// Reports and errors from the I/O thread.
    reports: Receiver<IoResult>,
    /// When the write in progress started; `None` when no write is running.
    writing_since: Arc<Mutex<Option<Instant>>>,
}

impl HidLink {
    /// Moves `device` onto a new I/O thread.
    fn spawn(device: HidDevice) -> Result<Self, String> {
        let (packets, packet_rx) = mpsc::channel();
        let (report_tx, reports) = mpsc::channel();
        let writing_since = Arc::new(Mutex::new(None));
        let since = Arc::clone(&writing_since);
        std::thread::Builder::new()
            .name("rustykey-hid-io".into())
            .spawn(move || io_loop(&device, &packet_rx, &report_tx, &since))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            packets,
            reports,
            writing_since,
        })
    }
}

/// Locks, ignoring poisoning (the data is a timestamp).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// I/O thread body: writes queued packets (report ID 0 in front), otherwise reads with a short
/// timeout; forwards reports and errors. Ends when the [`HidLink`] is dropped.
// ponytail: a write that never returns keeps this thread and the OS handle alive until it does;
// the driver has already moved on. Upgrade path: none in hidapi (no write cancel).
fn io_loop(
    device: &HidDevice,
    packets: &Receiver<[u8; 64]>,
    reports: &Sender<IoResult>,
    writing_since: &Mutex<Option<Instant>>,
) {
    loop {
        match packets.try_recv() {
            Ok(packet) => {
                let mut buf = [0u8; 65];
                buf[1..].copy_from_slice(&packet);
                *lock(writing_since) = Some(Instant::now());
                let result = device.write(&buf);
                *lock(writing_since) = None;
                if let Err(e) = result
                    && reports.send(Err(e.to_string())).is_err()
                {
                    return;
                }
                continue;
            }
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }
        let mut report = [0u8; 64];
        let delivered = match device.read_timeout(&mut report, IO_READ_MS) {
            Ok(0) => true,
            Ok(_) => reports.send(Ok(report)).is_ok(),
            Err(e) => {
                let delivered = reports.send(Err(e.to_string())).is_ok();
                std::thread::sleep(IO_RETRY);
                delivered
            }
        };
        if !delivered {
            return;
        }
    }
}

impl Link for HidLink {
    /// Next report from the I/O thread (report ID 0 is not included, zero-padded to 64 bytes).
    fn read(&mut self, timeout_ms: u64) -> Result<Option<[u8; 64]>, String> {
        match self.reports.recv_timeout(Duration::from_millis(timeout_ms)) {
            Ok(Ok(report)) => Ok(Some(report)),
            Ok(Err(e)) => Err(e),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("device disconnected".into()),
        }
    }

    /// Queues one output report; a write failure arrives later through [`HidLink::read`].
    fn write(&mut self, packet: &[u8; 64]) -> Result<(), String> {
        self.packets
            .send(*packet)
            .map_err(|_| "device disconnected".to_string())
    }

    /// True once the running write has taken [`WRITE_TIMEOUT`].
    fn write_stuck(&self) -> bool {
        lock(&self.writing_since).is_some_and(|t| t.elapsed() >= WRITE_TIMEOUT)
    }
}
