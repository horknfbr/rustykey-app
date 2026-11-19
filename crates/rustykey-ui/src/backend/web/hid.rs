//! WebHID driver: runs one sans-IO [`Engine`] on the page's event loop (the desktop driver loop, JS-style).
//!
//! Inputs: `inputreport` events → `on_report`; [`send`] → `submit`; a `setTimeout` at
//! `next_deadline()` → `on_tick`; `navigator.hid` `connect`/`disconnect` events and a 2 s rescan
//! while disconnected → open + `on_connected` / `on_disconnected`. After every input, [`flush`]
//! acts on the engine's outputs and re-arms the timer. Only state transitions are logged.

use futures::channel::oneshot;
use futures::future::{Either, select};
use onlykey_core::api::{Command, DeviceError, DeviceState, Event, Reply, Snapshot};
use onlykey_core::engine::{Engine, Millis, Output, RequestId};
use onlykey_core::protocol::{BOOTLOADER_PRODUCT_ID, USB_IDS};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{
    Hid, HidConnectionEvent, HidDevice, HidDeviceFilter, HidDeviceRequestOptions,
    HidInputReportEvent,
};

/// Rescan interval while no device is open (`useDeviceStore.ts` connect poll).
const RESCAN_MS: i32 = 2_000;
/// A connect that has not produced a status by now is torn down and retried.
const CONNECT_WATCHDOG_MS: Millis = 20_000;
/// `HIDDevice.open()` that has not settled by now counts as failed (`HID_CONNECT_TIMEOUT_MS`).
const OPEN_TIMEOUT_MS: i32 = 4_000;
/// `HIDDevice.sendReport()` that has not settled by now counts as an unplug (`HID_SEND_TIMEOUT_MS`).
const SEND_TIMEOUT_MS: i32 = 3_000;
/// Usage page of the raw app interface on Beta 8+ firmware.
const BETA8_USAGE_PAGE: u16 = 0xFFAB;
/// Interfaces the app never talks to: keyboard (Generic Desktop), FIDO, debug serial.
const NON_APP_USAGE_PAGES: [u16; 3] = [0x01, 0xF1D0, 0xFFC9];
/// `connect_error` when the page has no `navigator.hid` (not Chrome, or not a secure context).
const NO_WEBHID: &str =
    "WebHID is not available in this browser. Open RustyKey in Chrome over https.";

/// Result of one command.
type Answer = Result<Reply, DeviceError>;

/// Everything the page-wide driver owns.
struct Driver {
    /// Protocol engine (one per page).
    engine: Engine,
    /// Set once the WebHID listeners and rescan are installed.
    started: bool,
    /// The opened device in use.
    device: Option<HidDevice>,
    /// `inputreport` handler of `device`; dropped on close.
    on_input: Option<Closure<dyn FnMut(HidInputReportEvent)>>,
    /// An enumerate/open is in flight (coalesces rescans and connect events).
    opening: bool,
    /// When the current device was opened, until its first status.
    connecting_since: Option<Millis>,
    /// Callers waiting for a reply.
    waiting: HashMap<RequestId, oneshot::Sender<Answer>>,
    /// UI event callbacks.
    listeners: Vec<Rc<dyn Fn(Event)>>,
    /// Packets not yet handed to `sendReport`, in order.
    writes: VecDeque<[u8; 64]>,
    /// A `sendReport` is in flight (writes go one at a time).
    writing: bool,
    /// Pending `setTimeout` for `next_deadline`.
    timer: Option<i32>,
    /// Last state logged.
    last_state: DeviceState,
}

thread_local! {
    /// The one driver of this page.
    static DRIVER: RefCell<Driver> = RefCell::new(Driver {
        engine: Engine::new(unix_now().saturating_sub(now())),
        started: false,
        device: None,
        on_input: None,
        opening: false,
        connecting_since: None,
        waiting: HashMap::new(),
        listeners: Vec::new(),
        writes: VecDeque::new(),
        writing: false,
        timer: None,
        last_state: DeviceState::Disconnected,
    });
    /// `setTimeout` callback for engine deadlines (created once, reused).
    static TICK: Closure<dyn Fn()> = Closure::new(on_timer);
}

/// Runs `f` on the driver (never call a UI listener inside: see [`flush`]).
fn with<R>(f: impl FnOnce(&mut Driver) -> R) -> R {
    DRIVER.with_borrow_mut(f)
}

/// Monotonic page time in ms (`performance.now()`).
fn now() -> Millis {
    let ms = web_sys::window()
        .and_then(|w| w.performance())
        .map_or(0.0, |p| p.now());
    ms.max(0.0) as Millis
}

/// Wall-clock Unix ms (`Date.now()`).
fn unix_now() -> u64 {
    js_sys::Date::now().max(0.0) as u64
}

/// `navigator.hid`, or `None` when the browser or context has no WebHID.
fn hid() -> Option<Hid> {
    let navigator = web_sys::window()?.navigator();
    js_sys::Reflect::get(&navigator, &"hid".into())
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null())
        .map(JsCast::unchecked_into)
}

/// Text of a JS rejection (a `DOMException`'s `name: message`, else its string form).
fn error_text(e: &JsValue) -> String {
    let field = |k: &str| {
        js_sys::Reflect::get(e, &k.into())
            .ok()
            .and_then(|v| v.as_string())
    };
    match (field("name"), field("message")) {
        (Some(name), Some(msg)) if !msg.is_empty() => format!("{name}: {msg}"),
        (_, Some(msg)) => msg,
        _ => e.as_string().unwrap_or_else(|| format!("{e:?}")),
    }
}

/// Resolves after `ms` (a `setTimeout` promise).
pub(super) async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = promise.await;
}

/// Awaits `fut`, or fails with "timed out" after `ms`.
async fn within<T>(
    ms: i32,
    fut: impl IntoFuture<Output = Result<T, JsValue>>,
) -> Result<T, JsValue> {
    match select(Box::pin(fut.into_future()), Box::pin(sleep(ms))).await {
        Either::Left((out, _)) => out,
        Either::Right(((), _)) => Err(JsValue::from_str("timed out")),
    }
}

/// Top-level usage pages of one `HIDDevice` (one USB interface).
fn usage_pages(device: &HidDevice) -> Vec<u16> {
    device
        .collections()
        .iter()
        .filter_map(|c| c.get_usage_page())
        .collect()
}

/// Index of the interface to open (port of `ChromeHidTransport.selectDevice`); each entry is
/// `(vendor id, product id, usage pages)`. USB IDs are tried in PARITY order; the bootloader takes
/// the first match; else the 0xFFAB raw interface; else one that is not only keyboard/FIDO/debug.
/// WebHID exposes no serial number, so the Beta 8 serial rule cannot apply here.
fn select_index(devices: &[(u16, u16, Vec<u16>)]) -> Option<usize> {
    USB_IDS.iter().find_map(|&(vid, pid)| {
        let mut matches = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.0 == vid && d.1 == pid);
        if pid == BOOTLOADER_PRODUCT_ID {
            return matches.next().map(|(i, _)| i);
        }
        let matches: Vec<_> = matches.collect();
        let non_app =
            |p: &[u16]| !p.is_empty() && p.iter().all(|x| NON_APP_USAGE_PAGES.contains(x));
        matches
            .iter()
            .find(|(_, d)| d.2.contains(&BETA8_USAGE_PAGE))
            .or_else(|| matches.iter().find(|(_, d)| !non_app(&d.2)))
            .map(|(i, _)| *i)
    })
}

/// Installs the WebHID listeners and the rescan loop and looks for a granted device; idempotent.
/// Without WebHID the snapshot's `connect_error` says so.
pub fn start() {
    if with(|d| std::mem::replace(&mut d.started, true)) {
        return;
    }
    let Some(hid) = hid() else {
        with(|d| d.engine.set_connect_error(Some(NO_WEBHID.into())));
        flush();
        return;
    };
    let on_connect = Closure::<dyn Fn(HidConnectionEvent)>::new(|_| scan());
    hid.set_onconnect(Some(on_connect.as_ref().unchecked_ref()));
    on_connect.forget();
    let on_disconnect = Closure::<dyn Fn(HidConnectionEvent)>::new(|ev: HidConnectionEvent| {
        let gone = ev.device();
        if with(|d| d.device.as_ref() == Some(&gone)) {
            close("unplugged");
        }
    });
    hid.set_ondisconnect(Some(on_disconnect.as_ref().unchecked_ref()));
    on_disconnect.forget();
    let rescan = Closure::<dyn Fn()>::new(|| {
        watchdog();
        scan();
    });
    if let Some(w) = web_sys::window() {
        let _ = w.set_interval_with_callback_and_timeout_and_arguments_0(
            rescan.as_ref().unchecked_ref(),
            RESCAN_MS,
        );
    }
    rescan.forget();
    scan();
}

/// Shows Chrome's device chooser filtered to the OnlyKey USB IDs (needs a user gesture), then
/// connects. A dismissed chooser is not an error.
pub async fn request_device() {
    let Some(hid) = hid() else { return };
    let filters: Vec<HidDeviceFilter> = USB_IDS
        .iter()
        .map(|&(vid, pid)| {
            let f = HidDeviceFilter::new();
            f.set_vendor_id(u32::from(vid));
            f.set_product_id(pid);
            f
        })
        .collect();
    match hid
        .request_device(&HidDeviceRequestOptions::new(&filters))
        .await
    {
        Ok(_) => scan(),
        Err(e) => {
            let text = error_text(&e);
            if !text.starts_with("NotFoundError") {
                with(|d| d.engine.set_connect_error(Some(text)));
                flush();
            }
        }
    }
}

/// Opens the best granted device if none is open; errors reach the UI as `connect_error`.
fn scan() {
    let Some(hid) = hid() else { return };
    if with(|d| d.device.is_some() || std::mem::replace(&mut d.opening, true)) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async move {
        let picked = match hid.get_devices().await {
            Ok(list) => {
                let devices: Vec<HidDevice> = list.iter().collect();
                let ids: Vec<_> = devices
                    .iter()
                    .map(|d| (d.vendor_id(), d.product_id(), usage_pages(d)))
                    .collect();
                select_index(&ids).map(|i| devices[i].clone())
            }
            Err(_) => None,
        };
        let opened = match picked {
            Some(device) if device.opened() => Ok(Some(device)),
            Some(device) => within(OPEN_TIMEOUT_MS, device.open())
                .await
                .map(|_| Some(device)),
            None => Ok(None),
        };
        match opened {
            Ok(Some(device)) => attach(device),
            Ok(None) => {}
            Err(e) => {
                let text = error_text(&e);
                with(|d| {
                    if d.engine.snapshot().connect_error.as_deref() != Some(text.as_str()) {
                        web_sys::console::warn_1(&format!("device: open failed: {text}").into());
                        d.engine.set_connect_error(Some(text));
                    }
                });
            }
        }
        with(|d| d.opening = false);
        flush();
    });
}

/// Starts using an opened device: input handler, clock re-sync, `on_connected`.
fn attach(device: HidDevice) {
    let on_input = Closure::<dyn FnMut(HidInputReportEvent)>::new(on_input_report);
    device.set_oninputreport(Some(on_input.as_ref().unchecked_ref()));
    web_sys::console::info_1(&format!("device: opened {:04x}", device.product_id()).into());
    with(|d| {
        let t = now();
        let pid = device.product_id();
        d.engine.set_unix_origin(unix_now().saturating_sub(t));
        if d.engine.snapshot().connect_error.is_some() {
            d.engine.set_connect_error(None);
        }
        d.device = Some(device);
        d.on_input = Some(on_input);
        d.engine.on_connected(pid, t);
        d.connecting_since = Some(t);
    });
}

/// One input report (report ID 0, 64 bytes; shorter ones zero-padded) → `on_report`.
fn on_input_report(ev: HidInputReportEvent) {
    let data = ev.data();
    let mut report = [0u8; 64];
    let len = data.byte_length().min(64);
    for (i, b) in report.iter_mut().enumerate().take(len) {
        *b = data.get_uint8(i);
    }
    with(|d| {
        if d.device.as_ref() == Some(&ev.device()) {
            d.engine.on_report(&report, now());
        }
    });
    flush();
}

/// Closes the device in use; the engine fails work in flight and wipes the session.
fn close(reason: &str) {
    let device = with(|d| {
        d.on_input = None;
        d.writes.clear();
        d.connecting_since = None;
        d.engine.on_disconnected(now());
        d.device.take()
    });
    if let Some(device) = device {
        web_sys::console::info_1(&format!("device: closed ({reason})").into());
        device.set_oninputreport(None);
        wasm_bindgen_futures::spawn_local(async move {
            let _ = device.close().await;
        });
    }
    flush();
}

/// Tears down a connect that never produced a status (hung handle).
fn watchdog() {
    let hung = with(|d| {
        if d.engine.snapshot().state != DeviceState::Disconnected {
            d.connecting_since = None;
        }
        d.connecting_since
            .is_some_and(|t| now() >= t + CONNECT_WATCHDOG_MS)
    });
    if hung {
        close("connect watchdog");
    }
}

/// Deadline timer fired: run due timeouts and sleeps.
fn on_timer() {
    with(|d| {
        d.timer = None;
        d.engine.on_tick(now());
    });
    flush();
}

/// Acts on every engine output, re-arms the deadline timer, then tells the UI listeners
/// (outside the driver borrow, so they may call back in).
fn flush() {
    let (events, listeners, probe_failed) = with(|d| {
        let mut events = Vec::new();
        while let Some(output) = d.engine.poll_output() {
            match output {
                // With no device the engine has already failed the work; drop the packet.
                Output::Write(packet) if d.device.is_some() => d.writes.push_back(packet),
                Output::Write(_) => {}
                Output::Reply(id, answer) => {
                    if let Some(tx) = d.waiting.remove(&id) {
                        let _ = tx.send(answer);
                    }
                }
                Output::Event(event) => {
                    if let Event::Snapshot(snap) = &event
                        && snap.state != d.last_state
                    {
                        let line = format!("device: {:?} -> {:?}", d.last_state, snap.state);
                        web_sys::console::info_1(&line.into());
                        d.last_state = snap.state;
                    }
                    events.push(event);
                }
            }
        }
        rearm(d);
        let probe_failed = d.device.is_some() && !d.engine.is_connected();
        (events, d.listeners.clone(), probe_failed)
    });
    pump_writes();
    for event in events {
        for f in &listeners {
            f(event.clone());
        }
    }
    if probe_failed {
        // The engine gave up on the connect probe: close and let the rescan retry.
        close("connect probe failed");
    }
}

/// Replaces the deadline timer with one for the engine's `next_deadline`.
fn rearm(d: &mut Driver) {
    let Some(w) = web_sys::window() else { return };
    if let Some(id) = d.timer.take() {
        w.clear_timeout_with_handle(id);
    }
    if let Some(at) = d.engine.next_deadline() {
        let ms = i32::try_from(at.saturating_sub(now())).unwrap_or(i32::MAX);
        d.timer = TICK.with(|tick| {
            w.set_timeout_with_callback_and_timeout_and_arguments_0(
                tick.as_ref().unchecked_ref(),
                ms,
            )
            .ok()
        });
    }
}

/// Starts the writer task if packets are queued; it sends them one at a time, and a failed or
/// hung `sendReport` closes the device (an unplug, as on desktop).
fn pump_writes() {
    if with(|d| d.writes.is_empty() || std::mem::replace(&mut d.writing, true)) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        loop {
            let next = with(|d| {
                let packet = d.writes.pop_front();
                let device = d.device.clone();
                match (packet, device) {
                    (Some(p), Some(dev)) => Some((p, dev)),
                    _ => {
                        d.writing = false;
                        None
                    }
                }
            });
            let Some((mut packet, device)) = next else {
                return;
            };
            let sent = match device.send_report_with_u8_slice(0, &mut packet) {
                Ok(promise) => within(SEND_TIMEOUT_MS, promise).await.map(|_| ()),
                Err(e) => Err(e),
            };
            if let Err(e) = sent {
                with(|d| d.writing = false);
                if with(|d| d.device.as_ref() == Some(&device)) {
                    close(&error_text(&e));
                }
                return;
            }
        }
    });
}

/// Runs one command on the engine and waits for its reply.
pub async fn send(cmd: Command) -> Answer {
    let (tx, rx) = oneshot::channel();
    with(|d| {
        let id = d.engine.submit(cmd, now());
        d.waiting.insert(id, tx);
    });
    flush();
    rx.await.unwrap_or(Err(DeviceError::Disconnected))
}

/// The engine's current snapshot.
pub fn snapshot() -> Snapshot {
    with(|d| d.engine.snapshot().clone())
}

/// Registers a UI event callback and starts the driver.
pub fn on_event(f: impl Fn(Event) + 'static) {
    with(|d| d.listeners.push(Rc::new(f)));
    start();
}

#[cfg(test)]
mod tests {
    //! Interface selection over fake `getDevices()` lists.

    use super::select_index;

    /// Beta 8+: keyboard, raw and debug interfaces of one device; raw wins.
    #[test]
    fn beta8_prefers_raw_usage_page() {
        let list = [
            (0x1D50, 0x60FC, vec![0x01]),
            (0x1D50, 0x60FC, vec![0xFFAB]),
            (0x1D50, 0x60FC, vec![0xFFC9]),
        ];
        assert_eq!(select_index(&list), Some(1));
    }

    /// DUO PIDs come before the shared 60FC one; the bootloader takes its first match.
    #[test]
    fn connect_order_and_bootloader() {
        let list = [
            (0x1D50, 0x60FC, vec![0xFFAB]),
            (0x1D50, 0x614C, vec![0xFFAB]),
        ];
        assert_eq!(select_index(&list), Some(1));
        let boot = [(0x0000, 0xB001, vec![0x01]), (0x0000, 0xB001, vec![0xFFAB])];
        assert_eq!(select_index(&boot), Some(0));
    }

    /// Only keyboard/FIDO interfaces granted: open nothing; a Classic's vendor page is fine.
    #[test]
    fn never_opens_keyboard_only() {
        let kbd = [(0x1D50, 0x60FC, vec![0x01]), (0x1D50, 0x60FC, vec![0xF1D0])];
        assert_eq!(select_index(&kbd), None);
        let classic = [(0x16C0, 0x0486, vec![0x01, 0xFF00])];
        assert_eq!(select_index(&classic), Some(0));
        assert_eq!(select_index(&[(0x046D, 0xC52B, vec![0xFFAB])]), None);
    }
}
