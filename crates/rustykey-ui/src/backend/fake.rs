//! Fake backend for UI work and screenshots in a plain browser (`--features fake`).
//!
//! Starts as an unlocked DUO. Every command answers after ~300 ms. Dev keys:
//! Ctrl+Shift+D cycles Disconnected → Locked → Unlocked → Config mode (locked) → Config mode (unlocked) → Bootloader → Uninitialized;
//! Ctrl+Shift+K toggles Classic / DUO.

use super::{AppUpdate, Backend, FirmwareRelease, Platform, Prefs};
use leptos::ev::keydown;
use leptos::prelude::window_event_listener;
use onlykey_core::api::{Command, DeviceError, DeviceKind, DeviceState, Event, Reply, Snapshot};
use std::cell::RefCell;
use std::rc::Rc;

/// Order the dev switcher walks through: (state, locked). Config mode appears twice: the config-mode lock
/// (before the config PIN) and unlocked in config mode.
const CYCLE: [(DeviceState, bool); 7] = [
    (DeviceState::Disconnected, false),
    (DeviceState::Locked, true),
    (DeviceState::Unlocked, false),
    (DeviceState::ConfigMode, true),
    (DeviceState::ConfigMode, false),
    (DeviceState::Bootloader, false),
    (DeviceState::Uninitialized, false),
];

/// Fake device + host state.
struct Fake {
    /// Current snapshot.
    snap: Snapshot,
    /// Event listeners.
    listeners: Vec<Rc<dyn Fn(Event)>>,
    /// In-memory prefs.
    prefs: Prefs,
}

thread_local! {
    /// The one fake device.
    static FAKE: RefCell<Fake> = RefCell::new(Fake {
        snap: snapshot_for(DeviceState::Unlocked, false, DeviceKind::Duo, 1),
        listeners: Vec::new(),
        prefs: Prefs::default(),
    });
}

/// Builds the snapshot a real device of `kind` would report in `state` (`locked` matters for config mode).
fn snapshot_for(state: DeviceState, locked: bool, kind: DeviceKind, epoch: u64) -> Snapshot {
    let locked = locked && matches!(state, DeviceState::Locked | DeviceState::ConfigMode);
    let connected = state != DeviceState::Disconnected;
    let mut labels: [Option<String>; 24] = Default::default();
    if !locked && matches!(state, DeviceState::Unlocked | DeviceState::ConfigMode) {
        for (i, l) in ["GitHub", "Email", "Bank", "VPN", "Work SSO"]
            .iter()
            .enumerate()
        {
            labels[i * 2] = Some((*l).to_string());
        }
    }
    Snapshot {
        state,
        kind: if connected { kind } else { DeviceKind::Unknown },
        firmware: match state {
            DeviceState::Disconnected | DeviceState::Bootloader => None,
            _ => Some("v3.0.4-prodp".into()),
        },
        pin_set: true,
        product_name: match (connected, kind) {
            (false, _) => String::new(),
            (true, DeviceKind::Duo) => "OnlyKey Duo".into(),
            (true, _) => "OnlyKey".into(),
        },
        labels,
        session_epoch: epoch,
        connect_error: None,
        locked,
    }
}

/// Sends `event` to every listener (outside the borrow, so listeners may call back in).
fn emit(event: Event) {
    let listeners = FAKE.with_borrow(|f| f.listeners.clone());
    for l in listeners {
        l(event.clone());
    }
}

/// Moves the fake to `state`/`locked`/`kind`, bumping the epoch like the engine (unplug, unlocked → locked).
fn set_state(state: DeviceState, locked: bool, kind: DeviceKind) {
    let snap = FAKE.with_borrow_mut(|f| {
        let prev = f.snap.state;
        let wipe = (prev != DeviceState::Disconnected && state == DeviceState::Disconnected)
            || (prev != DeviceState::Disconnected && !f.snap.locked && locked);
        let epoch = f.snap.session_epoch + u64::from(wipe);
        f.snap = snapshot_for(state, locked, kind, epoch);
        f.snap.clone()
    });
    emit(Event::Snapshot(snap));
}

/// Resolves after `ms` milliseconds.
async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Installs the Ctrl+Shift+D / Ctrl+Shift+K dev switcher.
fn install_switcher() {
    let handle = window_event_listener(keydown, |e| {
        if !(e.ctrl_key() && e.shift_key()) {
            return;
        }
        let (state, locked, kind) =
            FAKE.with_borrow(|f| (f.snap.state, f.snap.locked, f.snap.kind));
        let kind = if kind == DeviceKind::Unknown {
            DeviceKind::Duo
        } else {
            kind
        };
        match e.key().to_ascii_lowercase().as_str() {
            "d" => {
                let i = CYCLE
                    .iter()
                    .position(|s| *s == (state, locked))
                    .unwrap_or(0);
                let (next, next_locked) = CYCLE[(i + 1) % CYCLE.len()];
                set_state(next, next_locked, kind);
            }
            "k" => {
                let other = if kind == DeviceKind::Duo {
                    DeviceKind::Classic
                } else {
                    DeviceKind::Duo
                };
                set_state(state, locked, other);
            }
            _ => return,
        }
        e.prevent_default();
    });
    std::mem::forget(handle);
}

/// Stateless handle to the thread-local fake.
pub struct FakeBackend;

impl Backend for FakeBackend {
    /// Waits 300 ms, says what ran, returns `Done` (`Labels` for `GetLabels`, `FirmwarePending` for firmware outside the bootloader); a DUO unlock unlocks.
    async fn send(&self, cmd: Command) -> Result<Reply, DeviceError> {
        sleep(300).await;
        let snap = FAKE.with_borrow(|f| f.snap.clone());
        if snap.state == DeviceState::Disconnected {
            return Err(DeviceError::Disconnected);
        }
        match &cmd {
            Command::RefreshStatus => return Ok(Reply::Done),
            Command::GetLabels => {
                return Ok(Reply::Labels {
                    labels: snap.labels,
                });
            }
            Command::DuoPin { setup: false, .. } => {
                let state = if snap.state == DeviceState::ConfigMode {
                    DeviceState::ConfigMode
                } else {
                    DeviceState::Unlocked
                };
                set_state(state, false, snap.kind);
            }
            _ => {}
        }
        emit(Event::Message {
            text: format!("fake: {cmd:?} done"),
        });
        if matches!(cmd, Command::LoadFirmware { .. }) && snap.state != DeviceState::Bootloader {
            return Ok(Reply::FirmwarePending);
        }
        Ok(Reply::Done)
    }

    /// Current fake snapshot.
    async fn snapshot(&self) -> Snapshot {
        FAKE.with_borrow(|f| f.snap.clone())
    }

    /// Adds a listener; the first call also installs the dev keyboard switcher.
    fn on_event(&self, f: impl Fn(Event) + 'static) {
        let first = FAKE.with_borrow_mut(|s| {
            s.listeners.push(Rc::new(f));
            s.listeners.len() == 1
        });
        if first {
            install_switcher();
        }
    }

    /// In-memory prefs.
    async fn prefs_get(&self) -> Prefs {
        FAKE.with_borrow(|f| f.prefs.clone())
    }

    /// In-memory prefs.
    async fn prefs_set(&self, prefs: Prefs) -> Result<(), String> {
        FAKE.with_borrow_mut(|f| f.prefs = prefs);
        Ok(())
    }

    /// No file picker in the fake.
    async fn pick_text_file(&self, _accept: &[&str]) -> Option<(String, String)> {
        None
    }

    /// Pretends to save.
    async fn save_text_file(&self, _default_name: &str, _text: &str) -> bool {
        true
    }

    /// Opens a new tab.
    async fn open_url(&self, url: &str) {
        if let Some(w) = web_sys::window() {
            let _ = w.open_with_url_and_target(url, "_blank");
        }
    }

    /// Always offers app 0.2.0 after 300 ms.
    async fn app_update_check(&self, _force: bool) -> Result<Option<AppUpdate>, String> {
        sleep(300).await;
        Ok(Some(AppUpdate {
            version: "0.2.0".into(),
            notes: "Fake release.".into(),
        }))
    }

    /// Reports 10 progress steps over ~1 s, then fails (a real host restarts instead of returning).
    async fn app_update_install(
        &self,
        on_progress: impl Fn(u64, Option<u64>) + 'static,
    ) -> Result<(), String> {
        for i in 1..=10u64 {
            sleep(100).await;
            on_progress(i * 100_000, Some(1_000_000));
        }
        // A real host restarts here and never returns; the fake fails so the dialog can be closed.
        Err("Fake backend: install skipped (a real host restarts the app here).".into())
    }

    /// Always offers firmware v3.0.5 after 300 ms.
    async fn fw_check(&self, _force: bool) -> Result<Option<FirmwareRelease>, String> {
        sleep(300).await;
        Ok(Some(FirmwareRelease {
            version: "v3.0.5".into(),
        }))
    }

    /// Four dummy blocks after 600 ms.
    async fn fw_download(&self) -> Result<Vec<Vec<u8>>, String> {
        sleep(600).await;
        Ok(vec![vec![0u8; 32]; 4])
    }

    /// Acts as desktop so desktop-only controls show in screenshots.
    fn platform(&self) -> Platform {
        Platform::Desktop
    }
}
