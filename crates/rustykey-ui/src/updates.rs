//! App and firmware update flows (`useAppUpdateStore.ts`, `useFirmwareUpdateStore.ts`), their hosts
//! (`AppUpdateHost.tsx`, `FirmwareUpdateHost.tsx`) and dialogs (`AppUpdateDialog.tsx`, `FirmwareUpdateDialog.tsx`).
//!
//! Session-only state (already checked, downloaded firmware blocks) lives here in memory, never in prefs.
//! The stores use `ArcRwSignal`s in a thread-local so they outlive the session-keyed pages that read them.

use crate::backend::{Backend, Platform, backend};
use crate::components::{Button, ButtonKind, Modal};
use crate::state::{AppState, Tab, Working, is_locked, use_app};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{Command, DeviceState, Reply};
use onlykey_core::firmware::supports_app_update;
use std::cell::Cell;
use std::sync::Arc;

/// Config-mode how-to used by the firmware update copy (`CONFIG_MODE_HOLD_COPY`).
const CONFIG_MODE_HOLD_COPY: &str = "For OnlyKey hold down button #6 for 5+ seconds and release. For OnlyKey DUO hold down button #1 for 10+ seconds and release. The light will turn off; if a PIN was set, re-enter it. OnlyKey flashes red in config mode.";

/// Where an update flow is (`AppUpdatePhase` / `FirmwareUpdatePhase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing happening.
    Idle,
    /// Asking the host for a release.
    Checking,
    /// A newer release exists.
    Available,
    /// Downloading it.
    Downloading,
    /// Downloaded and verified.
    Ready,
    /// Installing / loading.
    Applying,
    /// Forced check found nothing newer.
    UpToDate,
    /// Something failed (`error` says what).
    Error,
}

impl Phase {
    /// A request is in flight; dismiss and new checks wait.
    pub fn busy(self) -> bool {
        matches!(self, Phase::Checking | Phase::Downloading | Phase::Applying)
    }

    /// The dialog has something to show in this phase (`shouldPresent`).
    fn presents(self) -> bool {
        !matches!(self, Phase::Idle | Phase::Checking)
    }
}

/// Firmware update state shared by the host, the Firmware page and the firmware loader.
#[derive(Clone)]
pub struct FwStore {
    /// Flow phase.
    pub phase: ArcRwSignal<Phase>,
    /// Dialog requested.
    prompt: ArcRwSignal<bool>,
    /// Device version at the last check.
    current: ArcRwSignal<String>,
    /// Release version found by the last check.
    pub latest: ArcRwSignal<Option<String>>,
    /// Downloaded, verified blocks (session only).
    pub blocks: ArcRwSignal<Option<Arc<Vec<Vec<u8>>>>>,
    /// Last error text (also shown on the Firmware page).
    pub error: ArcRwSignal<Option<String>>,
    /// An auto-check already ran this app session (`ok-fw-checked-session`).
    checked: ArcRwSignal<bool>,
    /// Blocks were handed to the engine before a bootloader reboot; show progress when it reconnects.
    pending_reboot: ArcRwSignal<bool>,
    /// The WorkingDialog is showing a resumed firmware stream.
    streaming: ArcRwSignal<bool>,
}

/// App update state shared by the host, its dialog and the Tools page.
#[derive(Clone)]
pub struct AppStore {
    /// Flow phase.
    pub phase: ArcRwSignal<Phase>,
    /// Dialog requested.
    prompt: ArcRwSignal<bool>,
    /// Release version found by the last check.
    pub latest: ArcRwSignal<Option<String>>,
    /// Last error text.
    pub error: ArcRwSignal<Option<String>>,
    /// Bytes downloaded so far.
    received: ArcRwSignal<u64>,
    /// Download size, if known.
    total: ArcRwSignal<Option<u64>>,
    /// An auto-check already ran this app session.
    checked: ArcRwSignal<bool>,
    /// The found release can be installed in place (false on a Linux `.deb`).
    can_install: ArcRwSignal<bool>,
    /// Release page for installs that cannot update themselves.
    release_url: ArcRwSignal<String>,
}

thread_local! {
    /// The one firmware update store.
    static FW: FwStore = FwStore {
        phase: ArcRwSignal::new(Phase::Idle),
        prompt: ArcRwSignal::new(false),
        current: ArcRwSignal::new(String::new()),
        latest: ArcRwSignal::new(None),
        blocks: ArcRwSignal::new(None),
        error: ArcRwSignal::new(None),
        checked: ArcRwSignal::new(false),
        pending_reboot: ArcRwSignal::new(false),
        streaming: ArcRwSignal::new(false),
    };
    /// The one app update store.
    static APP: AppStore = AppStore {
        phase: ArcRwSignal::new(Phase::Idle),
        prompt: ArcRwSignal::new(false),
        latest: ArcRwSignal::new(None),
        error: ArcRwSignal::new(None),
        received: ArcRwSignal::new(0),
        total: ArcRwSignal::new(None),
        checked: ArcRwSignal::new(false),
        can_install: ArcRwSignal::new(true),
        release_url: ArcRwSignal::new(String::new()),
    };
    /// Bumps on unplug so firmware results from before it are dropped (`generation`).
    static FW_GENERATION: Cell<u64> = const { Cell::new(0) };
}

/// The firmware update store.
pub fn fw() -> FwStore {
    FW.with(Clone::clone)
}

/// The app update store.
pub fn app_updates() -> AppStore {
    APP.with(Clone::clone)
}

/// Current firmware generation.
fn fw_gen() -> u64 {
    FW_GENERATION.with(Cell::get)
}

/// True for host errors that should pop the dialog even on an automatic check (`autoDownloadErrorShowsModal`):
/// integrity, location and parse failures. Plain network failures stay quiet.
/// The host words its errors to match these keywords: keep in step with `src-tauri/src/updates.rs`.
fn serious(message: &str) -> bool {
    ["SHA-256", "refused", "parsed", "installer"]
        .iter()
        .any(|k| message.contains(k))
}

/// Download percentage, if the total is known.
fn percent(received: u64, total: Option<u64>) -> Option<u64> {
    total
        .filter(|t| *t > 0)
        .map(|t| (received.saturating_mul(100) / t).min(100))
}

// ---------- Firmware ----------

/// Device facts the firmware flow reads, taken untracked.
struct DeviceFacts {
    /// Device present.
    connected: bool,
    /// Locked (incl. config-mode lock).
    locked: bool,
    /// In the bootloader.
    bootloader: bool,
    /// Not uninitialized.
    initialized: bool,
    /// In config mode.
    config_mode: bool,
    /// Firmware text ("" if unknown).
    version: String,
}

/// Reads [`DeviceFacts`] from the snapshot without tracking.
fn facts(app: AppState) -> DeviceFacts {
    app.snapshot.with_untracked(|s| DeviceFacts {
        connected: s.state != DeviceState::Disconnected,
        locked: is_locked(s),
        bootloader: s.state == DeviceState::Bootloader,
        initialized: s.state != DeviceState::Uninitialized,
        config_mode: s.state == DeviceState::ConfigMode,
        version: s.firmware.clone().unwrap_or_default(),
    })
}

/// `isSafeFirmwareCheckMoment`: desktop, connected, unlocked, not bootloader, not working, not in a Setup PIN step,
/// and a version is known (or the device is uninitialized).
pub fn fw_safe_moment(app: AppState) -> bool {
    let d = facts(app);
    backend().platform() == Platform::Desktop
        && d.connected
        && !d.locked
        && !d.bootloader
        && app.working.with_untracked(Option::is_none)
        && !app.setup_blocks_firmware_prompt.get_untracked()
        && (!d.version.is_empty() || !d.initialized)
}

/// Sets the firmware error and opens the dialog when `prompt`.
fn fw_present_error(message: String, prompt: bool) {
    let s = fw();
    s.error.set(Some(message));
    s.phase.set(Phase::Error);
    s.prompt.set(prompt);
}

/// One firmware check (`runCheck`); `force` = "Check now".
async fn fw_run_check(app: AppState, force: bool) {
    let s = fw();
    let generation = fw_gen();
    let d = facts(app);
    s.phase.set(Phase::Checking);
    s.error.set(None);
    s.prompt.set(false);
    s.current.set(d.version.clone());
    if !force {
        s.checked.set(true);
    }
    if !supports_app_update(&d.version) && d.initialized {
        let msg = "This firmware cannot be updated from the app. Follow the loading instructions at docs.crp.to.";
        if force {
            fw_present_error(msg.into(), true);
        } else {
            s.error.set(Some(msg.into()));
            s.phase.set(Phase::Idle);
        }
        return;
    }
    let result = backend().fw_check(force).await;
    if fw_gen() != generation {
        return;
    }
    match result {
        Ok(Some(release)) => {
            s.latest.set(Some(release.version));
            s.phase.set(Phase::Available);
            s.prompt.set(true);
        }
        Ok(None) => {
            s.phase
                .set(if force { Phase::UpToDate } else { Phase::Idle });
            s.prompt.set(force);
        }
        Err(e) => {
            let prompt = force || serious(&e);
            fw_present_error(e, prompt);
        }
    }
}

/// `startAutoCheck`: pref on, idle, not yet checked this session, safe moment.
pub fn fw_start_auto_check(app: AppState) {
    let s = fw();
    let phase = s.phase.get_untracked();
    if !app.prefs.with_untracked(|p| p.auto_update_fw)
        || phase.busy()
        || matches!(
            phase,
            Phase::Available | Phase::Downloading | Phase::Ready | Phase::Error
        )
        || s.checked.get_untracked()
        || !fw_safe_moment(app)
    {
        return;
    }
    spawn_local(fw_run_check(app, false));
}

/// "Check now" on the Firmware page (`checkNow`).
pub fn fw_check_now(app: AppState) {
    if fw().phase.get_untracked().busy() || !fw_safe_moment(app) {
        return;
    }
    spawn_local(fw_run_check(app, true));
}

/// Dialog "Download" (`confirmDownload`).
fn fw_confirm_download() {
    let s = fw();
    if s.phase.get_untracked() != Phase::Available {
        return;
    }
    let generation = fw_gen();
    s.phase.set(Phase::Downloading);
    s.prompt.set(true);
    spawn_local(async move {
        let result = backend().fw_download().await;
        if fw_gen() != generation {
            return;
        }
        match result {
            Ok(blocks) => {
                s.blocks.set(Some(Arc::new(blocks)));
                s.phase.set(Phase::Ready);
            }
            Err(e) => fw_present_error(e, true),
        }
    });
}

/// Loads `blocks` (`applyFirmwareBlocks`): streams in the bootloader (Ok(true)); otherwise the engine triggers the
/// bootloader and holds the blocks (Ok(false)) and the host shows progress when the device comes back.
pub async fn apply_firmware(app: AppState, blocks: Vec<Vec<u8>>) -> Result<bool, String> {
    if blocks.is_empty() {
        return Err("Could not parse firmware file.".into());
    }
    let message = if facts(app).bootloader {
        "Loading firmware… 0%"
    } else {
        "Triggering reboot to bootloader — do not remove OnlyKey…"
    };
    let reply = app
        .working(message, backend().send(Command::LoadFirmware { blocks }))
        .await
        .map_err(|e| e.to_string())?;
    if reply == Reply::FirmwarePending {
        fw().pending_reboot.set(true);
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Dialog "Load firmware" (`applyFirmware`): needs config mode or the bootloader.
fn fw_apply(app: AppState) {
    let s = fw();
    let Some(blocks) = s.blocks.get_untracked() else {
        return;
    };
    let d = facts(app);
    if s.phase.get_untracked() != Phase::Ready
        || app.working.with_untracked(Option::is_some)
        || d.locked
    {
        return;
    }
    if d.initialized && !d.config_mode && !d.bootloader {
        fw_present_error(
            format!("OnlyKey is not in config mode. {CONFIG_MODE_HOLD_COPY}"),
            true,
        );
        return;
    }
    let generation = fw_gen();
    s.phase.set(Phase::Applying);
    s.prompt.set(true);
    spawn_local(async move {
        let result = apply_firmware(app, blocks.to_vec()).await;
        if fw_gen() != generation {
            return;
        }
        match result {
            Ok(_) => {
                s.checked.set(true);
                s.phase.set(Phase::Idle);
                s.prompt.set(false);
            }
            Err(e) if e.to_lowercase().contains("not in config mode") => fw_present_error(
                format!("OnlyKey is not in config mode. {CONFIG_MODE_HOLD_COPY}"),
                true,
            ),
            Err(e) => fw_present_error(format!("Firmware load failed. {e}"), true),
        }
    });
}

/// Dialog "Open Firmware tab" (`openFirmwareTab`).
fn fw_open_tab(app: AppState) {
    let s = fw();
    if s.phase.get_untracked().busy() {
        return;
    }
    app.tab.set(Tab::Firmware);
    s.checked.set(true);
    s.prompt.set(false);
}

/// Dialog "Later" / "OK" (`dismiss`).
fn fw_dismiss() {
    let s = fw();
    if s.phase.get_untracked().busy() {
        return;
    }
    s.checked.set(true);
    s.phase.set(Phase::Idle);
    s.prompt.set(false);
}

/// Unplug: drops downloaded blocks and any in-flight result (`resetOnDisconnect`); the session check flag stays.
fn fw_reset_on_disconnect() {
    FW_GENERATION.with(|g| g.set(g.get() + 1));
    let s = fw();
    s.phase.set(Phase::Idle);
    s.prompt.set(false);
    s.current.set(String::new());
    s.latest.set(None);
    s.blocks.set(None);
    s.error.set(None);
}

// ---------- App ----------

/// Sets the app update error and opens the dialog when `prompt`.
fn app_present_error(message: String, prompt: bool) {
    let s = app_updates();
    s.error.set(Some(message));
    s.phase.set(Phase::Error);
    s.prompt.set(prompt);
}

/// One app update check (`runCheck`); `force` = "Check now".
async fn app_run_check(force: bool) {
    let s = app_updates();
    s.phase.set(Phase::Checking);
    s.error.set(None);
    s.prompt.set(false);
    if !force {
        s.checked.set(true);
    }
    match backend().app_update_check(force).await {
        Ok(Some(update)) => {
            s.latest.set(Some(update.version));
            s.can_install.set(update.can_install);
            s.release_url.set(update.release_url);
            s.phase.set(Phase::Available);
            s.prompt.set(true);
        }
        Ok(None) => {
            s.phase
                .set(if force { Phase::UpToDate } else { Phase::Idle });
            s.prompt.set(force);
        }
        Err(e) => {
            let prompt = force || serious(&e);
            app_present_error(e, prompt);
        }
    }
}

/// `startAutoCheck`: desktop, pref on, not busy, not yet checked this session.
pub fn app_start_auto_check(auto_update: bool) {
    let s = app_updates();
    if backend().platform() != Platform::Desktop
        || !auto_update
        || s.phase.get_untracked().busy()
        || s.checked.get_untracked()
    {
        return;
    }
    spawn_local(app_run_check(false));
}

/// "Check now" on the Tools page.
pub fn app_check_now() {
    if app_updates().phase.get_untracked().busy() {
        return;
    }
    spawn_local(app_run_check(true));
}

/// Dialog "Download": downloads, verifies and installs in one host call (the updater plugin restarts the app).
fn app_confirm_download() {
    let s = app_updates();
    if s.phase.get_untracked() != Phase::Available {
        return;
    }
    s.phase.set(Phase::Downloading);
    s.prompt.set(true);
    s.received.set(0);
    s.total.set(None);
    spawn_local(async move {
        let progress = s.clone();
        let result = backend()
            .app_update_install(move |received, total| {
                progress.received.set(received);
                progress.total.set(total);
            })
            .await;
        match result {
            Ok(()) => s.phase.set(Phase::Applying),
            Err(e) => app_present_error(e, true),
        }
    });
}

/// Dialog "Open release page" for installs that cannot update themselves (Linux `.deb`).
fn app_open_release_page() {
    let url = app_updates().release_url.get_untracked();
    app_dismiss();
    spawn_local(async move { backend().open_url(&url).await });
}

/// Dialog "Later" / "OK" (`dismissUpdatePrompt`).
fn app_dismiss() {
    let s = app_updates();
    if !s.phase.get_untracked().busy() {
        s.prompt.set(false);
    }
}

// ---------- Views ----------

/// What an update dialog shows: title, text, optional progress, cancel and confirm buttons.
struct DialogView {
    /// Heading.
    title: String,
    /// Body text.
    message: String,
    /// Progress bar percent.
    percent: Option<u64>,
    /// Cancel label and whether it is disabled.
    cancel: Option<(&'static str, bool)>,
    /// Confirm label.
    confirm: Option<&'static str>,
}

/// Renders a [`DialogView`]; Esc and cancel call `on_cancel`, confirm calls `on_confirm`.
fn dialog(v: DialogView, on_cancel: Callback<()>, on_confirm: Callback<()>) -> AnyView {
    view! {
        <Modal title=v.title on_close=on_cancel>
            <p class="modal-text">{v.message}</p>
            {v
                .percent
                .map(|p| {
                    view! {
                        <div
                            class="progress"
                            role="progressbar"
                            aria-valuemin="0"
                            aria-valuemax="100"
                            aria-valuenow=p
                        >
                            <div class="progress-bar" style:width=format!("{p}%")></div>
                        </div>
                    }
                })}
            <div class="modal-actions">
                {v
                    .cancel
                    .map(|(label, disabled)| {
                        view! {
                            <Button
                                kind=ButtonKind::Secondary
                                disabled=disabled
                                on:click=move |_| on_cancel.run(())
                            >
                                {label}
                            </Button>
                        }
                    })}
                {v
                    .confirm
                    .map(|label| {
                        view! { <Button on:click=move |_| on_confirm.run(())>{label}</Button> }
                    })}
            </div>
        </Modal>
    }
    .into_any()
}

/// `FirmwareUpdateDialog` contents for the current phase.
fn fw_dialog_view(app: AppState) -> DialogView {
    let s = fw();
    let latest = s.latest.get().unwrap_or_default();
    let current = s.current.get();
    let can_load_now = app.snapshot.with(|snap| {
        matches!(
            snap.state,
            DeviceState::Bootloader | DeviceState::Uninitialized | DeviceState::ConfigMode
        )
    });
    let (title, message, cancel, confirm) = match s.phase.get() {
        Phase::Available => (
            "Firmware update available",
            format!(
                "Firmware {latest} is available. Your version is {current}. Download the update?"
            ),
            Some(("Later", false)),
            Some("Download"),
        ),
        Phase::Downloading => (
            "Downloading firmware",
            format!("Downloading firmware {latest}…"),
            Some(("Later", true)),
            None,
        ),
        Phase::Ready if can_load_now => (
            "Firmware downloaded",
            format!(
                "Firmware {latest} was downloaded and verified (SHA-256). Load onto OnlyKey? The key will restart. Do not remove OnlyKey."
            ),
            Some(("Later", false)),
            Some("Load firmware"),
        ),
        Phase::Ready => (
            "Firmware downloaded",
            format!(
                "Firmware {latest} was downloaded and verified (SHA-256). To load it, put OnlyKey in config mode. {CONFIG_MODE_HOLD_COPY}"
            ),
            Some(("Later", false)),
            Some("Open Firmware tab"),
        ),
        Phase::Applying => (
            "Loading firmware",
            "Do not remove OnlyKey.".into(),
            None,
            None,
        ),
        Phase::UpToDate => (
            "Firmware update",
            format!("Firmware {current} is up to date."),
            Some(("OK", false)),
            None,
        ),
        _ => (
            "Firmware update",
            s.error
                .get()
                .unwrap_or_else(|| "Firmware update failed.".into()),
            Some(("OK", false)),
            None,
        ),
    };
    DialogView {
        title: title.into(),
        message,
        percent: None,
        cancel,
        confirm,
    }
}

/// `AppUpdateDialog` contents for the current phase.
fn app_dialog_view() -> DialogView {
    let s = app_updates();
    let latest = s.latest.get().unwrap_or_default();
    let current = env!("CARGO_PKG_VERSION");
    let pct = percent(s.received.get(), s.total.get());
    let (title, message, cancel, confirm, percent) = match s.phase.get() {
        Phase::Available if s.can_install.get() => (
            "App update available",
            format!("Version {latest} is available. You have {current}. Download the update?"),
            Some(("Later", false)),
            Some("Download"),
            None,
        ),
        Phase::Available => (
            "App update available",
            format!(
                "Version {latest} is available. You have {current}. This installation cannot update itself; get the new version from the release page."
            ),
            Some(("Later", false)),
            Some("Open release page"),
            None,
        ),
        Phase::Downloading => (
            "Downloading update",
            match pct {
                Some(p) => format!("Downloading {latest}… {p}%"),
                None => format!("Downloading {latest}…"),
            },
            Some(("Later", true)),
            None,
            pct,
        ),
        Phase::Applying | Phase::Ready => (
            "Starting installer",
            "RustyKey will restart.".into(),
            None,
            None,
            None,
        ),
        Phase::UpToDate => (
            "App update",
            format!("RustyKey {current} is up to date."),
            Some(("OK", false)),
            None,
            None,
        ),
        _ => (
            "App update",
            s.error.get().unwrap_or_else(|| "App update failed.".into()),
            Some(("OK", false)),
            None,
            None,
        ),
    };
    DialogView {
        title: title.into(),
        message,
        percent,
        cancel,
        confirm,
    }
}

/// Keeps the WorkingDialog text in step with device progress for restore and firmware loads.
fn follow_progress(app: AppState) {
    Effect::new(move |_| {
        let Some(w) = app.working.get() else {
            return;
        };
        let Some(p) = w.progress else {
            return;
        };
        let label = if w.message.starts_with("Loading firmware") {
            format!("Loading firmware… {p}%")
        } else if ["Preparing restore", "Sending backup", "Applying backup"]
            .iter()
            .any(|k| w.message.starts_with(k))
        {
            if p >= 95 {
                "Applying backup on OnlyKey…".into()
            } else {
                format!("Sending backup to OnlyKey… {p}%")
            }
        } else {
            return;
        };
        if label != w.message {
            app.working.update(|w| {
                if let Some(w) = w {
                    w.message = label;
                }
            });
        }
    });
}

/// Firmware auto-check, unplug reset, resumed-stream progress and the firmware dialog. Mounted by [`UpdateHosts`].
#[component]
fn FirmwareUpdateHost(
    /// Prefs have been read from the host (gates the first auto-check).
    loaded: RwSignal<bool>,
) -> impl IntoView {
    let app = use_app();
    let s = fw();
    Effect::new(move |_| {
        app.snapshot.track();
        app.working.track();
        app.setup_blocks_firmware_prompt.track();
        app.prefs.track();
        if loaded.get() {
            untrack(|| fw_start_auto_check(app));
        }
    });
    Effect::new(move |was_connected: Option<bool>| {
        let connected = app
            .snapshot
            .with(|snap| snap.state != DeviceState::Disconnected);
        if was_connected == Some(true) && !connected {
            untrack(fw_reset_on_disconnect);
        }
        connected
    });
    let (pending, streaming) = (s.pending_reboot.clone(), s.streaming.clone());
    Effect::new(move |_| {
        let bootloader = app
            .snapshot
            .with(|snap| snap.state == DeviceState::Bootloader);
        if bootloader && pending.get() {
            pending.set(false);
            streaming.set(true);
            app.working.set(Some(Working {
                message: "Loading firmware… 0%".into(),
                progress: None,
            }));
        } else if !bootloader && streaming.get() {
            streaming.set(false);
            app.working.set(None);
        }
    });
    let open = move || {
        let snap_connected = app
            .snapshot
            .with(|snap| snap.state != DeviceState::Disconnected);
        let d = app
            .snapshot
            .with(|snap| (is_locked(snap), snap.state == DeviceState::Bootloader));
        let deferred = app.working.with(Option::is_some)
            || (snap_connected && d.0)
            || app.setup_blocks_firmware_prompt.get()
            || d.1;
        snap_connected && fw().prompt.get() && !deferred && fw().phase.get().presents()
    };
    move || {
        open().then(|| {
            let on_cancel = Callback::new(move |()| fw_dismiss());
            let on_confirm = Callback::new(move |()| match fw().phase.get_untracked() {
                Phase::Available => fw_confirm_download(),
                Phase::Ready => {
                    let can_load = app.snapshot.with_untracked(|snap| {
                        matches!(
                            snap.state,
                            DeviceState::Bootloader
                                | DeviceState::Uninitialized
                                | DeviceState::ConfigMode
                        )
                    });
                    if can_load {
                        fw_apply(app);
                    } else {
                        fw_open_tab(app);
                    }
                }
                _ => {}
            });
            dialog(fw_dialog_view(app), on_cancel, on_confirm)
        })
    }
}

/// App auto-check at start and the app update dialog. Mounted by [`UpdateHosts`].
#[component]
fn AppUpdateHost() -> impl IntoView {
    let app = use_app();
    let open = move || {
        let (connected, locked) = app
            .snapshot
            .with(|snap| (snap.state != DeviceState::Disconnected, is_locked(snap)));
        let deferred = app.working.with(Option::is_some) || (connected && locked);
        let s = app_updates();
        s.prompt.get() && !deferred && s.phase.get().presents()
    };
    move || {
        open().then(|| {
            let on_cancel = Callback::new(move |()| app_dismiss());
            let on_confirm = Callback::new(move |()| {
                if app_updates().can_install.get_untracked() {
                    app_confirm_download();
                } else {
                    app_open_release_page();
                }
            });
            dialog(app_dialog_view(), on_cancel, on_confirm)
        })
    }
}

/// Global update hosts and dialogs plus WorkingDialog progress text; mount once next to the other global overlays.
#[component]
pub fn UpdateHosts() -> impl IntoView {
    let app = use_app();
    let loaded = RwSignal::new(false);
    follow_progress(app);
    // Tray "Check for Updates…": forced app + firmware checks, shown like "Check now".
    backend().on_check_updates(move || {
        app_check_now();
        fw_check_now(app);
    });
    spawn_local(async move {
        // Read prefs ourselves so a stored "off" is honoured before the first check.
        let prefs = backend().prefs_get().await;
        loaded.set(true);
        app_start_auto_check(prefs.auto_update);
    });
    view! {
        <AppUpdateHost />
        <FirmwareUpdateHost loaded=loaded />
    }
}

#[cfg(test)]
mod tests {
    //! Pure helpers of the update flows.

    use super::*;

    /// Percent is capped at 100 and unknown without a total.
    #[test]
    fn percent_rules() {
        assert_eq!(percent(50, Some(200)), Some(25));
        assert_eq!(percent(500, Some(200)), Some(100));
        assert_eq!(percent(5, None), None);
        assert_eq!(percent(5, Some(0)), None);
    }

    /// Integrity and location errors pop the dialog on auto-checks; network errors do not.
    #[test]
    fn serious_errors() {
        assert!(serious(
            "The downloaded firmware failed integrity verification (SHA-256). It was not sent to OnlyKey."
        ));
        assert!(serious(
            "Firmware download refused: the location is not an allowed HTTPS GitHub path."
        ));
        assert!(!serious("Could not reach the firmware server."));
    }
}
