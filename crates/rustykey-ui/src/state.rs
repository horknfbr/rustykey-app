//! App-wide state (Leptos context): device snapshot, messages, working dialog, tab, prefs. Never holds secrets.

use crate::backend::{Backend, Prefs, backend};
use futures::channel::oneshot;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{DeviceState, Event, Snapshot};
use std::future::Future;

/// Most device messages kept (newest first).
const MAX_MESSAGES: usize = 50;

/// Sidebar tabs, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Setup wizard.
    Setup,
    /// Slot grid + editor.
    Slots,
    /// Private keys.
    Keys,
    /// Backup / restore.
    Backup,
    /// Firmware load.
    Firmware,
    /// Device preferences.
    Preferences,
    /// Yubikey OTP + raw keys.
    Advanced,
    /// App update + external tools.
    Tools,
}

impl Tab {
    /// All tabs in sidebar order.
    pub const ALL: [Tab; 8] = [
        Tab::Setup,
        Tab::Slots,
        Tab::Keys,
        Tab::Backup,
        Tab::Firmware,
        Tab::Preferences,
        Tab::Advanced,
        Tab::Tools,
    ];

    /// Sidebar label.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Setup => "Setup",
            Tab::Slots => "Slots",
            Tab::Keys => "Keys",
            Tab::Backup => "Backup",
            Tab::Firmware => "Firmware",
            Tab::Preferences => "Preferences",
            Tab::Advanced => "Advanced",
            Tab::Tools => "Tools",
        }
    }
}

/// What the WorkingDialog shows while a long operation runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Working {
    /// What is running.
    pub message: String,
    /// 0–100 once the device reports progress.
    pub progress: Option<u8>,
}

/// An open ConfirmDialog; dropping `reply` answers "cancel".
#[derive(Debug)]
pub struct ConfirmRequest {
    /// Dialog title.
    pub title: String,
    /// Dialog body.
    pub message: String,
    /// Confirm button text.
    pub confirm_label: String,
    /// Red confirm button.
    pub danger: bool,
    /// Answer channel.
    pub reply: oneshot::Sender<bool>,
}

/// Handles to every global signal; `Copy`, fetch with [`use_app`].
#[derive(Clone, Copy)]
pub struct AppState {
    /// Latest device snapshot.
    pub snapshot: RwSignal<Snapshot>,
    /// Device messages, newest first, at most 50; cleared when the epoch changes.
    pub messages: RwSignal<Vec<String>>,
    /// Open WorkingDialog, if any.
    pub working: RwSignal<Option<Working>>,
    /// Selected sidebar tab.
    pub tab: RwSignal<Tab>,
    /// Stored prefs (theme lives here).
    pub prefs: RwSignal<Prefs>,
    /// Last DUO unlock error text ("Incorrect PIN", "…password attempts…").
    pub pin_error: RwSignal<Option<String>>,
    /// Open ConfirmDialog, if any.
    pub confirm: RwSignal<Option<ConfirmRequest>>,
    /// True while a Setup step other than 1 or 11 is open; firmware update prompts wait until it clears.
    #[allow(
        dead_code,
        reason = "set by Setup (task 9), read by the firmware prompt (task 11)"
    )]
    pub setup_blocks_firmware_prompt: RwSignal<bool>,
    /// `snapshot.session_epoch`, as its own memo so keyed blocks rerun only when it changes.
    pub epoch: Memo<u64>,
}

/// The app state from context (provided by [`AppState::start`]).
pub fn use_app() -> AppState {
    expect_context()
}

/// True when the LockScreen applies: device reports locked (incl. a config-mode lock), not bootloader/uninitialized.
pub fn is_locked(s: &Snapshot) -> bool {
    s.locked && matches!(s.state, DeviceState::Locked | DeviceState::ConfigMode)
}

/// Tab after a snapshot change (`useDeviceStore.ts:136-145`, `:206-285`): Setup on unplug and on an idle lock;
/// Slots on an unlock that is not a config-mode one (Setup if uninitialized/bootloader); else unchanged.
pub fn next_tab(old: &Snapshot, new: &Snapshot, current: Tab) -> Tab {
    use DeviceState::*;
    let was_connected = old.state != Disconnected;
    // The store treats "no device" as locked, so connecting to an unlocked device counts as an unlock.
    let was_locked = old.locked || !was_connected;
    if new.state == Disconnected {
        return if was_connected { Tab::Setup } else { current };
    }
    let config = new.state == ConfigMode;
    if was_connected && !was_locked && new.locked {
        return if config { current } else { Tab::Setup };
    }
    if was_locked && !new.locked && !config {
        return if matches!(new.state, Bootloader | Uninitialized) {
            Tab::Setup
        } else {
            Tab::Slots
        };
    }
    current
}

/// Puts `theme` on `<html>` (`.light` class; dark is the default).
pub fn apply_theme(theme: &str) {
    if let Some(root) = document().document_element() {
        let _ = root
            .class_list()
            .toggle_with_force("light", theme == "light");
    }
}

impl AppState {
    /// Creates the state, provides it as context, loads prefs + snapshot and subscribes to events.
    pub fn start() -> Self {
        let snapshot = RwSignal::new(Snapshot::default());
        let state = Self {
            snapshot,
            messages: RwSignal::new(Vec::new()),
            working: RwSignal::new(None),
            tab: RwSignal::new(Tab::Setup),
            prefs: RwSignal::new(Prefs::default()),
            pin_error: RwSignal::new(None),
            confirm: RwSignal::new(None),
            setup_blocks_firmware_prompt: RwSignal::new(false),
            epoch: Memo::new(move |_| snapshot.with(|s| s.session_epoch)),
        };
        provide_context(state);
        backend().on_event(move |e| state.on_event(e));
        spawn_local(async move {
            let prefs = backend().prefs_get().await;
            apply_theme(&prefs.theme);
            state.prefs.set(prefs);
            state.apply_snapshot(backend().snapshot().await);
        });
        state
    }

    /// Routes one backend event into the signals.
    fn on_event(self, event: Event) {
        match event {
            Event::Snapshot(s) => self.apply_snapshot(s),
            Event::Message { text } => self.messages.update(|m| {
                m.insert(0, text);
                m.truncate(MAX_MESSAGES);
            }),
            Event::Error { text } => {
                if text.contains("password attempts") || text.contains("Incorrect PIN") {
                    self.pin_error.set(Some(text));
                }
            }
            Event::Progress { percent, .. } => self.working.update(|w| {
                if let Some(w) = w {
                    w.progress = Some(percent);
                }
            }),
        }
    }

    /// Stores a snapshot; on a new epoch wipes messages, working, PIN error and any open confirm; picks the tab.
    fn apply_snapshot(self, new: Snapshot) {
        let old = self.snapshot.get_untracked();
        if new.session_epoch != old.session_epoch {
            self.messages.set(Vec::new());
            self.working.set(None);
            self.confirm.set(None);
        }
        if new.state != old.state || new.session_epoch != old.session_epoch {
            self.pin_error.set(None);
        }
        let current = self.tab.get_untracked();
        let tab = next_tab(&old, &new, current);
        // `set` notifies even for an equal value, which would remount the page and wipe its local state.
        if tab != current {
            self.tab.set(tab);
        }
        self.snapshot.set(new);
    }

    /// Saves a prefs change (and applies the theme); returns the host's error text on failure.
    pub async fn save_prefs(self, prefs: Prefs) -> Result<(), String> {
        apply_theme(&prefs.theme);
        self.prefs.set(prefs.clone());
        backend().prefs_set(prefs).await
    }

    /// Shows the WorkingDialog with `message` while `fut` runs.
    #[allow(dead_code, reason = "used by the pages in tasks 9-11")]
    pub async fn working<T>(self, message: impl Into<String>, fut: impl Future<Output = T>) -> T {
        self.working.set(Some(Working {
            message: message.into(),
            progress: None,
        }));
        let out = fut.await;
        self.working.set(None);
        out
    }

    /// Opens the ConfirmDialog and resolves true on confirm, false on cancel / Esc / session wipe.
    #[allow(dead_code, reason = "used by the pages in tasks 9-11")]
    pub async fn confirm(
        self,
        title: impl Into<String>,
        message: impl Into<String>,
        confirm_label: impl Into<String>,
        danger: bool,
    ) -> bool {
        let (reply, rx) = oneshot::channel();
        self.confirm.set(Some(ConfirmRequest {
            title: title.into(),
            message: message.into(),
            confirm_label: confirm_label.into(),
            danger,
            reply,
        }));
        rx.await.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    //! Default-tab rules (`useDeviceStore.ts:136-145`, `:206-285`).

    use super::*;
    use DeviceState::*;

    /// A connected snapshot in `state` with the given lock flag.
    fn snap(state: DeviceState, locked: bool) -> Snapshot {
        Snapshot {
            state,
            locked,
            ..Snapshot::default()
        }
    }

    /// Unplug and idle lock go to Setup; first unlock goes to Slots; config-mode lock/unlock and other moves keep the tab.
    #[test]
    fn default_tab_rules() {
        let off = snap(Disconnected, false);
        let locked = snap(Locked, true);
        let unlocked = snap(Unlocked, false);
        let cfg_locked = snap(ConfigMode, true);
        let cfg_unlocked = snap(ConfigMode, false);
        assert_eq!(next_tab(&unlocked, &off, Tab::Keys), Tab::Setup);
        assert_eq!(next_tab(&off, &off, Tab::Tools), Tab::Tools);
        assert_eq!(next_tab(&unlocked, &locked, Tab::Keys), Tab::Setup);
        assert_eq!(next_tab(&unlocked, &cfg_locked, Tab::Keys), Tab::Keys);
        assert_eq!(
            next_tab(&cfg_locked, &cfg_unlocked, Tab::Advanced),
            Tab::Advanced
        );
        assert_eq!(next_tab(&locked, &unlocked, Tab::Setup), Tab::Slots);
        assert_eq!(next_tab(&off, &unlocked, Tab::Setup), Tab::Slots);
        assert_eq!(next_tab(&off, &locked, Tab::Tools), Tab::Tools);
        assert_eq!(
            next_tab(&off, &snap(Uninitialized, false), Tab::Tools),
            Tab::Setup
        );
        assert_eq!(next_tab(&unlocked, &unlocked, Tab::Backup), Tab::Backup);
    }
}
