//! The only door from the UI to the device and the host: the `Backend` trait and the impl chosen by cargo feature.

use onlykey_core::api::{Command, DeviceError, Event, Reply, Snapshot};
use onlykey_core::onepassword::{ItemFill, LinkedSlot, OpLogin, OpStatus, SlotSyncResult};
use serde::{Deserialize, Serialize};

#[cfg(feature = "fake")]
mod fake;
#[cfg(all(feature = "tauri", not(any(feature = "fake", feature = "web"))))]
mod tauri;
#[cfg(all(feature = "web", not(feature = "fake")))]
mod web;

/// The backend compiled into this build (`fake` beats `web` beats `tauri`).
#[cfg(feature = "fake")]
pub use fake::FakeBackend as Active;
/// The backend compiled into this build (`fake` beats `web` beats `tauri`).
#[cfg(all(feature = "tauri", not(any(feature = "fake", feature = "web"))))]
pub use tauri::TauriBackend as Active;
/// The backend compiled into this build (`fake` beats `web` beats `tauri`).
#[cfg(all(feature = "web", not(feature = "fake")))]
pub use web::WebBackend as Active;

#[cfg(not(any(feature = "tauri", feature = "web", feature = "fake")))]
compile_error!("enable one of the features `tauri`, `web` or `fake`");

/// Returns the build's backend; it is a stateless handle, so call this wherever you need one.
pub fn backend() -> Active {
    Active
}

/// Which host the UI runs in; desktop-only controls hide on `Web`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "each build constructs only its own variant")]
pub enum Platform {
    /// Tauri desktop app (macOS, Windows, Linux).
    Desktop,
    /// Browser build (ChromeOS, WebHID).
    Web,
}

/// Persisted app preferences (SPEC §Prefs); never holds secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Start at login (hidden, in the tray).
    pub autostart: bool,
    /// Check for app updates automatically.
    pub auto_update: bool,
    /// Check for firmware updates automatically.
    pub auto_update_fw: bool,
    /// Hide to tray when the window closes.
    pub close_to_tray: bool,
    /// `"dark"` or `"light"`.
    pub theme: String,
    /// Last slot editor tab.
    pub slot_editor_mode: String,
}

impl Default for Prefs {
    /// SPEC defaults: every flag on, dark theme.
    fn default() -> Self {
        Self {
            autostart: true,
            auto_update: true,
            auto_update_fw: true,
            close_to_tray: true,
            theme: "dark".into(),
            slot_editor_mode: String::new(),
        }
    }
}

/// A prefs change: only the `Some` keys are sent, and the host merges them into the stored prefs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PrefsPatch {
    /// Start at login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostart: Option<bool>,
    /// Check for app updates automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
    /// Check for firmware updates automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_update_fw: Option<bool>,
    /// Hide to tray when the window closes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_to_tray: Option<bool>,
    /// `"dark"` or `"light"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    /// Last slot editor tab.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_editor_mode: Option<String>,
}

impl Prefs {
    /// Returns these prefs with the keys set in `patch` replaced.
    pub fn merged(mut self, patch: &PrefsPatch) -> Self {
        let p = patch.clone();
        self.autostart = p.autostart.unwrap_or(self.autostart);
        self.auto_update = p.auto_update.unwrap_or(self.auto_update);
        self.auto_update_fw = p.auto_update_fw.unwrap_or(self.auto_update_fw);
        self.close_to_tray = p.close_to_tray.unwrap_or(self.close_to_tray);
        self.theme = p.theme.unwrap_or(self.theme);
        self.slot_editor_mode = p.slot_editor_mode.unwrap_or(self.slot_editor_mode);
        self
    }
}

/// What the 1Password methods answer on hosts without the `op` CLI (the web build).
pub const OP_DESKTOP_ONLY: &str = "1Password sync is only available in the desktop app.";

/// A newer app release found by [`Backend::app_update_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdate {
    /// Release version, e.g. `"0.2.0"`.
    pub version: String,
    /// Release notes (may be empty).
    #[serde(default)]
    pub notes: String,
    /// This install can update itself (false on a Linux `.deb`: show "Open release page" instead).
    pub can_install: bool,
    /// Release page for installs that cannot update themselves.
    pub release_url: String,
}

/// A newer firmware release found by [`Backend::fw_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareRelease {
    /// Release version with a leading `v`, e.g. `"v3.0.5"`.
    pub version: String,
}

/// Everything the UI may ask of the device and host. Single-threaded (wasm), futures are `!Send`.
#[allow(
    dead_code,
    reason = "file/url methods are used by the pages in tasks 9-11"
)]
pub trait Backend {
    /// Runs one device command.
    async fn send(&self, cmd: Command) -> Result<Reply, DeviceError>;
    /// Current device state (a disconnected default if the host cannot say).
    async fn snapshot(&self) -> Snapshot;
    /// Registers `f` for every device event; call once at startup.
    fn on_event(&self, f: impl Fn(Event) + 'static);
    /// Registers `f` for the tray's "Check for Updates…" (`host://check-updates`); no-op without a tray.
    fn on_check_updates(&self, _f: impl Fn() + 'static) {}
    /// Reads prefs (defaults if the host has none).
    async fn prefs_get(&self) -> Prefs;
    /// Merges `patch` (only its `Some` keys) into the stored prefs; returns the full prefs after the merge.
    async fn prefs_set(&self, patch: PrefsPatch) -> Result<Prefs, String>;
    /// Registers `f` for `host://prefs-changed` (full prefs after any change, UI or tray); no-op without a host.
    fn on_prefs_changed(&self, _f: impl Fn(Prefs) + 'static) {}
    /// Shows and focuses the app window (update prompts); no-op without a window to raise.
    async fn show_window(&self) {}
    /// Asks the user for a text file; `accept` lists extensions like `"txt"`. Returns (name, contents).
    async fn pick_text_file(&self, accept: &[&str]) -> Option<(String, String)>;
    /// Asks the user where to save `text`; true when saved.
    async fn save_text_file(&self, default_name: &str, text: &str) -> bool;
    /// Opens an https URL in the system browser.
    async fn open_url(&self, url: &str);
    /// Which host this is.
    fn platform(&self) -> Platform;
    /// Checks for a newer app release (15 s timeout on the host); `None` = up to date. `force` = user asked.
    async fn app_update_check(&self, force: bool) -> Result<Option<AppUpdate>, String>;
    /// Downloads, verifies and installs the release found by the last check, then restarts the app.
    /// `on_progress(received, total)` gets download bytes as they arrive (`total` unknown = `None`).
    async fn app_update_install(
        &self,
        on_progress: impl Fn(u64, Option<u64>) + 'static,
    ) -> Result<(), String>;
    /// Checks GitHub for newer firmware than the connected device's (15 s timeout); `None` = up to date.
    async fn fw_check(&self, force: bool) -> Result<Option<FirmwareRelease>, String>;
    /// Downloads the latest STD firmware (allowlist + SHA-256 checked, 60 s timeout) as blocks for `LoadFirmware`.
    async fn fw_download(&self) -> Result<Vec<Vec<u8>>, String>;
    /// Whether the 1Password CLI is usable (never prompts Touch ID).
    async fn op_status(&self) -> Result<OpStatus, String> {
        Err(OP_DESKTOP_ONLY.into())
    }
    /// Items tagged `onlykey/slot-N` with their link state (no secrets).
    async fn op_list(&self) -> Result<Vec<LinkedSlot>, String> {
        Err(OP_DESKTOP_ONLY.into())
    }
    /// Writes linked 1Password items to the device (all linked slots, or just `slots`).
    async fn op_sync(&self, _slots: Option<Vec<u8>>) -> Result<Vec<SlotSyncResult>, String> {
        Err(OP_DESKTOP_ONLY.into())
    }
    /// Stores the `op --account` choice (`None` = the CLI's default account).
    async fn op_set_account(&self, _account: Option<String>) -> Result<(), String> {
        Err(OP_DESKTOP_ONLY.into())
    }
    /// Login items for the editor's picker (titles only).
    async fn op_logins(&self) -> Result<Vec<OpLogin>, String> {
        Err(OP_DESKTOP_ONLY.into())
    }
    /// One item mapped to slot editor values (secrets; call only on the user's explicit pick).
    async fn op_item_form(&self, _id: &str) -> Result<ItemFill, String> {
        Err(OP_DESKTOP_ONLY.into())
    }
}

#[cfg(test)]
mod tests {
    //! Prefs patch merge.

    use super::*;

    /// Only the patched keys change.
    #[test]
    fn patch_merges_and_serializes_only_set_keys() {
        let patch = PrefsPatch {
            theme: Some("light".into()),
            ..PrefsPatch::default()
        };
        let merged = Prefs::default().merged(&patch);
        assert_eq!(merged.theme, "light");
        assert_eq!(
            Prefs {
                theme: "dark".into(),
                ..merged
            },
            Prefs::default()
        );
    }
}
