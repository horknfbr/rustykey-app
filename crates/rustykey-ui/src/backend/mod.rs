//! The only door from the UI to the device and the host: the `Backend` trait and the impl chosen by cargo feature.

use onlykey_core::api::{Command, DeviceError, Event, Reply, Snapshot};
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

/// A newer app release found by [`Backend::app_update_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppUpdate {
    /// Release version, e.g. `"0.2.0"`.
    pub version: String,
    /// Release notes (may be empty).
    #[serde(default)]
    pub notes: String,
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
    /// Reads prefs (defaults if the host has none).
    async fn prefs_get(&self) -> Prefs;
    /// Stores prefs.
    async fn prefs_set(&self, prefs: Prefs) -> Result<(), String>;
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
}
