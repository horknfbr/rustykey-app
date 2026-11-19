//! Browser (WebHID) backend stub; task 12 runs the core engine here. Until then it reports no device.

use super::{AppUpdate, Backend, FirmwareRelease, Platform, Prefs};
use onlykey_core::api::{Command, DeviceError, Event, Reply, Snapshot};

/// Error for desktop-only host features.
const NOT_AVAILABLE: &str = "Not available in the browser version of RustyKey.";

/// Placeholder WebHID backend: always disconnected.
pub struct WebBackend;

impl Backend for WebBackend {
    /// No device yet.
    async fn send(&self, _cmd: Command) -> Result<Reply, DeviceError> {
        Err(DeviceError::Disconnected)
    }

    /// Disconnected default.
    async fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }

    /// No events yet.
    fn on_event(&self, _f: impl Fn(Event) + 'static) {}

    /// Defaults (task 12: localStorage).
    async fn prefs_get(&self) -> Prefs {
        Prefs::default()
    }

    /// Not stored yet (task 12: localStorage).
    async fn prefs_set(&self, _prefs: Prefs) -> Result<(), String> {
        Ok(())
    }

    /// Not yet (task 12: file input).
    async fn pick_text_file(&self, _accept: &[&str]) -> Option<(String, String)> {
        None
    }

    /// Not yet (task 12: download).
    async fn save_text_file(&self, _default_name: &str, _text: &str) -> bool {
        false
    }

    /// Opens a new tab.
    async fn open_url(&self, url: &str) {
        if let Some(w) = web_sys::window() {
            let _ = w.open_with_url_and_target(url, "_blank");
        }
    }

    /// No app updater in the browser build (SPEC §Web build).
    async fn app_update_check(&self, _force: bool) -> Result<Option<AppUpdate>, String> {
        Err(NOT_AVAILABLE.into())
    }

    /// No app updater in the browser build.
    async fn app_update_install(
        &self,
        _on_progress: impl Fn(u64, Option<u64>) + 'static,
    ) -> Result<(), String> {
        Err(NOT_AVAILABLE.into())
    }

    /// No firmware download in the browser build (GitHub assets have no CORS), so no check either.
    async fn fw_check(&self, _force: bool) -> Result<Option<FirmwareRelease>, String> {
        Err(NOT_AVAILABLE.into())
    }

    /// No firmware download in the browser build; load a firmware file instead.
    async fn fw_download(&self) -> Result<Vec<Vec<u8>>, String> {
        Err(NOT_AVAILABLE.into())
    }

    /// Always web.
    fn platform(&self) -> Platform {
        Platform::Web
    }
}
