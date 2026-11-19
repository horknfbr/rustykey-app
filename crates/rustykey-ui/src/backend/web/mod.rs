//! Browser (ChromeOS) backend: the core engine over WebHID ([`hid`]), `localStorage` prefs,
//! `<input type=file>` / `<a download>` files, `window.open` links. No app or firmware updater.

mod hid;

use super::{AppUpdate, Backend, FirmwareRelease, Platform, Prefs, PrefsPatch};
use futures::channel::oneshot;
use onlykey_core::api::{Command, DeviceError, Event, Reply, Snapshot};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, HtmlInputElement, Storage, Url};

/// Error for desktop-only host features.
const NOT_AVAILABLE: &str = "Not available in the browser version of RustyKey.";
/// `localStorage` key of the prefs JSON.
const PREFS_KEY: &str = "rustykey.prefs";
/// Largest file `pick_text_file` reads.
const MAX_FILE_BYTES: f64 = 4.0 * 1024.0 * 1024.0;
/// How long a download's blob URL lives before it is revoked.
const REVOKE_AFTER_MS: i32 = 10_000;

/// Stateless handle to the page's WebHID driver and browser host features.
pub struct WebBackend;

impl WebBackend {
    /// "Connect OnlyKey": Chrome's device chooser (call from a click), then connect.
    pub async fn request_device(&self) {
        hid::request_device().await;
    }
}

/// `window.localStorage`, if the browser allows it here.
fn storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// An event handler that fires `tx` the first time it runs (later calls do nothing).
fn once_flag(tx: oneshot::Sender<()>) -> Closure<dyn Fn()> {
    let slot = Rc::new(RefCell::new(Some(tx)));
    Closure::new(move || {
        if let Some(tx) = slot.borrow_mut().take() {
            let _ = tx.send(());
        }
    })
}

impl Backend for WebBackend {
    /// Runs the command on the in-page engine.
    async fn send(&self, cmd: Command) -> Result<Reply, DeviceError> {
        hid::send(cmd).await
    }

    /// The engine's snapshot.
    async fn snapshot(&self) -> Snapshot {
        hid::snapshot()
    }

    /// Registers `f` and starts the WebHID driver.
    fn on_event(&self, f: impl Fn(Event) + 'static) {
        hid::on_event(f);
    }

    /// Prefs JSON from `localStorage`; defaults if absent, unreadable or blocked.
    async fn prefs_get(&self) -> Prefs {
        storage()
            .and_then(|s| s.get_item(PREFS_KEY).ok().flatten())
            .and_then(|text| js_sys::JSON::parse(&text).ok())
            .and_then(|v| serde_wasm_bindgen::from_value(v).ok())
            .unwrap_or_default()
    }

    /// Merges `patch` into the `localStorage` prefs JSON and returns the result.
    async fn prefs_set(&self, patch: PrefsPatch) -> Result<Prefs, String> {
        let fail = || "Could not save preferences in this browser.".to_string();
        let prefs = self.prefs_get().await.merged(&patch);
        let value = serde_wasm_bindgen::to_value(&prefs).map_err(|_| fail())?;
        let text: String = js_sys::JSON::stringify(&value).map_err(|_| fail())?.into();
        storage()
            .ok_or_else(fail)?
            .set_item(PREFS_KEY, &text)
            .map_err(|_| fail())?;
        Ok(prefs)
    }

    /// Hidden `<input type=file>` limited to `accept`; `None` if cancelled, the extension is not
    /// in `accept`, the file is over 4 MB, or it cannot be read as text.
    async fn pick_text_file(&self, accept: &[&str]) -> Option<(String, String)> {
        let doc = web_sys::window()?.document()?;
        let input: HtmlInputElement = doc.create_element("input").ok()?.dyn_into().ok()?;
        input.set_type("file");
        let exts: Vec<String> = accept
            .iter()
            .map(|e| format!(".{}", e.trim_start_matches('.').to_lowercase()))
            .collect();
        input.set_accept(&exts.join(","));
        let (tx, rx) = oneshot::channel();
        let done = once_flag(tx);
        for event in ["change", "cancel"] {
            input
                .add_event_listener_with_callback(event, done.as_ref().unchecked_ref())
                .ok()?;
        }
        input.click();
        rx.await.ok()?;
        drop(done);
        let file = input.files()?.get(0)?;
        let name = file.name();
        let lower = name.to_lowercase();
        if !exts.is_empty() && !exts.iter().any(|e| lower.ends_with(e.as_str())) {
            return None;
        }
        if file.size() > MAX_FILE_BYTES {
            return None;
        }
        let text = file.text().await.ok()?;
        Some((name, text.as_string()?))
    }

    /// Downloads `text` as `default_name` via a blob URL; true once the download is started.
    async fn save_text_file(&self, default_name: &str, text: &str) -> bool {
        let Some(doc) = web_sys::window().and_then(|w| w.document()) else {
            return false;
        };
        let opts = BlobPropertyBag::new();
        opts.set_type("text/plain;charset=utf-8");
        let parts = js_sys::Array::of1(&JsValue::from_str(text));
        let Ok(blob) = Blob::new_with_str_sequence_and_options(&parts, &opts) else {
            return false;
        };
        let Ok(url) = Url::create_object_url_with_blob(&blob) else {
            return false;
        };
        let Some(a) = doc
            .create_element("a")
            .ok()
            .and_then(|e| e.dyn_into::<HtmlAnchorElement>().ok())
        else {
            let _ = Url::revoke_object_url(&url);
            return false;
        };
        a.set_href(&url);
        a.set_download(default_name);
        a.click();
        wasm_bindgen_futures::spawn_local(async move {
            hid::sleep(REVOKE_AFTER_MS).await;
            let _ = Url::revoke_object_url(&url);
        });
        true
    }

    /// Opens an `https://` URL in a new tab (`noopener`); anything else is ignored.
    async fn open_url(&self, url: &str) {
        if !url.starts_with("https://") {
            return;
        }
        if let Some(w) = web_sys::window() {
            let _ = w.open_with_url_and_target_and_features(url, "_blank", "noopener");
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
