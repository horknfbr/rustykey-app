//! Desktop backend: Tauri commands via `window.__TAURI__.core.invoke`, events via `__TAURI__.event.listen`.

use super::{AppUpdate, Backend, FirmwareRelease, Platform, Prefs};
use onlykey_core::api::{Command, DeviceError, Event, Reply, Snapshot};
use onlykey_core::onepassword::{ItemFill, LinkedSlot, OpLogin, OpStatus, SlotSyncResult};
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// `window.__TAURI__.core.invoke(cmd, args)`; rejects with the command's error.
    #[wasm_bindgen(catch, js_namespace = ["__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    /// `window.__TAURI__.core.invoke(cmd, args)` with a raw JS args object (needed to pass a `Channel`).
    #[wasm_bindgen(catch, js_namespace = ["__TAURI__", "core"], js_name = invoke)]
    async fn invoke_raw(cmd: &str, args: &JsValue) -> Result<JsValue, JsValue>;

    /// `window.__TAURI__.core.Channel`: streams messages from a command back to the webview.
    #[wasm_bindgen(js_namespace = ["__TAURI__", "core"])]
    type Channel;

    /// `new Channel()`.
    #[wasm_bindgen(constructor, js_namespace = ["__TAURI__", "core"])]
    fn new() -> Channel;

    /// `channel.onmessage = f`.
    #[wasm_bindgen(method, setter)]
    fn set_onmessage(this: &Channel, f: &Closure<dyn Fn(JsValue)>);

    /// `window.__TAURI__.event.listen(event, handler)`.
    #[wasm_bindgen(catch, js_namespace = ["__TAURI__", "event"])]
    async fn listen(event: &str, handler: &Closure<dyn Fn(JsValue)>) -> Result<JsValue, JsValue>;
}

/// Stateless handle to the Tauri bridge.
pub struct TauriBackend;

/// Empty argument object for commands without parameters.
#[derive(Serialize)]
struct NoArgs {}

/// Calls a Tauri command with camelCase `args` (Tauri's default) and decodes the result.
async fn call<T: DeserializeOwned>(cmd: &str, args: impl Serialize) -> Result<T, JsValue> {
    let args = args.serialize(&serde_wasm_bindgen::Serializer::json_compatible())?;
    let value = invoke(cmd, args).await?;
    Ok(serde_wasm_bindgen::from_value(value)?)
}

/// Text of an invoke rejection (src-tauri commands reject with a string).
fn error_text(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// Args of `app_update_check` and `fw_check`.
#[derive(Serialize)]
struct ForceArgs {
    /// User asked (skip the host's session/pref gating).
    force: bool,
}

/// One `app_update_install` progress message.
#[derive(serde::Deserialize)]
struct InstallProgress {
    /// Bytes downloaded so far.
    received: u64,
    /// Total bytes, if the server said.
    total: Option<u64>,
}

/// Turns an invoke rejection into a `DeviceError` (structured if src-tauri sent one, else its text).
fn device_error(e: JsValue) -> DeviceError {
    serde_wasm_bindgen::from_value(e.clone()).unwrap_or_else(|_| DeviceError::Device {
        message: e.as_string().unwrap_or_else(|| format!("{e:?}")),
    })
}

impl Backend for TauriBackend {
    /// `device { cmd }`.
    async fn send(&self, cmd: Command) -> Result<Reply, DeviceError> {
        /// Args of the `device` command.
        #[derive(Serialize)]
        struct Args {
            /// The command.
            cmd: Command,
        }
        call("device", Args { cmd }).await.map_err(device_error)
    }

    /// `snapshot`.
    async fn snapshot(&self) -> Snapshot {
        call("snapshot", NoArgs {}).await.unwrap_or_default()
    }

    /// Listens on `device://event`; the closure lives for the app's lifetime.
    fn on_event(&self, f: impl Fn(Event) + 'static) {
        let handler = Closure::<dyn Fn(JsValue)>::new(move |msg: JsValue| {
            let payload = js_sys::Reflect::get(&msg, &"payload".into()).unwrap_or(msg);
            if let Ok(event) = serde_wasm_bindgen::from_value(payload) {
                f(event);
            }
        });
        wasm_bindgen_futures::spawn_local(async move {
            let _ = listen("device://event", &handler).await;
            handler.forget();
        });
    }

    /// Listens on `host://check-updates` (tray "Check for Updates…"); the closure lives for the app's lifetime.
    fn on_check_updates(&self, f: impl Fn() + 'static) {
        let handler = Closure::<dyn Fn(JsValue)>::new(move |_: JsValue| f());
        wasm_bindgen_futures::spawn_local(async move {
            let _ = listen("host://check-updates", &handler).await;
            handler.forget();
        });
    }

    /// `prefs_get`.
    async fn prefs_get(&self) -> Prefs {
        call("prefs_get", NoArgs {}).await.unwrap_or_default()
    }

    /// `prefs_set { prefs }`.
    async fn prefs_set(&self, prefs: Prefs) -> Result<(), String> {
        /// Args of `prefs_set`.
        #[derive(Serialize)]
        struct Args {
            /// The prefs.
            prefs: Prefs,
        }
        call("prefs_set", Args { prefs }).await.map_err(error_text)
    }

    /// `pick_text_file { filters }`.
    async fn pick_text_file(&self, accept: &[&str]) -> Option<(String, String)> {
        /// Args of `pick_text_file`.
        #[derive(Serialize)]
        struct Args<'a> {
            /// Extensions without dots.
            filters: &'a [&'a str],
        }
        call("pick_text_file", Args { filters: accept })
            .await
            .ok()
            .flatten()
    }

    /// `save_text_file { defaultName, text }`.
    async fn save_text_file(&self, default_name: &str, text: &str) -> bool {
        /// Args of `save_text_file`.
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Args<'a> {
            /// Suggested file name.
            default_name: &'a str,
            /// File contents.
            text: &'a str,
        }
        call("save_text_file", Args { default_name, text })
            .await
            .unwrap_or(false)
    }

    /// `open_url { url }` (src-tauri allows https only).
    async fn open_url(&self, url: &str) {
        /// Args of `open_url`.
        #[derive(Serialize)]
        struct Args<'a> {
            /// The URL.
            url: &'a str,
        }
        let _: Result<(), _> = call("open_url", Args { url }).await;
    }

    /// `app_update_check { force }`.
    async fn app_update_check(&self, force: bool) -> Result<Option<AppUpdate>, String> {
        call("app_update_check", ForceArgs { force })
            .await
            .map_err(error_text)
    }

    /// `app_update_install { onProgress: Channel<{received, total}> }`.
    async fn app_update_install(
        &self,
        on_progress: impl Fn(u64, Option<u64>) + 'static,
    ) -> Result<(), String> {
        let channel = Channel::new();
        let handler = Closure::<dyn Fn(JsValue)>::new(move |msg: JsValue| {
            if let Ok(p) = serde_wasm_bindgen::from_value::<InstallProgress>(msg) {
                on_progress(p.received, p.total);
            }
        });
        channel.set_onmessage(&handler);
        let args = js_sys::Object::new();
        js_sys::Reflect::set(&args, &"onProgress".into(), &channel).map_err(error_text)?;
        let out = invoke_raw("app_update_install", &args).await;
        drop(handler);
        out.map(|_| ()).map_err(error_text)
    }

    /// `fw_check { force }`.
    async fn fw_check(&self, force: bool) -> Result<Option<FirmwareRelease>, String> {
        call("fw_check", ForceArgs { force })
            .await
            .map_err(error_text)
    }

    /// `fw_download` (blocks as arrays of bytes).
    async fn fw_download(&self) -> Result<Vec<Vec<u8>>, String> {
        call("fw_download", NoArgs {}).await.map_err(error_text)
    }

    /// `op_status`.
    async fn op_status(&self) -> Result<OpStatus, String> {
        call("op_status", NoArgs {}).await.map_err(error_text)
    }

    /// `op_list`.
    async fn op_list(&self) -> Result<Vec<LinkedSlot>, String> {
        call("op_list", NoArgs {}).await.map_err(error_text)
    }

    /// `op_sync { slots }`.
    async fn op_sync(&self, slots: Option<Vec<u8>>) -> Result<Vec<SlotSyncResult>, String> {
        /// Args of `op_sync`.
        #[derive(Serialize)]
        struct Args {
            /// Slots to sync; `None` = every linked slot.
            slots: Option<Vec<u8>>,
        }
        call("op_sync", Args { slots }).await.map_err(error_text)
    }

    /// `op_logins`.
    async fn op_logins(&self) -> Result<Vec<OpLogin>, String> {
        call("op_logins", NoArgs {}).await.map_err(error_text)
    }

    /// `op_item_form { id }`.
    async fn op_item_form(&self, id: &str) -> Result<ItemFill, String> {
        /// Args of `op_item_form`.
        #[derive(Serialize)]
        struct Args<'a> {
            /// 1Password item ID.
            id: &'a str,
        }
        call("op_item_form", Args { id }).await.map_err(error_text)
    }

    /// Always desktop.
    fn platform(&self) -> Platform {
        Platform::Desktop
    }
}
