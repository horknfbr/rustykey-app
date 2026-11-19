//! RustyKey desktop entry point.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod device;
mod host;
mod prefs;
mod tray;
mod updates;
mod window;

use device::{Bus, DeviceService};
use onlykey_core::api::{Command, DeviceError, Reply, Snapshot};
use std::sync::Mutex;
use tauri::{Emitter, Manager, State, WindowEvent};

/// Runs one device command; errors serialize as the `DeviceError` JSON the UI decodes.
#[tauri::command]
async fn device(cmd: Command, svc: State<'_, DeviceService>) -> Result<Reply, DeviceError> {
    svc.send(cmd).await
}

/// The current device snapshot.
#[tauri::command]
fn snapshot(svc: State<'_, DeviceService>) -> Snapshot {
    svc.snapshot()
}

/// The device bus: hidapi, or a simulated device when built with `mock` and `RUSTYKEY_MOCK` is set.
fn make_bus() -> Box<dyn Bus> {
    #[cfg(feature = "mock")]
    if let Ok(value) = std::env::var("RUSTYKEY_MOCK") {
        match device::mock::MockBus::from_env_value(&value) {
            Some(bus) => {
                eprintln!("device: using mock {value}");
                return Box::new(bus);
            }
            None => eprintln!("device: unknown RUSTYKEY_MOCK={value}; using hidapi"),
        }
    }
    Box::new(device::hid::HidBus::default())
}

/// Starts the Tauri app.
fn main() {
    tauri::Builder::default()
        // Must be first: a second launch hands its args here and exits.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !window::hidden_arg(&args) {
                window::show(app);
            }
        }))
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .args(["--hidden"])
                .build(),
        )
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(updates::Updates::default())
        .setup(|app| {
            let handle = app.handle().clone();
            let svc = DeviceService::spawn(make_bus, move |event| {
                let _ = handle.emit("device://event", event);
            });
            app.manage(svc);

            let prefs = prefs::load(app.handle());
            prefs::apply_autostart(app.handle(), prefs.autostart);
            app.manage::<prefs::PrefsState>(Mutex::new(prefs));

            tray::init(app.handle())?;
            let args: Vec<String> = std::env::args().collect();
            if window::hidden_arg(&args) {
                window::hide(app.handle());
            } else {
                window::show(app.handle());
            }
            Ok(())
        })
        .on_window_event(|win, event| {
            // Close button: hide to tray when the pref is on; otherwise let it close (app quits).
            if let WindowEvent::CloseRequested { api, .. } = event
                && prefs::current(win.app_handle()).close_to_tray
            {
                api.prevent_close();
                window::hide(win.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            device,
            snapshot,
            prefs::prefs_get,
            prefs::prefs_set,
            host::pick_text_file,
            host::save_text_file,
            host::open_url,
            updates::app_update_check,
            updates::app_update_install,
            updates::fw_check,
            updates::fw_download,
        ])
        .build(tauri::generate_context!())
        .expect("error while building RustyKey")
        .run(|_app, _event| {
            // macOS Dock click (or Finder relaunch) while hidden brings the window back.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = _event {
                window::show(_app);
            }
        });
}
