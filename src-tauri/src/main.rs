//! RustyKey desktop entry point.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod device;

use device::{Bus, DeviceService};
use onlykey_core::api::{Command, DeviceError, Reply, Snapshot};
use tauri::{Emitter, Manager, State};

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
        .setup(|app| {
            let handle = app.handle().clone();
            let svc = DeviceService::spawn(make_bus, move |event| {
                let _ = handle.emit("device://event", event);
            });
            app.manage(svc);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![device, snapshot])
        .run(tauri::generate_context!())
        .expect("error while running RustyKey");
}
