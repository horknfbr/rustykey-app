//! RustyKey desktop entry point.

// Hide the console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// Starts the Tauri app.
fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running RustyKey");
}
