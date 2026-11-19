//! Main window show/hide, with the macOS Dock icon following visibility.

use tauri::{AppHandle, Manager};

/// Label of the one window (tauri.conf.json).
const MAIN: &str = "main";

/// Shows, unminimizes and focuses the main window; on macOS also brings back the Dock icon.
pub fn show(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// `show_window`: shows and focuses the main window (the UI's update prompts call it). A sync
/// command, so it runs on the main thread like every other window change.
#[tauri::command]
pub fn show_window(app: AppHandle) {
    show(&app);
}

/// Hides the main window; on macOS the app becomes menu-bar only (no Dock icon).
pub fn hide(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

/// True when the process was started with `--hidden` (autostart).
pub fn hidden_arg(args: &[String]) -> bool {
    args.iter().any(|a| a == "--hidden")
}
