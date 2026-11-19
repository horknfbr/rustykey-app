//! Persisted preferences (`settings.json` in the app config dir via `tauri-plugin-store`).
//! Never holds secrets.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_store::StoreExt as _;

/// App preferences; same JSON shape as the UI's `backend::Prefs`.
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

/// Current prefs, kept in Tauri managed state.
pub type PrefsState = Mutex<Prefs>;

/// The settings store (`<app config dir>/settings.json`).
fn store(app: &AppHandle) -> Result<std::sync::Arc<tauri_plugin_store::Store<tauri::Wry>>, String> {
    let path = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join("settings.json");
    app.store(path).map_err(|e| e.to_string())
}

/// Reads prefs from the store; missing or bad values fall back to the defaults.
pub fn load(app: &AppHandle) -> Prefs {
    let Ok(store) = store(app) else {
        return Prefs::default();
    };
    let map: serde_json::Map<_, _> = store.entries().into_iter().collect();
    serde_json::from_value(map.into()).unwrap_or_default()
}

/// Writes every pref field as a top-level key and saves the file.
fn save(app: &AppHandle, prefs: &Prefs) -> Result<(), String> {
    let store = store(app)?;
    if let serde_json::Value::Object(map) =
        serde_json::to_value(prefs).map_err(|e| e.to_string())?
    {
        for (key, value) in map {
            store.set(key, value);
        }
    }
    store.save().map_err(|e| e.to_string())
}

/// Makes the OS login item match `on` (LaunchAgent / Run key / autostart entry).
pub fn apply_autostart(app: &AppHandle, on: bool) {
    let launcher = app.autolaunch();
    let result = match (on, launcher.is_enabled().unwrap_or(!on)) {
        (true, false) => launcher.enable(),
        (false, true) => launcher.disable(),
        _ => Ok(()),
    };
    if let Err(e) = result {
        eprintln!("autostart: {e}");
    }
}

/// Current prefs, cloned out of managed state.
pub fn current(app: &AppHandle) -> Prefs {
    app.state::<PrefsState>()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Stores `prefs`, then applies side effects: autostart (only when it changed) and a tray rebuild.
pub fn update(app: &AppHandle, prefs: Prefs) -> Result<(), String> {
    save(app, &prefs)?;
    let old = std::mem::replace(
        &mut *app
            .state::<PrefsState>()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        prefs.clone(),
    );
    if old.autostart != prefs.autostart {
        apply_autostart(app, prefs.autostart);
    }
    crate::tray::refresh(app);
    Ok(())
}

/// `prefs_get`: the current prefs.
#[tauri::command]
pub async fn prefs_get(state: State<'_, PrefsState>) -> Result<Prefs, String> {
    Ok(state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone())
}

/// `prefs_set { prefs }`: stores prefs and applies their side effects.
#[tauri::command]
pub async fn prefs_set(app: AppHandle, prefs: Prefs) -> Result<(), String> {
    update(&app, prefs)
}
