//! Persisted preferences (`settings.json` in the app config dir via `tauri-plugin-store`).
//! Never holds secrets.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
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
    /// SPEC defaults: `autostart` off (it mirrors the OS at start), every other flag on, dark theme.
    fn default() -> Self {
        Self {
            autostart: false,
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

/// The OS login-item state (LaunchAgent / Run key / autostart entry); false when it cannot be read.
pub fn os_autostart(app: &AppHandle) -> bool {
    app.autolaunch().is_enabled().unwrap_or(false)
}

/// Turns the OS login item on or off and returns what the OS reports afterwards (`on` if it
/// cannot tell), as the original app's tray toggle does.
fn set_os_autostart(app: &AppHandle, on: bool) -> bool {
    let launcher = app.autolaunch();
    let result = if on {
        launcher.enable()
    } else {
        launcher.disable()
    };
    if let Err(e) = result {
        eprintln!("autostart: {e}");
    }
    launcher.is_enabled().unwrap_or(on)
}

/// Merges the keys in `patch` into `old`. Unknown keys or wrong types are an error. Calls
/// `set_os` (returns the resulting OS state) only when the patch changes `autostart`.
pub fn apply(
    old: &Prefs,
    patch: &Map<String, Value>,
    set_os: impl FnOnce(bool) -> bool,
) -> Result<Prefs, String> {
    let Value::Object(mut map) = serde_json::to_value(old).map_err(|e| e.to_string())? else {
        return Err("Preferences are not an object.".into());
    };
    for (key, value) in patch {
        if !map.contains_key(key) {
            return Err(format!("Unknown preference \"{key}\"."));
        }
        map.insert(key.clone(), value.clone());
    }
    let mut next: Prefs = serde_json::from_value(Value::Object(map))
        .map_err(|e| format!("Invalid preference value: {e}"))?;
    if next.autostart != old.autostart {
        next.autostart = set_os(next.autostart);
    }
    Ok(next)
}

/// Current prefs, cloned out of managed state.
pub fn current(app: &AppHandle) -> Prefs {
    app.state::<PrefsState>()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Applies `patch` (see [`apply`]), then emits `host://prefs-changed` with the full prefs,
/// rebuilds the tray and saves the file. Returns the new prefs.
pub fn set(app: &AppHandle, patch: &Map<String, Value>) -> Result<Prefs, String> {
    let next = {
        let state = app.state::<PrefsState>();
        let mut prefs = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = apply(&prefs, patch, |on| set_os_autostart(app, on))?;
        *prefs = next.clone();
        next
    };
    let _ = app.emit("host://prefs-changed", &next);
    crate::tray::refresh(app);
    save(app, &next)?;
    Ok(next)
}

/// `prefs_get`: the current prefs.
#[tauri::command]
pub async fn prefs_get(state: State<'_, PrefsState>) -> Result<Prefs, String> {
    Ok(state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone())
}

/// `prefs_set { patch }`: merges only the keys sent (unknown keys are an error) and returns the
/// full prefs.
#[tauri::command]
pub async fn prefs_set(app: AppHandle, patch: Map<String, Value>) -> Result<Prefs, String> {
    set(&app, &patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `value` as a patch object.
    fn patch(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    /// Only the sent keys change; the OS is not touched without `autostart`.
    #[test]
    fn patch_merges_sent_keys_only() {
        let old = Prefs::default();
        let next = apply(
            &old,
            &patch(json!({"theme": "light", "close_to_tray": false})),
            |_| panic!("autostart must not be touched"),
        )
        .unwrap();
        assert_eq!(
            next,
            Prefs {
                theme: "light".into(),
                close_to_tray: false,
                ..old.clone()
            }
        );
        // Sending the current value is not a change either.
        let same = apply(&old, &patch(json!({"autostart": old.autostart})), |_| {
            panic!("autostart must not be touched")
        })
        .unwrap();
        assert_eq!(same, old);
    }

    /// A changed `autostart` goes to the OS, and the pref takes what the OS reports.
    #[test]
    fn autostart_follows_os() {
        let old = Prefs::default();
        let mut asked = None;
        let next = apply(&old, &patch(json!({"autostart": true})), |on| {
            asked = Some(on);
            false
        })
        .unwrap();
        assert_eq!(asked, Some(true));
        assert!(!next.autostart);
    }

    /// Unknown keys and wrong types are refused.
    #[test]
    fn bad_patches_rejected() {
        let old = Prefs::default();
        let never = |_: bool| -> bool { panic!("autostart must not be touched") };
        let unknown = apply(&old, &patch(json!({"theme": "light", "nope": 1})), never).unwrap_err();
        assert!(unknown.contains("nope"), "{unknown}");
        assert!(apply(&old, &patch(json!({"auto_update": "yes"})), never).is_err());
    }
}
