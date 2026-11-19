//! Tray / menu-bar icon (SPEC §Tray). The menu is rebuilt in full and re-set on every change,
//! never edited in place (Linux StatusNotifier shows an empty menu otherwise).

use crate::device::DeviceService;
use crate::prefs::{self, Prefs};
use crate::window;
use onlykey_core::api::{Command, DeviceState, Event, Snapshot};
use std::sync::{Mutex, PoisonError};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

/// Id of the one tray icon.
const TRAY_ID: &str = "main";

/// One menu row, as plain data so the layout can be unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A clickable (or greyed-out) item.
    Item {
        /// Menu event id.
        id: &'static str,
        /// Label.
        text: String,
        /// Clickable.
        enabled: bool,
    },
    /// A checkbox bound to a pref.
    Check {
        /// Menu event id.
        id: &'static str,
        /// Label.
        text: &'static str,
        /// Ticked.
        checked: bool,
    },
    /// A divider.
    Separator,
}

/// Status line: "OnlyKey Duo — Unlocked · v3.0.4-prodp", or "No OnlyKey connected".
pub fn status_line(snap: &Snapshot) -> String {
    let state = match snap.state {
        DeviceState::Disconnected => return "No OnlyKey connected".into(),
        DeviceState::Bootloader => "Bootloader",
        DeviceState::Uninitialized => "Uninitialized",
        DeviceState::Locked => "Locked",
        DeviceState::Unlocked => "Unlocked",
        DeviceState::ConfigMode => "Config Mode",
    };
    let name = if snap.product_name.is_empty() {
        "OnlyKey"
    } else {
        &snap.product_name
    };
    match &snap.firmware {
        Some(fw) => format!("{name} — {state} · {fw}"),
        None => format!("{name} — {state}"),
    }
}

/// The full menu for these prefs and this device snapshot, top to bottom.
pub fn model(prefs: &Prefs, snap: &Snapshot) -> Vec<Entry> {
    let item = |id, text: &str, enabled| Entry::Item {
        id,
        text: text.into(),
        enabled,
    };
    let check = |id, text, checked| Entry::Check { id, text, checked };
    let unlocked = snap.state == DeviceState::Unlocked;
    vec![
        item("status", &status_line(snap), false),
        item("open", "Open RustyKey", true),
        item("set_time", "Set Device Time Now", unlocked),
        // Task 15 (1Password sync) enables this when unlocked and the `op` CLI is found.
        item("sync_1password", "Sync from 1Password", false),
        item("check_updates", "Check for Updates…", true),
        Entry::Separator,
        check("autostart", "Start at Login (in tray)", prefs.autostart),
        check(
            "auto_update",
            "Check App Updates Automatically",
            prefs.auto_update,
        ),
        check(
            "auto_update_fw",
            "Check Firmware Updates Automatically",
            prefs.auto_update_fw,
        ),
        check(
            "close_to_tray",
            "Hide to Tray When Window Closes",
            prefs.close_to_tray,
        ),
        Entry::Separator,
        item("quit", "Quit RustyKey", true),
    ]
}

/// Tray icons and the last menu shown (to skip identical rebuilds); Tauri managed state.
struct TrayState {
    /// Icon while no device is connected.
    idle: Image<'static>,
    /// Icon while a device is connected (glyph plus a dot).
    connected: Image<'static>,
    /// Last (menu, connected) applied.
    last: Mutex<Option<(Vec<Entry>, bool)>>,
}

/// The monochrome key glyph from `icons/tray@2x.png`.
fn idle_icon() -> Image<'static> {
    Image::from_bytes(include_bytes!("../icons/tray@2x.png"))
        .expect("bundled tray icon is a valid PNG")
        .to_owned()
}

/// `base` with a filled dot in the bottom-right corner (the "connected" variant).
fn with_dot(base: &Image<'_>) -> Image<'static> {
    let (w, h) = (base.width(), base.height());
    let mut rgba = base.rgba().to_vec();
    let r = w.min(h) as f32 * 0.16;
    let (cx, cy) = (w as f32 - r - 1.0, h as f32 - r - 1.0);
    for y in 0..h {
        for x in 0..w {
            let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
            if dx * dx + dy * dy <= r * r {
                let i = ((y * w + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[0, 0, 0, 255]);
            }
        }
    }
    Image::new_owned(rgba, w, h)
}

/// Builds the native menu from `entries`.
fn build_menu(app: &AppHandle, entries: &[Entry]) -> tauri::Result<Menu<tauri::Wry>> {
    let menu = Menu::new(app)?;
    for entry in entries {
        match entry {
            Entry::Item { id, text, enabled } => {
                menu.append(&MenuItem::with_id(app, *id, text, *enabled, None::<&str>)?)?
            }
            Entry::Check { id, text, checked } => menu.append(&CheckMenuItem::with_id(
                app,
                *id,
                *text,
                true,
                *checked,
                None::<&str>,
            )?)?,
            Entry::Separator => menu.append(&PredefinedMenuItem::separator(app)?)?,
        }
    }
    Ok(menu)
}

/// Rebuilds the tray from the current prefs and device snapshot.
pub fn refresh(app: &AppHandle) {
    let snap = app.state::<DeviceService>().snapshot();
    refresh_with(app, &snap);
}

/// Rebuilds the menu, tooltip and icon for `snap` when anything visible changed.
fn refresh_with(app: &AppHandle, snap: &Snapshot) {
    let (Some(tray), Some(state)) = (app.tray_by_id(TRAY_ID), app.try_state::<TrayState>()) else {
        return;
    };
    let entries = model(&prefs::current(app), snap);
    let connected = snap.state != DeviceState::Disconnected;
    {
        let mut last = state.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.as_ref() == Some(&(entries.clone(), connected)) {
            return;
        }
        *last = Some((entries.clone(), connected));
    }
    match build_menu(app, &entries) {
        Ok(menu) => {
            let _ = tray.set_menu(Some(menu));
        }
        Err(e) => eprintln!("tray: menu build failed: {e}"),
    }
    let _ = tray.set_tooltip(Some(status_line(snap)));
    let icon = if connected {
        &state.connected
    } else {
        &state.idle
    };
    let _ = tray.set_icon(Some(icon.clone()));
    #[cfg(target_os = "macos")]
    let _ = tray.set_icon_as_template(true);
}

/// Runs the action for menu item `id`.
fn on_menu(app: &AppHandle, id: &str) {
    let toggle = |flip: fn(&mut Prefs)| {
        let mut p = prefs::current(app);
        flip(&mut p);
        if let Err(e) = prefs::update(app, p) {
            eprintln!("tray: saving prefs failed: {e}");
        }
    };
    match id {
        "open" => window::show(app),
        "set_time" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = app.state::<DeviceService>().send(Command::SetTime).await;
            });
        }
        "check_updates" => {
            let _ = app.emit("host://check-updates", ());
        }
        "autostart" => toggle(|p| p.autostart = !p.autostart),
        "auto_update" => toggle(|p| p.auto_update = !p.auto_update),
        "auto_update_fw" => toggle(|p| p.auto_update_fw = !p.auto_update_fw),
        "close_to_tray" => toggle(|p| p.close_to_tray = !p.close_to_tray),
        "quit" => app.exit(0),
        _ => {}
    }
}

/// Creates the tray icon, paints the first menu, and keeps it current from device snapshots.
pub fn init(app: &AppHandle) -> tauri::Result<()> {
    let idle = idle_icon();
    let connected = with_dot(&idle);
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(idle.clone())
        .icon_as_template(cfg!(target_os = "macos"))
        // macOS opens the menu on left click; Windows/Linux show the window instead.
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
                && !cfg!(target_os = "macos")
            {
                window::show(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(TrayState {
        idle,
        connected,
        last: Mutex::new(None),
    });
    refresh(app);
    let rx = app.state::<DeviceService>().subscribe();
    let app = app.clone();
    std::thread::Builder::new()
        .name("rustykey-tray".into())
        .spawn(move || {
            for event in rx {
                if let Event::Snapshot(snap) = event {
                    refresh_with(&app, &snap);
                }
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use onlykey_core::api::DeviceKind;

    /// A snapshot in `state` for an OnlyKey Duo on `firmware`.
    fn snap(state: DeviceState, firmware: Option<&str>) -> Snapshot {
        Snapshot {
            state,
            kind: DeviceKind::Duo,
            firmware: firmware.map(Into::into),
            product_name: "OnlyKey Duo".into(),
            ..Snapshot::default()
        }
    }

    /// Status line text for every device state.
    #[test]
    fn status_lines() {
        let fw = Some("v3.0.4-prodp");
        let cases = [
            (DeviceState::Disconnected, "No OnlyKey connected"),
            (
                DeviceState::Bootloader,
                "OnlyKey Duo — Bootloader · v3.0.4-prodp",
            ),
            (
                DeviceState::Uninitialized,
                "OnlyKey Duo — Uninitialized · v3.0.4-prodp",
            ),
            (DeviceState::Locked, "OnlyKey Duo — Locked · v3.0.4-prodp"),
            (
                DeviceState::Unlocked,
                "OnlyKey Duo — Unlocked · v3.0.4-prodp",
            ),
            (
                DeviceState::ConfigMode,
                "OnlyKey Duo — Config Mode · v3.0.4-prodp",
            ),
        ];
        for (state, want) in cases {
            assert_eq!(status_line(&snap(state, fw)), want);
        }
        assert_eq!(
            status_line(&snap(DeviceState::Bootloader, None)),
            "OnlyKey Duo — Bootloader"
        );
        let unnamed = Snapshot {
            state: DeviceState::Locked,
            ..Snapshot::default()
        };
        assert_eq!(status_line(&unnamed), "OnlyKey — Locked");
    }

    /// Ids of the clickable items in `entries`.
    fn enabled_ids(entries: &[Entry]) -> Vec<&'static str> {
        entries
            .iter()
            .filter_map(|e| match e {
                Entry::Item {
                    id, enabled: true, ..
                } => Some(*id),
                _ => None,
            })
            .collect()
    }

    /// Item order, enabled flags and checkbox state follow prefs and snapshot.
    #[test]
    fn menu_model() {
        let prefs = Prefs {
            auto_update: false,
            ..Prefs::default()
        };
        let m = model(&prefs, &snap(DeviceState::Unlocked, Some("v3.0.4-prodp")));
        let labels: Vec<String> = m
            .iter()
            .map(|e| match e {
                Entry::Item { text, .. } => text.clone(),
                Entry::Check { text, checked, .. } => {
                    format!("[{}] {text}", if *checked { "x" } else { " " })
                }
                Entry::Separator => "---".into(),
            })
            .collect();
        assert_eq!(
            labels,
            [
                "OnlyKey Duo — Unlocked · v3.0.4-prodp",
                "Open RustyKey",
                "Set Device Time Now",
                "Sync from 1Password",
                "Check for Updates…",
                "---",
                "[x] Start at Login (in tray)",
                "[ ] Check App Updates Automatically",
                "[x] Check Firmware Updates Automatically",
                "[x] Hide to Tray When Window Closes",
                "---",
                "Quit RustyKey",
            ]
        );
        assert_eq!(
            enabled_ids(&m),
            ["open", "set_time", "check_updates", "quit"]
        );
        for state in [
            DeviceState::Disconnected,
            DeviceState::Bootloader,
            DeviceState::Uninitialized,
            DeviceState::Locked,
            DeviceState::ConfigMode,
        ] {
            let m = model(&prefs, &snap(state, None));
            assert_eq!(
                enabled_ids(&m),
                ["open", "check_updates", "quit"],
                "{state:?}"
            );
        }
    }

    /// The connected icon differs only by the added dot.
    #[test]
    fn connected_icon_adds_dot() {
        let idle = idle_icon();
        let dot = with_dot(&idle);
        assert_eq!((dot.width(), dot.height()), (idle.width(), idle.height()));
        assert_ne!(dot.rgba(), idle.rgba());
        let (w, h) = (dot.width() as usize, dot.height() as usize);
        let centre = ((h * 5 / 6) * w + w * 5 / 6) * 4;
        assert_eq!(&dot.rgba()[centre..centre + 4], &[0, 0, 0, 255]);
    }
}
