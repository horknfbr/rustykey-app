//! Sidebar (logo, theme toggle, tabs, status block) and the DeviceMessages terminal (`App.tsx`, `DeviceMessages.tsx`).

use crate::state::{Tab, use_app};
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::DeviceState;

/// Lines the terminal shows at once.
const MESSAGE_LINES: usize = 5;

/// Left column: brand row, tab list, device status.
#[component]
pub fn Sidebar() -> impl IntoView {
    let app = use_app();
    let snap = app.snapshot;
    let connected = move || snap.with(|s| s.state != DeviceState::Disconnected);
    let device = move || {
        snap.with(|s| {
            format!("{} {}", s.product_name, s.firmware.as_deref().unwrap_or(""))
                .trim()
                .to_string()
        })
    };
    let mode = move || match snap.with(|s| s.state) {
        DeviceState::Bootloader => "Bootloader",
        DeviceState::ConfigMode => "Config mode",
        DeviceState::Uninitialized => "Uninitialized",
        DeviceState::Locked => "Locked",
        DeviceState::Unlocked | DeviceState::Disconnected => "Unlocked",
    };
    view! {
        <nav class="sidebar" aria-label="Main navigation">
            <div class="brand">
                <img src="assets/logo.png" alt="" class="brand-logo" draggable="false" />
                <span class="brand-name" title="RustyKey — for OnlyKey devices">
                    "RustyKey"
                </span>
                <ThemeToggle />
            </div>
            <ul class="tabs">
                {Tab::ALL
                    .into_iter()
                    .map(|tab| {
                        view! {
                            <li>
                                <button
                                    type="button"
                                    class="tab"
                                    class:active=move || app.tab.get() == tab
                                    on:click=move |_| app.tab.set(tab)
                                >
                                    {tab.label()}
                                </button>
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
            <div class="status">
                <div>{concat!("RustyKey ", env!("CARGO_PKG_VERSION"))}</div>
                <div class="status-conn" class:on=connected>
                    <span class="dot"></span>
                    {move || if connected() { "Connected" } else { "Disconnected" }}
                </div>
                <Show when=connected>
                    <div class="status-device">{device}</div>
                    <div class="muted">{mode}</div>
                </Show>
            </div>
        </nav>
    }
}

/// Sun/moon button; flips `prefs.theme` and saves it.
#[component]
fn ThemeToggle() -> impl IntoView {
    let app = use_app();
    let dark = move || app.prefs.with(|p| p.theme != "light");
    let label = move || {
        if dark() {
            "Switch to light mode"
        } else {
            "Switch to dark mode"
        }
    };
    view! {
        <button
            type="button"
            class="theme-toggle"
            title=label
            aria-label=label
            on:click=move |_| {
                let mut prefs = app.prefs.get_untracked();
                prefs.theme = if prefs.theme == "light" { "dark" } else { "light" }.into();
                spawn_local(async move {
                    let _ = app.save_prefs(prefs).await;
                });
            }
        >
            {move || if dark() { "☀️" } else { "🌙" }}
        </button>
    }
}

/// 5-line message terminal, newest on top; wheel, arrow keys and ▲▼ scroll; `title` shows full text.
#[component]
pub fn DeviceMessages() -> impl IntoView {
    let app = use_app();
    let offset = RwSignal::new(0usize);
    Effect::new(move |_| {
        app.messages.track();
        offset.set(0);
    });
    let total = move || app.messages.with(Vec::len);
    let newer = move || offset.get() > 0;
    let older = move || offset.get() + MESSAGE_LINES < total();
    let show_newer = move || {
        if newer() {
            offset.update(|o| *o -= 1);
        }
    };
    let show_older = move || {
        if older() {
            offset.update(|o| *o += 1);
        }
    };
    let lines = move || {
        let start = offset.get();
        app.messages.with(|m| {
            (start..start + MESSAGE_LINES)
                .map(|i| (i, m.get(i).cloned()))
                .collect::<Vec<_>>()
        })
    };
    view! {
        <div
            class="terminal"
            tabindex="0"
            aria-label="Device messages"
            on:wheel=move |e: ev::WheelEvent| {
                if e.delta_y() < 0.0 { show_older() } else if e.delta_y() > 0.0 { show_newer() }
            }
            on:keydown=move |e: ev::KeyboardEvent| match e.key().as_str() {
                "ArrowDown" => {
                    e.prevent_default();
                    show_older();
                }
                "ArrowUp" => {
                    e.prevent_default();
                    show_newer();
                }
                _ => {}
            }
        >
            <div class="terminal-lines">
                {move || {
                    lines()
                        .into_iter()
                        .map(|(i, msg)| {
                            let empty = msg.is_none();
                            let title = msg.clone();
                            let text = msg.unwrap_or_default();
                            view! {
                                <div
                                    class="terminal-line"
                                    class:latest=i == 0 && !empty
                                    class:empty=empty
                                    title=title
                                >
                                    <span class="prompt" aria-hidden="true">
                                        {if empty { "" } else { "›" }}
                                    </span>
                                    <span class="terminal-text">{text}</span>
                                </div>
                            }
                        })
                        .collect_view()
                }}
            </div>
            <div class="terminal-nav">
                <button
                    type="button"
                    aria-label="Show newer messages"
                    class:hidden=move || !newer()
                    on:click=move |_| show_newer()
                >
                    "▲"
                </button>
                <button
                    type="button"
                    aria-label="Show older messages"
                    class:hidden=move || !older()
                    on:click=move |_| show_older()
                >
                    "▼"
                </button>
            </div>
        </div>
    }
}
