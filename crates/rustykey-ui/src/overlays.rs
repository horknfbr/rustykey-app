//! Global overlays: disconnected screen, LockScreen (+ 1500 ms status poll), udev dialog, DUO PIN error toast.

use crate::backend::{Backend, Platform, backend};
use crate::components::{Button, Modal, Notice, NoticeKind};
use crate::state::{Tab, is_locked, use_app};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{Command, DeviceError, DeviceKind, DeviceState, DuoPins};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Linux udev help page (`DeviceDialogs.tsx`).
const UDEV_DOCS_URL: &str = "https://docs.crp.to/appfaq.html#onlykey-app-on-linux";

/// LockScreen status poll interval (`LockScreen.tsx` `LOCK_POLL_MS`).
const LOCK_POLL: Duration = Duration::from_millis(1500);

/// True when a connect error looks like missing udev rules (`utils/platform.ts` `isConnectErrorLikelyUdev`).
fn udev_like(message: &str) -> bool {
    let lower = message.to_lowercase();
    [
        "cannot open device",
        "access denied",
        "permission",
        "failed to open",
        "unable to connect",
    ]
    .iter()
    .any(|s| lower.contains(s))
}

/// True when the webview runs on desktop Linux (the udev dialog is Linux-only, as in the original).
fn is_linux() -> bool {
    window()
        .navigator()
        .user_agent()
        .is_ok_and(|ua| ua.contains("Linux") && !ua.contains("Android"))
}

/// True when the page has no WebHID (`navigator.hid`).
fn webhid_missing() -> bool {
    !js_sys::Reflect::has(&window().navigator(), &"hid".into()).unwrap_or(false)
}

/// "Searching for OnlyKey..." cover over every tab except Tools.
#[component]
pub fn DisconnectedOverlay() -> impl IntoView {
    let app = use_app();
    let show = move || {
        app.snapshot.with(|s| s.state == DeviceState::Disconnected) && app.tab.get() != Tab::Tools
    };
    let hid_hint = backend().platform() == Platform::Web && webhid_missing();
    view! {
        <Show when=show>
            <div class="overlay" data-testid="disconnected-overlay">
                <div class="overlay-icon" aria-hidden="true">
                    "🔌"
                </div>
                <h2>"Searching for OnlyKey..."</h2>
                <p class="muted">
                    "Please insert your OnlyKey into a USB port. The app will automatically detect and connect to your device."
                </p>
                {hid_hint
                    .then(|| {
                        view! {
                            <Notice kind=NoticeKind::Error>
                                "WebHID is unavailable in this browser. Open RustyKey in Chrome."
                            </Notice>
                        }
                    })}
                {move || {
                    app.snapshot
                        .with(|s| s.connect_error.clone())
                        .map(|e| view! { <Notice kind=NoticeKind::Error>{e}</Notice> })
                }}
            </div>
        </Show>
    }
}

/// Polls `RefreshStatus` every 1500 ms (one in flight) while mounted.
#[component]
fn LockPoller() -> impl IntoView {
    let busy = Arc::new(AtomicBool::new(false));
    let tick = move || {
        if busy.swap(true, Ordering::Relaxed) {
            return;
        }
        let busy = busy.clone();
        spawn_local(async move {
            // Timeouts are expected while locked; the next snapshot event carries any change.
            let _ = backend().send(Command::RefreshStatus).await;
            busy.store(false, Ordering::Relaxed);
        });
    };
    tick();
    let handle = set_interval_with_handle(tick, LOCK_POLL).ok();
    on_cleanup(move || {
        if let Some(h) = handle {
            h.clear();
        }
    });
}

/// Lock cover: DUO PIN form or Classic keypad text; polls while locked (`LockScreen.tsx`).
#[component]
pub fn LockScreen() -> impl IntoView {
    let app = use_app();
    let locked = move || app.snapshot.with(is_locked);
    let show = move || locked() && app.tab.get() != Tab::Tools;
    let duo = move || app.snapshot.with(|s| s.kind == DeviceKind::Duo);
    let pin = RwSignal::new(String::new());
    let submitting = RwSignal::new(false);
    let err = move || app.pin_error.get().unwrap_or_default();
    let exceeded = move || err().contains("password attempts");
    let incorrect = move || err().contains("Incorrect PIN") || err().contains("INITIALIZED-D");

    let unlock = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let primary = pin.get_untracked();
        if primary.is_empty() {
            return;
        }
        submitting.set(true);
        spawn_local(async move {
            let cmd = Command::DuoPin {
                pins: DuoPins {
                    primary,
                    ..DuoPins::default()
                },
                setup: false,
            };
            match backend().send(cmd).await {
                Ok(_) => {
                    pin.try_set(String::new());
                    let _ = backend().send(Command::RefreshStatus).await;
                }
                Err(e @ (DeviceError::IncorrectPin | DeviceError::AttemptsExceeded)) => {
                    app.pin_error.set(Some(e.to_string()));
                }
                Err(_) => {}
            }
            submitting.try_set(false);
        });
    };

    view! {
        <Show when=locked>
            <LockPoller />
        </Show>
        <Show when=show>
            <div class="overlay" data-testid="lock-screen">
                <h2>
                    {move || if duo() { "OnlyKey Duo Locked" } else { "OnlyKey Locked" }}
                </h2>
                <Show
                    when=duo
                    fallback=|| {
                        view! {
                            <p class="muted">"Enter your PIN on the OnlyKey six-button keypad."</p>
                            <div class="pill">"Waiting for PIN on device…"</div>
                        }
                    }
                >
                    <form class="lock-form" on:submit=unlock>
                        {move || {
                            if exceeded() {
                                view! {
                                    <p class="error">
                                        "PIN attempts exceeded for this session. Unplug and replug your OnlyKey."
                                    </p>
                                }
                            } else if incorrect() {
                                view! { <p class="error">"Incorrect PIN. Please try again."</p> }
                            } else {
                                view! {
                                    <p class="muted">
                                        "Please enter your PIN below to unlock your device."
                                    </p>
                                }
                            }
                        }}
                        <input
                            type="password"
                            class="pin-input"
                            autocomplete="off"
                            placeholder="Enter PIN"
                            autofocus
                            disabled=move || submitting.get() || exceeded()
                            bind:value=pin
                        />
                        <button
                            type="submit"
                            class="btn btn-primary"
                            disabled=move || submitting.get() || pin.with(String::is_empty) || exceeded()
                        >
                            {move || if submitting.get() { "Unlocking..." } else { "Unlock Device" }}
                        </button>
                    </form>
                </Show>
            </div>
        </Show>
    }
}

/// udev / permission dialog (Linux) and the DUO PIN error toast (`DeviceDialogs.tsx`).
#[component]
pub fn DeviceDialogs() -> impl IntoView {
    let app = use_app();
    let dismissed = RwSignal::new(None::<String>);
    let linux = is_linux();
    let udev_error = move || {
        app.snapshot
            .with(|s| s.connect_error.clone())
            .filter(|e| linux && udev_like(e) && dismissed.with(|d| d.as_ref() != Some(e)))
    };
    let pin_toast = move || {
        app.pin_error.get().filter(|_| {
            app.snapshot
                .with(|s| s.kind == DeviceKind::Duo && is_locked(s))
        })
    };
    view! {
        {move || {
            udev_error()
                .map(|e| {
                    let dismiss = Callback::new(move |()| dismissed.set(Some(e.clone())));
                    view! {
                        <Modal title="Linux USB Permissions" on_close=dismiss>
                            <p class="modal-text">
                                "OnlyKey could not access the device. On Linux you may need udev rules so your user can open the HID device without root."
                            </p>
                            <a
                                href=UDEV_DOCS_URL
                                on:click=|ev| {
                                    ev.prevent_default();
                                    spawn_local(async { backend().open_url(UDEV_DOCS_URL).await });
                                }
                            >
                                "View Linux setup instructions"
                            </a>
                            <div class="modal-actions">
                                <Button on:click=move |_| dismiss.run(())>"OK"</Button>
                            </div>
                        </Modal>
                    }
                })
        }}
        {move || {
            pin_toast()
                .map(|e| {
                    view! {
                        <div class="toast">
                            <Notice kind=NoticeKind::Error>{e}</Notice>
                        </div>
                    }
                })
        }}
    }
}
