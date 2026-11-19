//! Modal, ConfirmDialog and WorkingDialog (`dialogs/ConfirmDialog.tsx`, `dialogs/WorkingDialog.tsx`).

use super::{Button, ButtonKind};
use crate::state::use_app;
use leptos::ev;
use leptos::prelude::*;

/// Centred card (max 640 px) on a dim backdrop. Esc calls `on_close` unless `dismissible` is false.
#[component]
pub fn Modal(
    /// Heading.
    #[prop(into)]
    title: String,
    /// Called on Esc.
    #[prop(into, optional)]
    on_close: Option<Callback<()>>,
    /// False: Esc does nothing.
    #[prop(default = true)]
    dismissible: bool,
    /// Body.
    children: Children,
) -> impl IntoView {
    if let (true, Some(on_close)) = (dismissible, on_close) {
        let handle = window_event_listener(ev::keydown, move |e| {
            if e.key() == "Escape" {
                on_close.run(());
            }
        });
        on_cleanup(move || handle.remove());
    }
    let aria = title.clone();
    view! {
        <div class="modal-backdrop">
            <div class="modal" role="dialog" aria-modal="true" aria-label=aria>
                <h3 class="modal-title">{title}</h3>
                {children()}
            </div>
        </div>
    }
}

/// Renders the open [`crate::state::AppState::confirm`] request, if any. Mount once.
#[component]
pub fn ConfirmDialog() -> impl IntoView {
    let app = use_app();
    let answer = move |yes: bool| {
        if let Some(req) = app.confirm.try_update(Option::take).flatten() {
            let _ = req.reply.send(yes);
        }
    };
    move || {
        app.confirm
            .with(|c| {
                c.as_ref().map(|r| {
                    (
                        r.title.clone(),
                        r.message.clone(),
                        r.confirm_label.clone(),
                        r.danger,
                    )
                })
            })
            .map(|(title, message, label, danger)| {
                let kind = if danger {
                    ButtonKind::Danger
                } else {
                    ButtonKind::Primary
                };
                view! {
                    <Modal title=title on_close=Callback::new(move |()| answer(false))>
                        <p class="modal-text">{message}</p>
                        <div class="modal-actions">
                            <Button kind=ButtonKind::Secondary on:click=move |_| answer(false)>
                                "Cancel"
                            </Button>
                            <Button kind=kind on:click=move |_| answer(true)>
                                {label}
                            </Button>
                        </div>
                    </Modal>
                }
            })
    }
}

/// Busy overlay for long device operations; shows `AppState::working`. Mount inside the session-keyed block.
#[component]
pub fn WorkingDialog() -> impl IntoView {
    let app = use_app();
    move || {
        app.working.get().map(|w| {
            view! {
                <Modal title="Working…" dismissible=false>
                    <div class="working" role="alertdialog" aria-busy="true" aria-live="polite">
                        <div class="spinner" aria-hidden="true"></div>
                        <p>{w.message}</p>
                        {w
                            .progress
                            .map(|p| {
                                view! {
                                    <div
                                        class="progress"
                                        role="progressbar"
                                        aria-valuemin="0"
                                        aria-valuemax="100"
                                        aria-valuenow=p
                                    >
                                        <div class="progress-bar" style:width=format!("{p}%")></div>
                                    </div>
                                    <p class="muted small">{format!("{p}%")}</p>
                                }
                            })}
                        <p class="warn small">"Do not remove your OnlyKey."</p>
                    </div>
                </Modal>
            }
        })
    }
}
