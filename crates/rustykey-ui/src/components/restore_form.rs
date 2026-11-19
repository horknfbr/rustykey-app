//! Backup restore form shared by the Backup page and Setup step 10: file pick, restore with progress, reinsert notice
//! (`Backup.tsx:47-76`, `:177-188`). Also holds [`FilePick`], the "Choose File" row the firmware loader reuses.

use super::{Button, ButtonKind};
use crate::backend::{Backend, backend};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::Command;
use onlykey_core::backup::restore_payload;

/// A picked text file: (name, contents).
pub type PickedFile = Option<(String, String)>;

/// "Choose File" button plus the chosen file name; `accept` lists extensions without dots.
#[component]
pub fn FilePick(
    /// Allowed extensions, e.g. `&["txt", "okb"]`.
    accept: &'static [&'static str],
    /// The picked file, cleared by the caller after use.
    file: RwSignal<PickedFile>,
    /// Disables the button.
    #[prop(into, optional)]
    disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <div class="file-pick">
            <Button
                kind=ButtonKind::Secondary
                disabled=disabled
                on:click=move |_| {
                    spawn_local(async move {
                        if let Some(picked) = backend().pick_text_file(accept).await {
                            file.set(Some(picked));
                        }
                    });
                }
            >
                "Choose File"
            </Button>
            <span class="muted small">
                {move || {
                    file.with(|f| f.as_ref().map_or("No file chosen".to_string(), |f| f.0.clone()))
                }}
            </span>
        </div>
    }
}

/// Restore-from-backup form: choose a `.txt`/`.okb` backup, "Restore to OnlyKey", then the reinsert notice.
#[component]
pub fn RestoreForm() -> impl IntoView {
    let app = use_app();
    let file = RwSignal::new(None::<(String, String)>);
    let restoring = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let success = RwSignal::new(None::<String>);
    let restore = move |_| {
        // Take the backup text out of the signal so it is gone once the command finishes.
        let Some((_, text)) = file.try_update(Option::take).flatten() else {
            return;
        };
        restoring.set(true);
        error.set(None);
        success.set(None);
        spawn_local(async move {
            let result = match restore_payload(&text) {
                Ok(payload) => app
                    .working(
                        "Preparing restore…",
                        backend().send(Command::Restore { payload }),
                    )
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            drop(text);
            match result {
                Ok(_) => success.set(Some(
                    "Backup loaded. Remove and reinsert your OnlyKey to finish the restore.".into(),
                )),
                Err(e) => error.set(Some(e)),
            }
            restoring.set(false);
        });
    };
    view! {
        <div class="stack">
            <FilePick accept=&["txt", "okb"] file=file />
            <div>
                <Button
                    disabled=Signal::derive(move || restoring.get() || file.with(Option::is_none))
                    on:click=restore
                >
                    {move || if restoring.get() { "Restoring..." } else { "Restore to OnlyKey" }}
                </Button>
            </div>
            {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
            {move || success.get().map(|s| view! { <p class="status-success">{s}</p> })}
        </div>
    }
}
