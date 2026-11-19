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
/// In Setup (`on_cancel` given) the button reads "Next" and sits in the step bar with Cancel (`Setup.tsx` `RestoreStep`).
#[component]
pub fn RestoreForm(
    /// Called after a successful restore (Setup advances to the next step).
    #[prop(into, optional)]
    on_done: Option<Callback<()>>,
    /// Setup step bar mode: Cancel button that calls this.
    #[prop(into, optional)]
    on_cancel: Option<Callback<()>>,
) -> impl IntoView {
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
                Ok(_) => {
                    success.try_set(Some(
                        "Backup loaded. Remove and reinsert your OnlyKey to finish the restore."
                            .into(),
                    ));
                    // Skip it if the session reset meanwhile: the caller (and its callback) is gone.
                    if let Some(done) = on_done.filter(|_| restoring.try_get_untracked().is_some())
                    {
                        done.run(());
                    }
                }
                Err(e) => {
                    error.try_set(Some(e));
                }
            }
            restoring.try_set(false);
        });
    };
    let disabled = Signal::derive(move || restoring.get() || file.with(Option::is_none));
    view! {
        <div class="stack">
            <FilePick accept=&["txt", "okb"] file=file />
            {match on_cancel {
                None => view! {
                    <div>
                        <Button disabled=disabled on:click=restore>
                            {move || if restoring.get() { "Restoring..." } else { "Restore to OnlyKey" }}
                        </Button>
                    </div>
                }
                    .into_any(),
                Some(cancel) => view! {
                    <div class="setup-nav">
                        <Button disabled=disabled on:click=restore>
                            {move || if restoring.get() { "Please wait…" } else { "Next" }}
                        </Button>
                        <Button kind=ButtonKind::Secondary on:click=move |_| cancel.run(())>
                            "Cancel"
                        </Button>
                    </div>
                }
                    .into_any(),
            }}
            {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
            {move || success.get().map(|s| view! { <p class="status-success">{s}</p> })}
        </div>
    }
}
