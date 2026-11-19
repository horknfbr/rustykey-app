//! Backup / Restore page: capture the device-typed backup, verify, save; restore from a file (`Backup.tsx`).

use super::tools::{PseudoTabs, device_type};
use crate::backend::{Backend, backend};
use crate::components::restore_form::RestoreForm;
use crate::components::{Button, HelpTip};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::backup::{extract_block, file_name, verify};
use onlykey_core::protocol::config_mode_how_to;

/// `onlykey-backup-YYYY-MM-DDTHH-mm.txt` for the local time now.
fn backup_file_name() -> String {
    let now = js_sys::Date::new_0();
    // Date parts are small integers, so the casts cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    file_name(
        now.get_full_year() as i32,
        (now.get_month() + 1) as u8,
        now.get_date() as u8,
        now.get_hours() as u8,
        now.get_minutes() as u8,
    )
}

/// Backup / Restore page.
#[component]
pub fn BackupPage() -> impl IntoView {
    let app = use_app();
    let tab = RwSignal::new("backup");
    // The typed backup stays in this page-local signal only; it drops on remount (session epoch).
    let data = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let verified = RwSignal::new(None::<String>);
    let empty = move || data.with(|d| d.trim().is_empty());
    // WebKit autocorrect would alter the typed backup; Leptos has no typed `autocorrect` attribute.
    let area = NodeRef::<leptos::html::Textarea>::new();
    Effect::new(move |_| {
        if let Some(el) = area.get() {
            let _ = el.set_attribute("autocorrect", "off");
        }
    });

    let on_verify = move |_| match data.with_untracked(|d| verify(d)) {
        Ok(msg) => {
            verified.set(Some(msg.into()));
            error.set(None);
        }
        Err(e) => {
            verified.set(None);
            error.set(Some(e.to_string()));
        }
    };
    let on_save = move |_| {
        let block = data.with_untracked(|d| extract_block(d).to_string());
        if block.is_empty() {
            error.set(Some("Backup data cannot be empty.".into()));
            return;
        }
        error.set(None);
        spawn_local(async move {
            backend().save_text_file(&backup_file_name(), &block).await;
        });
    };

    view! {
        <h2 class="page-title">"Backup / Restore"</h2>
        <PseudoTabs tabs=&[("backup", "Backup"), ("restore", "Restore")] active=tab />
        <Show when=move || tab.get() == "backup">
            <div class="stack">
                <h3>
                    "Backup "
                    <HelpTip
                        href="https://docs.crp.to/usersguide.html#secure-encrypted-backup-anywhere"
                        tooltip="The Secure Encrypted Backup Anywhere feature allows you to backup OnlyKey on the go. The way that this works is that the OnlyKey encrypts everything on your OnlyKey using an encryption key and then types it out. This allows saving the backup in a text file or email on any computer."
                    />
                </h3>
                <fieldset class="step-fieldset">
                    <p>
                        <u>"Step 1"</u>
                        ". To begin backup, ensure that you have a backup passphrase set and have an offline copy of this backup passphrase. The same passphrase will be required to restore your OnlyKey."
                    </p>
                    <p>
                        <u>"Step 2"</u>
                        ". Click inside the text area below. Hold the #1 button down on your OnlyKey for 5+ seconds and release. This will TYPE out an encrypted backup of your OnlyKey into the text area."
                    </p>
                    <p>
                        <u>"Step 3"</u>
                        ". Once you see \"-----END ONLYKEY BACKUP-----\", the backup process is complete. Click [Verify Backup] to verify the backup integrity, or [Save File] to save your encrypted backup."
                    </p>
                </fieldset>
                <label class="form-row">
                    <span class="form-label">"Backup data"</span>
                    <textarea
                        rows="4"
                        class="mono"
                        spellcheck="false"
                        autocomplete="off"
                        node_ref=area
                        autocapitalize="off"
                        placeholder="DO NOT type in this field. Click inside here, then hold your OnlyKey button #1 for 5+ seconds."
                        bind:value=data
                    ></textarea>
                </label>
                <div class="button-row">
                    <Button disabled=Signal::derive(empty) on:click=on_verify>
                        "Verify Backup"
                    </Button>
                    <Button disabled=Signal::derive(empty) on:click=on_save>
                        "Save File"
                    </Button>
                    {move || verified.get().map(|m| view! { <span class="status-success">{m}</span> })}
                </div>
                {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
            </div>
        </Show>
        <Show when=move || tab.get() == "restore">
            <div class="stack">
                <h3>
                    "Restore "
                    <HelpTip
                        href="https://docs.crp.to/usersguide.html#restoring-onlykey"
                        tooltip="Using the backup file created, OnlyKey can be restored to a previous state. This also allows restoring to a different OnlyKey or a second OnlyKey in order to have an extra."
                    />
                </h3>
                <fieldset class="step-fieldset">
                    <p>
                        <u>"Step 1"</u>
                        ". To restore a backup file to your OnlyKey, ensure you have loaded the same backup passphrase or backup key you used to create the backup."
                    </p>
                    <p>
                        <u>"Step 2"</u>
                        ". "
                        {move || app.snapshot.with(|s| config_mode_how_to(device_type(s), true))}
                    </p>
                    <p>
                        <u>"Step 3"</u>
                        ". Click [Choose File], select your backup file, then click [Restore to OnlyKey]."
                    </p>
                    <p>
                        <u>"Step 4"</u>
                        ". A progress dialog shows while the backup is sent. Large restores can take 1–2 minutes. When finished, remove and reinsert the OnlyKey."
                    </p>
                </fieldset>
                <RestoreForm />
            </div>
        </Show>
    }
}
