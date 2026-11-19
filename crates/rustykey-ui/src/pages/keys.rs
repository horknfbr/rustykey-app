//! Private keys page: load an OpenPGP / OpenSSH key into a slot, or wipe one (`Keys.tsx`).

use super::tools::{ExtLink, device_type};
use crate::backend::{Backend, backend};
use crate::components::key_select_dialog::KeySelectDialog;
use crate::components::{Button, ButtonKind};
use crate::state::{AppState, use_app};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::Command;
use onlykey_core::keys::{
    AUTO_LOAD_SLOT, CandidateSummary, ImportError, import_key, import_selected, wipe_key,
};
use onlykey_core::protocol::{ECC_SLOTS, RSA_SLOTS, config_mode_how_to};

/// Sends `cmds` in order, stopping at the first error (its text).
pub async fn send_all(cmds: Vec<Command>) -> Result<(), String> {
    for cmd in cmds {
        backend().send(cmd).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Slot dropdown entries: Auto Load, RSA 1–4, `ECC n (10n)` (`RSA_SLOT_OPTIONS`).
fn slot_options() -> Vec<(u8, String)> {
    std::iter::once((AUTO_LOAD_SLOT, "Auto Load".to_string()))
        .chain(RSA_SLOTS.iter().map(|s| (*s, format!("RSA {s}"))))
        .chain(
            ECC_SLOTS
                .iter()
                .map(|s| (*s, format!("ECC {} ({s})", s - 100))),
        )
        .collect()
}

/// Keys page.
#[component]
pub fn KeysPage() -> impl IntoView {
    let app = use_app();
    let slot = RwSignal::new(AUTO_LOAD_SLOT);
    let key = RwSignal::new(String::new());
    let passphrase = RwSignal::new(String::new());
    let set_as_backup = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let candidates = RwSignal::new(None::<Vec<CandidateSummary>>);

    // Imports with the page's fields; `selection` answers the select dialog (`loadPemWithOptions`).
    let load = move |selection: Option<(usize, u8)>| {
        if key.with_untracked(|k| k.trim().is_empty()) {
            return;
        }
        loading.set(true);
        error.set(None);
        spawn_local(async move {
            let (text, pass) = (key.get_untracked(), passphrase.get_untracked());
            let backup = set_as_backup.get_untracked();
            let built = match selection {
                Some((index, target)) => {
                    import_selected(text.trim(), &pass, index, target, backup, false)
                }
                None => import_key(text.trim(), &pass, slot.get_untracked(), backup, false),
            };
            match built {
                Ok(cmds) => match send_all(cmds).await {
                    Ok(()) => {
                        key.set(String::new());
                        passphrase.set(String::new());
                        candidates.set(None);
                    }
                    Err(e) => error.set(Some(e)),
                },
                Err(ImportError::SelectionRequired(found)) => candidates.set(Some(found)),
                Err(ImportError::Invalid(e)) => error.set(Some(e)),
            }
            loading.set(false);
        });
    };
    let wipe = move |_| {
        let choice = slot.get_untracked();
        let shown = if choice == AUTO_LOAD_SLOT { 1 } else { choice };
        spawn_local(async move {
            if !app
                .confirm(
                    "Wipe key",
                    format!("Wipe key in slot {shown}?"),
                    "Wipe",
                    true,
                )
                .await
            {
                return;
            }
            loading.set(true);
            if let Err(e) = send_all(wipe_key(choice)).await {
                error.set(Some(e));
            }
            loading.set(false);
        });
    };

    view! {
        <h2 class="page-title">"Keys"</h2>
        <div class="stack">
            <p>
                "Load OpenPGP or OpenSSH keys onto your OnlyKey. Keys can be used with "
                <ExtLink href="https://docs.crp.to/onlykey-agent.html">"OnlyKey Agent"</ExtLink>
                " and "
                <ExtLink href="https://docs.crp.to/webcrypt.html">"OnlyKey Webcrypt"</ExtLink>
                "."
            </p>
            <p>
                "Need an OpenPGP key? Follow our guide "
                <ExtLink href="https://docs.crp.to/importpgp.html#generating-keys">"here"</ExtLink>
                " for generating an OpenPGP key with Keybase."
            </p>
            <ConfigModeLead lead="Before loading a key, you must first put your OnlyKey into config mode." app=app />

            <h3>"Load Private Key (PEM Format OpenPGP or OpenSSH)"</h3>
            <div class="field-pair">
                <label class="form-row">
                    <span class="form-label">"Slot"</span>
                    <select on:change=move |ev| {
                        if let Ok(v) = event_target_value(&ev).parse() {
                            slot.set(v);
                        }
                    }>
                        {slot_options()
                            .into_iter()
                            .map(|(v, label)| {
                                view! {
                                    <option value=v.to_string() selected=move || slot.get() == v>
                                        {label}
                                    </option>
                                }
                            })
                            .collect_view()}
                    </select>
                </label>
                <label class="form-row">
                    <span class="form-label">"Passphrase"</span>
                    <input type="password" autocomplete="off" bind:value=passphrase />
                </label>
            </div>
            <label class="form-row">
                <span class="form-label">"Key"</span>
                <textarea
                    rows="5"
                    class="mono"
                    spellcheck="false"
                    placeholder="OpenPGP or OpenSSH Key — paste PEM file contents"
                    bind:value=key
                ></textarea>
            </label>
            <label class="check-row">
                <input type="checkbox" bind:checked=set_as_backup />
                <span>"Set as backup key"</span>
            </label>
            <p class="muted small">
                "(This setting uses the above key for secure backups instead of any backup passphrase you might have set earlier.)"
            </p>
            <div class="button-row">
                <Button
                    disabled=Signal::derive(move || loading.get() || key.with(|k| k.trim().is_empty()))
                    on:click=move |_| load(None)
                >
                    "Save to OnlyKey"
                </Button>
                <Button kind=ButtonKind::Danger disabled=loading on:click=wipe>
                    "Wipe from OnlyKey"
                </Button>
            </div>
            {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
        </div>
        {move || {
            candidates
                .get()
                .map(|found| {
                    view! {
                        <KeySelectDialog
                            candidates=found
                            on_choose=Callback::new(move |sel| load(Some(sel)))
                            on_cancel=Callback::new(move |()| candidates.set(None))
                        />
                    }
                })
        }}
    }
}

/// Red lead-in line plus "To do this hold …" config-mode how-to (`ConfigModeInstructions` with `leadIn`).
#[component]
pub fn ConfigModeLead(
    /// Red lead-in text.
    lead: &'static str,
    /// App state.
    app: AppState,
) -> impl IntoView {
    view! {
        <p class="critical-text">{lead}</p>
        <p>
            {move || format!("To do this {}", app.snapshot.with(|s| config_mode_how_to(device_type(s), false)))}
        </p>
    }
}
