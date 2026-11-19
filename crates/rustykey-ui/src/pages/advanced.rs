//! Advanced page: legacy Yubikey OTP security info and raw-hex private keys (`Advanced.tsx`).
//! No client-side config-mode gate: the device refuses and the error says why (`Advanced.tsx:36-40`).

use super::keys::send_all;
use super::tools::device_type;
use crate::components::{Button, ButtonKind};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::Command;
use onlykey_core::keys::raw_key_commands;
use onlykey_core::protocol::{ECC_SLOTS, config_mode_tooltip};

/// Key types (`ECC_TYPES`).
const KEY_TYPES: [(u8, &str); 4] = [
    (1, "Curve25519/Ed25519"),
    (2, "NIST256P1"),
    (3, "SECP256K1"),
    (9, "HMACSHA1"),
];

/// Slots: ECC 1–10 (101–110), HMAC 2 (129), HMAC 1 (130).
fn slot_options() -> Vec<(u8, String)> {
    ECC_SLOTS
        .iter()
        .map(|s| (*s, format!("ECC {} ({s})", s - 100)))
        .chain([(129, "HMAC 2 (129)".into()), (130, "HMAC 1 (130)".into())])
        .collect()
}

/// `<select>` over `(value, label)` bound to a `u8` signal.
fn select_u8(value: RwSignal<u8>, options: Vec<(u8, String)>) -> impl IntoView {
    view! {
        <select on:change=move |ev| {
            if let Ok(v) = event_target_value(&ev).parse() {
                value.set(v);
            }
        }>
            {options
                .into_iter()
                .map(|(v, label)| {
                    view! { <option value=v.to_string() selected=move || value.get() == v>{label}</option> }
                })
                .collect_view()}
        </select>
    }
}

/// Advanced page.
#[component]
pub fn AdvancedPage() -> impl IntoView {
    let app = use_app();
    let public_id = RwSignal::new(String::new());
    let private_id = RwSignal::new(String::new());
    let secret = RwSignal::new(String::new());
    let key_type = RwSignal::new(1u8);
    let slot = RwSignal::new(101u8);
    let key = RwSignal::new(String::new());
    let as_backup = RwSignal::new(false);
    let as_signature = RwSignal::new(false);
    let as_decryption = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let status = RwSignal::new(None::<String>);

    // Runs `cmds` under the WorkingDialog; on success empties `clear` and shows `done`.
    let run =
        move |working: String, cmds: Vec<Command>, done: String, clear: Vec<RwSignal<String>>| {
            spawn_local(async move {
                match app.working(working, send_all(cmds)).await {
                    Ok(()) => {
                        clear.iter().for_each(|f| f.set(String::new()));
                        status.set(Some(done));
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        };

    let save_yubi = move |_| {
        error.set(None);
        status.set(None);
        let (p, q, s) = (
            public_id.get_untracked(),
            private_id.get_untracked(),
            secret.get_untracked(),
        );
        if p.is_empty() || q.is_empty() || s.is_empty() {
            error.set(Some("All Yubikey fields are required.".into()));
            return;
        }
        run(
            "Saving Yubikey security info…".into(),
            vec![Command::SetYubiAuth {
                public_id: p,
                private_id: q,
                secret_key: s,
            }],
            "Yubikey security info saved to OnlyKey.".into(),
            vec![public_id, private_id, secret],
        );
    };
    let wipe_yubi = move |_| {
        spawn_local(async move {
            if !app
                .confirm(
                    "Wipe Yubikey",
                    "Wipe Yubikey security info from OnlyKey?",
                    "Wipe",
                    true,
                )
                .await
            {
                return;
            }
            error.set(None);
            status.set(None);
            run(
                "Wiping Yubikey security info…".into(),
                vec![Command::WipeYubiAuth],
                "Yubikey security info wiped from OnlyKey.".into(),
                Vec::new(),
            );
        });
    };
    let save_key = move |_| {
        error.set(None);
        status.set(None);
        let s = slot.get_untracked();
        match raw_key_commands(
            key_type.get_untracked(),
            s,
            &key.get_untracked(),
            as_backup.get_untracked(),
            as_signature.get_untracked(),
            as_decryption.get_untracked(),
        ) {
            Ok(cmds) => run(
                "Saving private key…".into(),
                cmds,
                format!("Private key saved to slot {s}."),
                vec![key],
            ),
            Err(e) => error.set(Some(e.to_string())),
        }
    };
    let wipe_key = move |_| {
        let s = slot.get_untracked();
        spawn_local(async move {
            if !app
                .confirm(
                    "Wipe private key",
                    format!("Wipe private key from slot {s}?"),
                    "Wipe",
                    true,
                )
                .await
            {
                return;
            }
            error.set(None);
            status.set(None);
            run(
                format!("Wiping private key from slot {s}…"),
                vec![Command::WipePrivateKey { slot: s }],
                format!("Private key wiped from slot {s}."),
                Vec::new(),
            );
        });
    };
    let check = |label: &'static str, value: RwSignal<bool>| {
        view! {
            <label class="check-row">
                <input type="checkbox" bind:checked=value />
                <span>{label}</span>
            </label>
        }
    };

    view! {
        <h2 class="page-title">"Advanced"</h2>
        <hr class="divider" />
        <div class="stack">
            <h3>"Add Yubikey Security Info (Legacy)"</h3>
            <div class="field-row3">
                <input type="text" autocomplete="off" placeholder="Public id" maxlength="17" bind:value=public_id />
                <input type="text" autocomplete="off" placeholder="Private id" maxlength="17" bind:value=private_id />
                <input type="text" autocomplete="off" placeholder="Secret aes key" maxlength="47" bind:value=secret />
            </div>
            <div class="button-row">
                <Button on:click=save_yubi>"Save to OnlyKey"</Button>
                <Button kind=ButtonKind::Danger on:click=wipe_yubi>"Wipe from OnlyKey"</Button>
            </div>
        </div>
        <hr class="divider" />
        <div class="stack">
            <h3>"Add Private Key"</h3>
            <p class="critical-text">
                "Before saving or wiping a private key, put your OnlyKey into "
                <span class="inline-term" title=move || app.snapshot.with(|s| config_mode_tooltip(device_type(s)))>
                    "config mode"
                </span>
                "."
            </p>
            <div class="field-pair">
                <label class="form-row">
                    <span class="form-label">"Type"</span>
                    {select_u8(key_type, KEY_TYPES.iter().map(|(v, l)| (*v, (*l).to_string())).collect())}
                </label>
                <label class="form-row">
                    <span class="form-label">"Slot"</span>
                    {select_u8(slot, slot_options())}
                </label>
            </div>
            <label class="form-row">
                <span class="form-label">"Key"</span>
                <textarea
                    rows="3"
                    class="mono"
                    spellcheck="false"
                    placeholder="Private Key (ECC - 32 bytes hex, HMACSHA1 - 20 bytes hex)"
                    bind:value=key
                ></textarea>
            </label>
            {check("Set as backup key (only one backup may be set)", as_backup)}
            {check("Set as signature key", as_signature)}
            {check("Set as decryption key", as_decryption)}
            <div class="button-row">
                <Button on:click=save_key>"Save to OnlyKey"</Button>
                <Button kind=ButtonKind::Danger on:click=wipe_key>"Wipe from OnlyKey"</Button>
            </div>
        </div>
        {move || status.get().map(|s| view! { <p class="status-success">{s}</p> })}
        {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
    }
}
