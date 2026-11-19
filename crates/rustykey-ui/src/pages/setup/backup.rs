//! Backup steps: passphrase (8), OpenPGP backup key (9), restore (10) and firmware (11).

use super::{ExtLink, StepNav, Wiz, send_all};
use crate::components::firmware_loader::FirmwareLoader;
use crate::components::key_select_dialog::KeySelectDialog;
use crate::components::restore_form::RestoreForm;
use crate::components::{Button, CheckboxRow, RadioGroup, SelectRow};
use leptos::prelude::*;
use onlykey_core::keys::{
    CandidateSummary, ImportError, backup_key_mode_command, backup_passphrase_commands,
    pgp_backup_commands, validate_backup_passphrase,
};
use onlykey_core::protocol::{ECC_SLOTS, RSA_SLOTS, config_mode_passphrase_hint};

/// Backup key mode radio options: 0 permits changes (default), 1 locks.
fn key_mode_options() -> Vec<(String, String)> {
    vec![
        (
            "0".into(),
            "Permit future backup key changes (Default)".into(),
        ),
        ("1".into(), "Lock backup key on this device".into()),
    ]
}

/// Config-mode hint shown above the backup steps on an initialized device.
fn config_hint(wiz: Wiz) -> impl IntoView {
    move || {
        wiz.initialized()
            .then(|| view! { <p>{config_mode_passphrase_hint(wiz.ty.get())}</p> })
    }
}

/// Password field with a bold label, bound to a step-local signal.
fn secret_field(label: &'static str, aria: &'static str, value: RwSignal<String>) -> impl IntoView {
    view! {
        <label class="form-row">
            <b>{label}</b>
            <input type="password" autocomplete="new-password" aria-label=aria bind:value=value />
        </label>
    }
}

/// Step 8: backup passphrase + confirm; key-mode radios on an uninitialized device in advanced setup.
#[component]
pub(super) fn PassphraseStep(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    let passphrase = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let mode = RwSignal::new("0".to_string());
    let show_mode = move || !wiz.initialized() && wiz.advanced.get();

    let next = Callback::new(move |()| {
        let p = passphrase.get_untracked();
        let c = confirm.get_untracked();
        let mode = (!wiz.initialized_now() && wiz.advanced.get_untracked())
            .then(|| u8::from(mode.get_untracked() == "1"));
        wiz.run(Some("Setting backup passphrase…"), async move {
            validate_backup_passphrase(&p, &c).map_err(|e| e.to_string())?;
            let mut cmds: Vec<_> = mode.map(backup_key_mode_command).into_iter().collect();
            cmds.extend(backup_passphrase_commands(&p));
            send_all(cmds).await?;
            passphrase.try_set(String::new());
            confirm.try_set(String::new());
            wiz.next_or_landing(10);
            Ok(())
        });
    });

    view! {
        <div id="Step8">
            <h3>"Enter a Backup Passphrase"</h3>
            {config_hint(wiz)}
            <p>
                "Your passphrase will be used for secure backup and restore of your OnlyKey so make sure to choose a good one, write it down, and store it in a secure location."
            </p>
            <p>
                "Example of a " <em>"good"</em>
                " passphrase: 'this passphrase is not complex but it is long and it is not a common phrase'"
            </p>
            <p>
                "Example of a " <em>"bad"</em>
                " passphrase: 'the only thing we have to fear is fear itself'"
            </p>
            {secret_field("Enter Passphrase:", "Enter passphrase", passphrase)}
            <p class="muted small setup-hint">"Passphrase must be at least 25 characters"</p>
            {secret_field("Re-Enter Passphrase:", "Re-enter passphrase", confirm)}
            <Show when=show_mode>
                <RadioGroup name="setup-backup-key-mode" value=mode options=key_mode_options() />
            </Show>
            <p>
                "Learn more about secure backup "
                <ExtLink href="https://docs.crp.to/usersguide.html#secure-encrypted-backup-anywhere">
                    "here"
                </ExtLink> "."
            </p>
            <p>
                <Button on:click=move |_| wiz.step.set(9)>
                    <b>"Use OpenPGP key instead of passphrase"</b>
                </Button>
            </p>
        </div>
        <StepNav wiz=wiz on_next=next />
    }
}

/// Step 9: OpenPGP key as the backup key (slot, armored key, passphrase, signature flag, key mode).
#[component]
pub(super) fn PgpStep(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    let slot = RwSignal::new("1".to_string());
    let key = RwSignal::new(String::new());
    let passcode = RwSignal::new(String::new());
    let signature = RwSignal::new(false);
    let mode = RwSignal::new("0".to_string());
    let candidates = RwSignal::new(None::<Vec<CandidateSummary>>);
    let slot_options = RSA_SLOTS
        .iter()
        .map(|s| (s.to_string(), format!("RSA {s}")))
        .chain(
            ECC_SLOTS
                .iter()
                .map(|s| (s.to_string(), format!("ECC {} ({s})", s - 100))),
        )
        .collect();

    // `importPgpBackupKey`: import as backup key, then the key mode; `selection` answers the picker.
    let load = move |selection: Option<(usize, u8)>| {
        let text = key.get_untracked();
        let pass = passcode.get_untracked();
        let slot = slot.get_untracked().parse().unwrap_or(1);
        let sig = signature.get_untracked();
        let mode = u8::from(mode.get_untracked() == "1");
        wiz.run(Some("Loading backup key…"), async move {
            let cmds = match pgp_backup_commands(text.trim(), &pass, slot, selection, sig, mode) {
                Err(ImportError::SelectionRequired(found)) => {
                    candidates.try_set(Some(found));
                    return Ok(());
                }
                other => other.map_err(|e| e.to_string())?,
            };
            send_all(cmds).await?;
            key.try_set(String::new());
            passcode.try_set(String::new());
            wiz.next_or_landing(10);
            Ok(())
        });
    };

    view! {
        <div id="Step9">
            <h3>"Set a Backup Key"</h3>
            {config_hint(wiz)}
            <p>
                "Your OpenPGP key will be used for secure backup and restore of your OnlyKey, make sure to store it in a secure location."
            </p>
            <p>
                "Need a key? Follow our guide "
                <ExtLink href="https://docs.crp.to/importpgp.html#generating-keys">"here"</ExtLink>
                " for generating an OpenPGP key."
            </p>
            <SelectRow label="Slot:" value=slot options=slot_options />
            <label class="form-row">
                <span class="form-label">"Backup OpenPGP RSA/ECC Key:"</span>
                <textarea
                    class="setup-pgp-key"
                    rows="3"
                    spellcheck="false"
                    autocomplete="off"
                    placeholder="OpenPGP Key -- paste PEM file contents"
                    prop:value=move || key.get()
                    on:input=move |ev| key.set(event_target_value(&ev))
                ></textarea>
            </label>
            <label class="form-row">
                <span class="form-label">"Passphrase:"</span>
                <input type="password" autocomplete="new-password" bind:value=passcode />
            </label>
            <CheckboxRow label="Set as signature key - Use key to sign messages" checked=signature />
            <RadioGroup name="setup-pgp-key-mode" value=mode options=key_mode_options() />
            <p>
                <Button on:click=move |_| wiz.step.set(8)>
                    <b>"Use passphrase instead of PGP key"</b>
                </Button>
            </p>
        </div>
        <StepNav wiz=wiz on_next=Callback::new(move |()| load(None)) />
        {move || {
            candidates
                .get()
                .map(|found| {
                    view! {
                        <KeySelectDialog
                            candidates=found
                            on_choose=Callback::new(move |choice| {
                                candidates.set(None);
                                load(Some(choice));
                            })
                            on_cancel=Callback::new(move |()| candidates.set(None))
                        />
                    }
                })
        }}
    }
}

/// Step 10: restore from backup (shared restore form).
#[component]
pub(super) fn RestoreStep(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    view! {
        <div id="Step10">
            <h3>"Restore from Backup"</h3>
            <fieldset class="setup-fieldset">
                <p>
                    "To restore a backup file to your OnlyKey, ensure you have loaded the same backup passphrase or backup key you used to create the backup."
                </p>
                <p>"Click [Choose File], select your backup file, then click [Next]."</p>
                <p>
                    "Restore can take up to 1 minute to complete, your OnlyKey will automatically reboot when restoring is complete."
                </p>
                <p>
                    "If you do not have a backup file to restore then setup is complete, you may remove and reinsert your OnlyKey now."
                </p>
            </fieldset>
            <RestoreForm />
        </div>
        <StepNav wiz=wiz />
    }
}

/// Step 11: load firmware (shared firmware loader in Setup mode).
#[component]
pub(super) fn FirmwareStep(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    view! {
        <div id="Step11">
            <h3>"Load Firmware"</h3>
            <p>
                "To load new firmware file to your OnlyKey, click [Choose File], select your firmware file, then click [Load Firmware to OnlyKey]."
            </p>
            <p>"The OnlyKey will restart automatically when firmware load is complete."</p>
            <FirmwareLoader in_setup=true />
        </div>
        <StepNav wiz=wiz />
    }
}
