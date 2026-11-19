//! PIN steps: Classic keypad steps 2–7 and the DUO PIN form (step 2).

use super::{StepNav, Wiz, err_text, send_all};
use crate::backend::{Backend, backend};
use crate::components::{Button, CheckboxRow};
use leptos::prelude::*;
use onlykey_core::api::{Command, DuoPins, PinKind};
use onlykey_core::device_type::DeviceType;
use onlykey_core::protocol::{FieldId, product_name};

/// Disclaimer checkbox label.
const ACCEPT: &str = "I understand and accept the above risk.";
/// Error when Next runs without the disclaimer.
const ACCEPT_ERR: &str = "Please accept the disclaimer.";
/// Profile PIN disclaimer.
const PIN_DISCLAIMER: &str = "DISCLAIMER — I understand that there is no way to recover my PIN, and, if I forget my PIN, the only way to recover my OnlyKey is to perform a factory reset which wipes all sensitive information.";
/// "Change … PIN" advice.
const CHOOSE_NEW: &str = "Make sure to choose a new PIN that you will not forget and that only you know. It may be easier to remember a pattern rather than numbers. It is also good to keep a secure backup of your PIN somewhere just in case you forget.";
/// Keypad instruction under the disclaimer.
const ENTER_KEYPAD: &str = "Enter a 7 - 10 digit PIN on your OnlyKey six-button keypad. When you are finished, click [Next] below.";
/// Re-enter step body.
const REENTER: &str = "Re-enter the 7 - 10 digit PIN on your OnlyKey six-button keypad. When you are finished, click [Next] below.";
/// Second-profile intro (uninitialized).
const SECOND_INTRO: &str = "Your OnlyKey is now set up to store 12 accounts and is ready to use! OnlyKey permits adding a second profile to store an additonal 12 accounts (24 total). Set a second PIN to access the second profile. Second profile must be configured during initial setup and cannot be set up later.";
/// Self-destruct explanation (initialized).
const SD_INTRO: &str = "OnlyKey permits adding a self-destruct PIN that when entered will restore the OnlyKey to factory default settings. This is a helpful way to quickly wipe the OnlyKey. Alternatively, entering 10 incorrect PIN codes will wipe the OnlyKey.";
/// Self-destruct explanation (uninitialized).
const SD_INTRO_SETUP: &str = "Your OnlyKey is now set up to store 24 accounts and is ready to use! OnlyKey permits adding a self-destruct PIN that when entered will restore the OnlyKey to factory default settings. This is a helpful way to quickly wipe the OnlyKey. Alternatively, entering 10 incorrect PIN codes will wipe the OnlyKey.";
/// Self-destruct similarity warning.
const SD_WARNING: &str = "WARNING — Make sure to choose a PIN that is not similar to your profile PINs as this could result in unintentionally wiping your OnlyKey.";
/// Self-destruct disclaimer.
const SD_DISCLAIMER: &str = "DISCLAIMER — I understand that entering this PIN will cause OnlyKey to perform a factory default which wipes all sensitive information.";

/// Classic keypad PIN step `n` (2 primary, 3 re-enter, 4 second profile, 5 re-enter, 6 self-destruct, 7 re-enter).
#[component]
pub(super) fn ClassicPinStep(
    /// Wizard state.
    wiz: Wiz,
    /// Step number, 2–7.
    n: u8,
) -> impl IntoView {
    let accepted = RwSignal::new(false);
    let init = wiz.initialized_now();
    let disclaimer = move || view! { <CheckboxRow label=ACCEPT checked=accepted /> };

    let body = match (n, init) {
        (2, true) => view! {
            <h3>"Change Primary Profile PIN"</h3>
            <p>{CHOOSE_NEW}</p>
            <p>{PIN_DISCLAIMER}</p>
            {disclaimer()}
            <p>{ENTER_KEYPAD}</p>
        }
        .into_any(),
        (2, false) => view! {
            <h3>"Enter PIN on OnlyKey Keypad"</h3>
            <p>
                "The first step in setting up OnlyKey is to set a PIN code using the six-button keypad on the OnlyKey. This PIN will be used to unlock your OnlyKey to access your accounts."
                <br />
                <br />
                "Make sure to choose a PIN that you will not forget and that only you know. It may be easier to remember a pattern rather than numbers. It is also good to keep a secure backup of your PIN somewhere just in case you forget."
            </p>
            <p>{PIN_DISCLAIMER}</p>
            {disclaimer()}
            <p>
                "Enter a 7 - 10 digit PIN on your OnlyKey six button keypad. When you are finished, click [Next] below."
            </p>
        }
        .into_any(),
        (3, _) => view! {
            <h3>"Re-enter PIN on OnlyKey Keypad"</h3>
            <p>{REENTER}</p>
        }
        .into_any(),
        (4, true) => view! {
            <h3>"Change Second Profile PIN"</h3>
            <p>{CHOOSE_NEW}</p>
            <p>{PIN_DISCLAIMER}</p>
            {disclaimer()}
            <p>{ENTER_KEYPAD}</p>
        }
        .into_any(),
        (4, false) => view! {
            <h3>"Enter PIN for Second Profile on OnlyKey Keypad"</h3>
            <p>{SECOND_INTRO}</p>
            <p>
                <Button on:click=move |_| {
                    wiz.step.set(6);
                    wiz.pin_prompt(PinKind::SelfDestruct);
                }>
                    <b>"I don't want a second profile, skip this step"</b>
                </Button>
            </p>
            <p>{PIN_DISCLAIMER}</p>
            {disclaimer()}
            <p>{ENTER_KEYPAD}</p>
        }
        .into_any(),
        (5, _) => view! {
            <h3>"Re-enter PIN for Second Profile on OnlyKey Keypad"</h3>
            <p>{REENTER}</p>
        }
        .into_any(),
        (6, true) => view! {
            <h3>"Change Self-Destruct PIN"</h3>
            <p>{SD_INTRO}</p>
            <p>{SD_WARNING}</p>
            <p>{SD_DISCLAIMER}</p>
            {disclaimer()}
            <p>{ENTER_KEYPAD}</p>
        }
        .into_any(),
        (6, false) => view! {
            <h3>"Enter Self-Destruct PIN on OnlyKey Keypad"</h3>
            <p>{SD_INTRO_SETUP}</p>
            <p>
                <Button on:click=move |_| wiz.step.set(8)>
                    <b>"I don't want a self-destruct PIN, skip this step"</b>
                </Button>
            </p>
            <p>{SD_WARNING}</p>
            <p>{SD_DISCLAIMER}</p>
            {disclaimer()}
            <p>{ENTER_KEYPAD}</p>
        }
        .into_any(),
        _ => view! {
            <h3>"Re-enter Self-Destruct PIN on OnlyKey Keypad"</h3>
            <p>{REENTER}</p>
        }
        .into_any(),
    };

    let needs_accept = move || match n {
        2 | 4 => true,
        6 => init || wiz.guided.get(),
        _ => false,
    };
    let next = Callback::new(move |()| {
        let guided = wiz.guided.get_untracked();
        let advanced = wiz.advanced.get_untracked();
        let missing_accept = needs_accept() && !accepted.get_untracked();
        wiz.run(None, async move {
            if missing_accept {
                return Err(ACCEPT_ERR.into());
            }
            // (PIN to commit, PIN to prompt next, step after) per `Setup.tsx` StepNav handlers.
            let (which, then) = match n {
                2 => (PinKind::Primary, Some((3, PinKind::Primary))),
                3 => (PinKind::Primary, guided.then_some((4, PinKind::Second))),
                4 => (PinKind::Second, Some((5, PinKind::Second))),
                5 => (
                    PinKind::Second,
                    guided.then_some((6, PinKind::SelfDestruct)),
                ),
                6 => (PinKind::SelfDestruct, Some((7, PinKind::SelfDestruct))),
                _ => (PinKind::SelfDestruct, None),
            };
            if n == 4 && !init && advanced {
                // The second profile is always the encrypted (standard) profile.
                let cmd = Command::SetGlobal {
                    field: FieldId::SecProfileMode as u8,
                    value: 1,
                };
                backend().send(cmd).await.map_err(err_text)?;
            }
            wiz.pin_commit(which).await?;
            match then {
                Some((step, prompt)) => {
                    wiz.step.try_set(step);
                    wiz.pin_prompt(prompt);
                }
                None if n == 7 => wiz.next_or_landing(8),
                None => wiz.landing(),
            }
            Ok(())
        });
    });

    view! {
        <div id=format!("Step{n}")>{body}</div>
        <StepNav
            wiz=wiz
            on_next=next
            next_disabled=Signal::derive(move || needs_accept() && !accepted.get())
        />
    }
}

/// DUO step 2: disclaimer, Device PIN + confirm (required), Self-Destruct PIN + confirm (optional).
#[component]
pub(super) fn DuoPinStep(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    let duo = product_name(DeviceType::Duo);
    let accepted = RwSignal::new(false);
    let primary = RwSignal::new(String::new());
    let primary_confirm = RwSignal::new(String::new());
    let sd = RwSignal::new(String::new());
    let sd_confirm = RwSignal::new(String::new());
    let pin_input =
        move |value: RwSignal<String>, placeholder: &'static str, label: &'static str| {
            view! {
                <input
                    type="password"
                    autocomplete="off"
                    maxlength="16"
                    placeholder=placeholder
                    aria-label=label
                    bind:value=value
                />
            }
        };

    let next = Callback::new(move |()| {
        let ok = accepted.get_untracked();
        let p = primary.get_untracked();
        let s = sd.get_untracked();
        let pins_match = p == primary_confirm.get_untracked();
        let sd_match = s.is_empty() || s == sd_confirm.get_untracked();
        wiz.run(Some("Setting PINs…"), async move {
            if !ok {
                return Err(ACCEPT_ERR.into());
            }
            if !pins_match {
                return Err("PINs do not match.".into());
            }
            if !sd_match {
                return Err("Self-destruct PINs do not match.".into());
            }
            let pins = DuoPins {
                primary: p,
                second: None,
                self_destruct: (!s.is_empty()).then_some(s),
            };
            send_all(vec![Command::DuoPin { pins, setup: true }]).await?;
            for field in [primary, primary_confirm, sd, sd_confirm] {
                field.try_set(String::new());
            }
            wiz.next_or_landing(8);
            Ok(())
        });
    });

    view! {
        <div id="Step2">
            <h3>"Set or Change PINs"</h3>
            <p>
                {format!(
                    "Make sure to choose a device PIN that you will not forget and that only you know. Once set, it is required to know your device PIN to unlock your {duo}, so keep a secure backup of your PIN somewhere in case you forget.",
                )}
            </p>
            <p>
                {format!(
                    "DISCLAIMER — I understand that there is no way to recover my PINs, and, if I forget my PINs, the only way to recover my {duo} is to perform a factory reset which wipes all sensitive information.",
                )}
            </p>
            <CheckboxRow label=ACCEPT checked=accepted />
            <p>
                "Enter a 7-10 digit PIN code using ONLY the numbers 1 - 6. Using the numbers 1 - 6 allows you to physically enter the PIN onto OnlyKey in the event that the OnlyKey App is not available."
            </p>
            <p>"Example of a " <em>"good"</em> " PIN: '32536145'"</p>
            <p>"Examples of " <em>"bad"</em> " PINs: '1234567' '1111112' '1231231'"</p>
            <p>
                "Once set, your PIN can be entered via the OnlyKey App or by physically touching device buttons. Touch buttons 1, 2, 3 to enter 1, 2, 3 and hold (for 1 second) buttons 1, 2, 3 to enter 4, 5, 6."
            </p>
            <div class="setup-pins">
                <div class="setup-pin-col">
                    <u>"Device PIN"</u>
                    {pin_input(primary, "Device PIN", "Device PIN")}
                    {pin_input(primary_confirm, "Confirm", "Confirm Device PIN")}
                    <span>"[required]"</span>
                </div>
                <div class="setup-pin-col">
                    <u>"Self-Destruct"</u>
                    {pin_input(sd, "Self-Destruct PIN", "Self-Destruct PIN")}
                    {pin_input(sd_confirm, "Confirm", "Confirm Self-Destruct PIN")}
                    <span>"[optional, for wiping device and factory reset]"</span>
                </div>
            </div>
        </div>
        <StepNav
            wiz=wiz
            on_next=next
            next_disabled=Signal::derive(move || !accepted.get() || primary.with(String::is_empty))
        />
    }
}
