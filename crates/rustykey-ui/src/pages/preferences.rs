//! Device preferences: Standard and Advanced (config mode) tabs (`Preferences.tsx`).

use super::keys::send_all;
use super::tools::{PrefRow, PseudoTabs};
use crate::components::{Button, ButtonKind, HelpTip};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::Command;
use onlykey_core::protocol::{
    FieldId, KEYBOARD_LAYOUTS, SYSADMIN_MODE_PREF_HINT, WIPE_MODE_FULL, firmware_at_least,
};

/// A radio choice: (value, label, optional tooltip).
type Choice = (u8, &'static str, Option<&'static str>);

/// 0 challenge code, 1 button press (fields 21 and 22).
const CODE_OR_PRESS: &[Choice] = &[
    (0, "Challenge Code (enter 3 digits)", None),
    (1, "Button Press (tap any button)", None),
];

/// Field 30 also allows 2 = no confirmation.
const WEB_AGENT_CHOICES: &[Choice] = &[
    (0, "Challenge Code (enter 3 digits)", None),
    (1, "Button Press (tap any button)", None),
    (
        2,
        "None (no confirmation) - for unattended agents",
        Some(
            "No confirmation at all, for unattended tools that decrypt with web and agent derived keys (for example age). Applies over USB and to the OnlyKey web app: while it is set, either can derive and decrypt silently whenever the key is unlocked. Off by default; leave it off unless an unattended tool needs it. onlykey-agent SSH and GPG keys are not affected.",
        ),
    ),
];

/// Field 31: 0x01 stored + derived, 0x00 derived only, 0x02 off.
const WEBCRYPT_CHOICES: &[Choice] = &[
    (
        0x01,
        "Stored and derived keys",
        Some(
            "The web app can use the keys stored on this OnlyKey (PGP) as well as derived keys. This is the default, as on older firmware.",
        ),
    ),
    (
        0x00,
        "Derived keys only",
        Some(
            "The web app can use derived keys only. Derived keys are label-scoped and reproducible; the keys stored on this OnlyKey stay out of its reach.",
        ),
    ),
    (
        0x02,
        "Off - the web app cannot reach this key",
        Some(
            "Turns off the OnlyKey FIDO2 extension, so the web app cannot reach this key at all, derived keys included. If you turned it off on older firmware, it stays off until you save a choice here.",
        ),
    ),
];

/// Radio group with an unchosen (`None`) start (`ChoiceGroup`).
#[component]
fn ChoiceGroup(
    /// Group heading.
    legend: &'static str,
    /// HTML radio name.
    name: &'static str,
    /// Picked value; `None` = not chosen, nothing written.
    value: RwSignal<Option<u8>>,
    /// Options.
    choices: &'static [Choice],
    /// Heading tooltip.
    #[prop(optional)]
    tooltip: Option<&'static str>,
) -> impl IntoView {
    view! {
        <fieldset class="pref-choice-group">
            <legend>{legend} {tooltip.map(|t| view! { <HelpTip tooltip=t /> })}</legend>
            {choices
                .iter()
                .map(|(v, label, tip)| {
                    let v = *v;
                    view! {
                        <div class="check-row">
                            <label class="check-row">
                                <input
                                    type="radio"
                                    name=name
                                    prop:checked=move || value.get() == Some(v)
                                    on:change=move |_| value.set(Some(v))
                                />
                                <span>{*label}</span>
                            </label>
                            {tip.map(|t| view! { <HelpTip tooltip=t /> })}
                        </div>
                    }
                })
                .collect_view()}
        </fieldset>
    }
}

/// Number box bound to a text signal (empty = nothing typed).
fn number_input(
    value: RwSignal<String>,
    min: u8,
    max: u8,
    placeholder: &'static str,
) -> impl IntoView {
    view! {
        <input
            type="number"
            class="narrow"
            min=min
            max=max
            placeholder=placeholder
            bind:value=value
        />
    }
}

/// Parses a typed number, clamped to `min..=max` (non-numbers become `min`).
fn parse_clamped(text: &str, min: u8, max: u8) -> u8 {
    text.trim().parse::<i64>().map_or(min, |v| {
        u8::try_from(v.clamp(i64::from(min), i64::from(max))).unwrap_or(min)
    })
}

/// One `SetGlobal` write.
fn set(field: FieldId, value: u8) -> Command {
    Command::SetGlobal {
        field: field as u8,
        value,
    }
}

/// Preferences page.
#[component]
pub fn PreferencesPage() -> impl IntoView {
    let app = use_app();
    let tab = RwSignal::new("standard");
    let type_speed = RwSignal::new(String::new());
    let layout = RwSignal::new(0x01u8);
    let led = RwSignal::new(String::new());
    let lockout = RwSignal::new(String::new());
    let lock_button = RwSignal::new(String::new());
    let derived = RwSignal::new(None::<u8>);
    let stored = RwSignal::new(None::<u8>);
    let web_agent = RwSignal::new(None::<u8>);
    let webcrypt = RwSignal::new(None::<u8>);
    let status = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let has310 = move || {
        app.snapshot
            .with(|s| firmware_at_least(s.firmware.as_deref().unwrap_or(""), 3, 1, 0))
    };

    // Writes `writes` in order as (family name, command); "<label> saved." or the error, listing what was saved first.
    let run = move |label: &'static str, writes: Vec<(&'static str, Command)>| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(None);
        status.set(None);
        spawn_local(async move {
            let mut saved: Vec<&str> = Vec::new();
            let mut failed = None;
            for (name, cmd) in writes {
                if let Err(e) = send_all(vec![cmd]).await {
                    failed = Some(if saved.is_empty() {
                        e
                    } else {
                        let end = if e.ends_with(['.', '!', '?']) {
                            ""
                        } else {
                            "."
                        };
                        format!("{e}{end} Already saved: {}.", saved.join(", "))
                    });
                    break;
                }
                saved.push(name);
            }
            match failed {
                None => status.set(Some(format!("{label} saved."))),
                Some(mut msg) => {
                    if tab.get_untracked() == "standard"
                        && msg.to_lowercase().contains("config mode")
                    {
                        msg = format!("{msg} {SYSADMIN_MODE_PREF_HINT}");
                    }
                    error.set(Some(msg));
                }
            }
            busy.set(false);
        });
    };
    let one = move |label: &'static str, cmd: Command| run(label, vec![(label, cmd)]);
    // Irreversible device settings: writes `cmd` only after the user confirms `message`.
    let confirmed =
        move |title: &'static str, message: &'static str, label: &'static str, cmd: Command| {
            spawn_local(async move {
                if app.confirm(title, message, title, true).await {
                    one(label, cmd);
                }
            });
        };
    let input_mode_writes = move || {
        let mut w = Vec::new();
        if let Some(v) = derived.get() {
            w.push((
                "SSH/GPG derived keys",
                set(FieldId::DerivedChallengeMode, v),
            ));
        }
        if let Some(v) = stored.get() {
            w.push(("stored keys", set(FieldId::StoredChallengeMode, v)));
        }
        if let (true, Some(v)) = (has310(), web_agent.get()) {
            w.push((
                "web and agent derived keys",
                set(FieldId::WebAgentDeriveMode, v),
            ));
        }
        w
    };
    let disabled = move |empty: RwSignal<String>| {
        Signal::derive(move || busy.get() || empty.with(|t| t.trim().is_empty()))
    };

    view! {
        <h2 class="page-title">"Preferences"</h2>
        <PseudoTabs
            tabs=&[("standard", "Standard"), ("advanced", "Advanced")]
            active=tab
            on_change=Callback::new(move |()| {
                error.set(None);
                status.set(None);
            })
        />
        {move || status.get().map(|s| view! { <p class="status-success">{s}</p> })}
        {move || error.get().map(|e| view! { <p class="critical-text">{e}</p> })}
        <Show when=move || tab.get() == "standard">
            <p class="muted small">
                "Standard preferences apply while your OnlyKey is unlocked. Config mode is not required."
            </p>
            <div class="pref-panel">
                <div>
                    <PrefRow
                        title="Keyboard Type Speed"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-keyboard-type-speed"), "Change the rate of speed at which OnlyKey types out characters.\n\n1 - about one character per second\n4 - default\n10 - almost instantaneous type speed")
                        hint=Signal::stored(Some("(1 = slowest, 4 = default, 10 = fastest)".to_string()))
                    >
                        {number_input(type_speed, 1, 10, "1 - 10")}
                        <Button disabled=disabled(type_speed) on:click=move |_| one("Type speed", set(FieldId::TypeSpeed, parse_clamped(&type_speed.get_untracked(), 1, 10)))>
                            "Set Type Speed"
                        </Button>
                    </PrefRow>
                    <PrefRow
                        title="Keyboard Layout"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-keyboard-layouts"), "Select any of the supported keyboard layouts.")
                    >
                        <select on:change=move |ev| {
                            if let Ok(v) = event_target_value(&ev).parse() {
                                layout.set(v);
                            }
                        }>
                            {KEYBOARD_LAYOUTS
                                .iter()
                                .map(|l| {
                                    let v = l.value;
                                    view! {
                                        <option value=v.to_string() selected=move || layout.get() == v>
                                            {l.legacy_label}
                                        </option>
                                    }
                                })
                                .collect_view()}
                        </select>
                        <Button disabled=busy on:click=move |_| one("Keyboard layout", set(FieldId::KbdLayout, layout.get_untracked()))>
                            "Set Layout"
                        </Button>
                    </PrefRow>
                    <PrefRow
                        title="Indicator Light (LED) Brightness"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-led-brightness"), "Change the OnlyKey LED brightness.\n\n1 - dimmest\n8 - default\n10 - brightest")
                        hint=Signal::stored(Some("(1 = dimmest, 8 = default, 10 = brightest)".to_string()))
                    >
                        {number_input(led, 1, 10, "1 - 10")}
                        <Button disabled=disabled(led) on:click=move |_| one("LED brightness", set(FieldId::LedBrightness, parse_clamped(&led.get_untracked(), 1, 10)))>
                            "Set Brightness"
                        </Button>
                    </PrefRow>
                </div>
                <div>
                    <PrefRow
                        title="Inactivity Lockout Timer"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-inactivity-lockout-period"), "By default, OnlyKey locks itself after 30 minutes. Change this setting to any duration (in minutes) up to 255. If you don't want OnlyKey to lock, enter 0.")
                        hint=Signal::stored(Some("(1 – 255 Minutes, 30 = default, 0 to disable)".to_string()))
                    >
                        {number_input(lockout, 0, 255, "1 - 255")}
                        <Button disabled=disabled(lockout) on:click=move |_| one("Lockout", set(FieldId::Lockout, parse_clamped(&lockout.get_untracked(), 0, 255)))>
                            "Set Lockout"
                        </Button>
                    </PrefRow>
                    <PrefRow
                        title="Lock Button"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-lock-button"), "Choose a button (1-6) that you can quickly press to lock your OnlyKey and computer, or enter 0 to disable this feature.")
                        description=|| "The OnlyKey and the computer are locked automatically when this lock button is pressed (0 to disable)."
                    >
                        {number_input(lock_button, 0, 6, "1 - 6")}
                        <Button disabled=disabled(lock_button) on:click=move |_| one("Lock button", set(FieldId::LockButton, parse_clamped(&lock_button.get_untracked(), 0, 6)))>
                            "Set as Lock Button"
                        </Button>
                    </PrefRow>
                </div>
            </div>
        </Show>
        <Show when=move || tab.get() == "advanced">
            <p class="pref-advanced-note">
                "These settings require your OnlyKey to be in " <strong>"config mode"</strong>
                ". Enabling " <strong>"Sysadmin Mode"</strong>
                " also makes firmware require config mode for " <em>"all"</em>
                " slot/preference writes (including Standard) until Sysadmin Mode is turned off."
            </p>
            <div class="pref-panel">
                <div>
                    <PrefRow
                        title="Sysadmin Mode"
                        tip=(Some("https://docs.crp.to/usersguide.html#sysadmin-mode"), "By default, OnlyKey may only type regular keyboard characters, TAB, and RETURN. This is useful for entering login information like usernames and passwords. For more advanced use cases such as for system administrators, keystroke combinations such as CTRL-ALT-DEL and username/password or system commands may be used.")
                        description=|| "Allow advanced keystroke combinations and system commands?"
                    >
                        <Button disabled=busy on:click=move |_| one("Sysadmin Mode", set(FieldId::ModKeyMode, 1))>"Yes"</Button>
                        <Button disabled=busy on:click=move |_| one("Sysadmin Mode", set(FieldId::ModKeyMode, 0))>"No"</Button>
                    </PrefRow>
                    <PrefRow
                        title="HMAC User Input Mode"
                        tip=(Some("https://docs.crp.to/usersguide.html#hmac-mode"), "By default, you must press a button on OnlyKey to perform HMAC challenge-response operations. Selecting 'NO' for this option allows those operations without pressing a button.")
                        description=|| "Require a button press for HMAC challenge-response operations?"
                    >
                        <Button disabled=busy on:click=move |_| one("HMAC mode", set(FieldId::HmacChallengeMode, 1))>"Yes"</Button>
                        <Button disabled=busy on:click=move |_| one("HMAC mode", set(FieldId::HmacChallengeMode, 0))>"No"</Button>
                    </PrefRow>
                    <PrefRow
                        title="Full Wipe Mode"
                        tip=(Some("https://docs.crp.to/usersguide.html#configurable-wipe-mode"), "By default, only sensitive data is wiped from OnlyKey when 10 incorrect PINs are entered. You can wipe the firmware as well by changing this option to 'Full Wipe.'")
                        description=|| view! {
                            "Only sensitive data is wiped by default." <br />
                            <u>"Full Wipe"</u> " – " <em>"Wipe device and firmware must be reloaded."</em>
                        }
                        warning="WARNING - Once set to \"Full Wipe\" this cannot be changed."
                    >
                        <Button kind=ButtonKind::Danger disabled=busy on:click=move |_| confirmed(
                            "Set Full Wipe Mode",
                            "After 10 incorrect PINs, OnlyKey will wipe all data and its firmware, and the firmware must be reloaded. Once set, Full Wipe Mode cannot be changed back. This cannot be undone.",
                            "Wipe mode",
                            set(FieldId::WipeMode, WIPE_MODE_FULL),
                        )>
                            "Set Full Wipe Mode"
                        </Button>
                    </PrefRow>
                </div>
                <div>
                    <PrefRow
                        title="User Input Modes"
                        tip=(Some("https://docs.crp.to/usersguide.html#challenge-mode"), "How you confirm an operation on the OnlyKey itself. Each key family is its own setting on the device. The app cannot read the current settings, so Save writes only the families you choose.")
                        description=|| view! {
                            <em>"How you confirm an operation on the device. The app cannot read the current settings, so only the families you choose here are written."</em>
                        }
                        hint=Signal::derive(move || (!has310()).then(|| "Web and agent derived keys and Webcrypt Access need firmware 3.1.0 or later.".to_string()))
                    >
                        <ChoiceGroup legend="SSH/GPG derived keys" name="derivedKeyInput" value=derived choices=CODE_OR_PRESS />
                        <ChoiceGroup legend="Stored keys (PGP, SSH, RSA and ECC slots)" name="storedKeyInput" value=stored choices=CODE_OR_PRESS />
                        <Show when=has310>
                            <ChoiceGroup
                                legend="Web and agent derived keys"
                                name="webAgentDeriveInput"
                                value=web_agent
                                choices=WEB_AGENT_CHOICES
                                tooltip="Keys derived on demand from a label, shared by the OnlyKey web app and by local tools over USB (python-onlykey and its age plugin). SSH and GPG keys from onlykey-agent use the SSH/GPG derived keys setting above."
                            />
                        </Show>
                        <Button
                            disabled=Signal::derive(move || busy.get() || input_mode_writes().is_empty())
                            on:click=move |_| run("User input modes", untrack(input_mode_writes))
                        >
                            "Save User Input Modes"
                        </Button>
                    </PrefRow>
                    <Show when=has310>
                        <PrefRow
                            title="Webcrypt Access"
                            tip=(Some("https://docs.crp.to/webcrypt.html"), "What Webcrypt - the OnlyKey web app - is allowed to do with this OnlyKey. The origins that can reach the key are compiled into the firmware; this is not a list you can add to. Separate from the confirmation settings above.")
                            description=|| view! {
                                <em>"What the OnlyKey web app is allowed to do. The app cannot read the current setting, so nothing is written until you choose one."</em>
                            }
                        >
                            <ChoiceGroup legend="The web app can use" name="webcryptPolicy" value=webcrypt choices=WEBCRYPT_CHOICES />
                            <Button
                                disabled=Signal::derive(move || busy.get() || webcrypt.get().is_none())
                                on:click=move |_| {
                                    if let Some(v) = webcrypt.get_untracked() {
                                        one("Webcrypt access", set(FieldId::WebcryptPolicy, v));
                                    }
                                }
                            >
                                "Save Webcrypt Access"
                            </Button>
                        </PrefRow>
                    </Show>
                    <PrefRow
                        title="Backup Key Mode"
                        tip=(Some("https://docs.crp.to/usersguide.html#backup-key-mode"), "Backup key may be changed by default. Enabling this setting prevents any changes to the backup key and if no backup key is set will disable backups. Setting remains in effect until a factory default is completed.")
                        description=|| view! { <u>"Locked"</u> " - " <em>"Backup key may not be changed on device"</em> }
                        warning="WARNING - Once set to \"Locked\" this cannot be changed."
                    >
                        <Button kind=ButtonKind::Danger disabled=busy on:click=move |_| confirmed(
                            "Lock Backup Key",
                            "Once locked, the backup key cannot be changed on the device, and if no backup key is set, backups are disabled. This cannot be undone without a factory default.",
                            "Backup key mode",
                            set(FieldId::BackupKeyMode, 1),
                        )>
                            "Lock Backup Key"
                        </Button>
                    </PrefRow>
                </div>
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    //! Number parsing for the Standard tab.

    use super::*;

    /// Typed numbers clamp into range; junk becomes the minimum.
    #[test]
    fn parse_clamped_rules() {
        assert_eq!(parse_clamped("4", 1, 10), 4);
        assert_eq!(parse_clamped("99", 1, 10), 10);
        assert_eq!(parse_clamped("-3", 0, 255), 0);
        assert_eq!(parse_clamped("300", 0, 255), 255);
        assert_eq!(parse_clamped("x", 1, 10), 1);
    }
}
