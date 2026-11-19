//! Slot editor modal (`SlotEditor.tsx`): tabs, per-field enable boxes, save and wipe.
//!
//! Typed secrets live only in this component's signals and are cleared after a save.

use super::generator::PasswordGenerator;
use super::{refresh_labels, slot_label};
use crate::backend::{Backend, Prefs, backend};
use crate::components::{Button, ButtonKind, HelpTip, Modal, Notice, NoticeKind};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{DeviceError, DeviceKind};
use onlykey_core::protocol::{
    NEXTKEY_AFTER_FIELD_OPTIONS, NEXTKEY_AFTER_OTP_OPTIONS, NEXTKEY_BEFORE_FIELD_OPTIONS,
};
use onlykey_core::slot::{SlotForm, Yubikey, build_slot_commands, wipe_slot_command};

/// Type speed tooltip (`tooltips.ts` typeSpeed).
const TYPE_SPEED_TIP: &str = "Change the rate of speed at which OnlyKey types out characters.\n\n1 - about one character per second\n4 - default\n10 - almost instantaneous type speed";
/// Type speed docs link.
const TYPE_SPEED_HREF: &str =
    "https://docs.crp.to/usersguide.html#configurable-keyboard-type-speed";
/// NEXTKEY2 choices on the Multi-factor tab.
const TAB_OR_NONE: [(u8, &str); 2] = [(1, "Tab"), (0, "None")];

/// One field: its enable checkbox and its text value.
#[derive(Clone, Copy)]
struct Field {
    /// Checkbox: write this field.
    on: RwSignal<bool>,
    /// Input value.
    val: RwSignal<String>,
}

impl Field {
    /// Unchecked field with `val`.
    fn new(val: &str) -> Self {
        Self {
            on: RwSignal::new(false),
            val: RwSignal::new(val.into()),
        }
    }

    /// The value when checked.
    fn text(self) -> Option<String> {
        self.on.get_untracked().then(|| self.val.get_untracked())
    }

    /// The value as a number when checked (unparsable → 0, which the builder rejects where invalid).
    fn num(self) -> Option<u8> {
        self.text().map(|v| v.trim().parse().unwrap_or(0))
    }
}

/// Every editor field (`DEFAULT_FORM` / `DEFAULT_ENABLED`).
#[derive(Clone, Copy)]
struct Form {
    /// Label (checked by default).
    label: Field,
    /// URL.
    url: Field,
    /// Username.
    username: Field,
    /// Password; `confirm` is its re-entry.
    password: Field,
    /// Re-entered password.
    confirm: RwSignal<String>,
    /// Delay after URL.
    delay1: Field,
    /// Delay after username.
    delay2: Field,
    /// Delay before MFA.
    delay3: Field,
    /// Key before username.
    next_key4: Field,
    /// Key after username.
    next_key1: Field,
    /// Key after password.
    next_key2: Field,
    /// Key before OTP.
    next_key5: Field,
    /// Key after OTP.
    next_key3: Field,
    /// Keyboard type speed.
    speed: Field,
    /// TOTP secret.
    totp: Field,
    /// Yubico OTP checkbox (value unused).
    yubi: Field,
    /// Yubico public identity.
    yubi_public: RwSignal<String>,
    /// Yubico private identity.
    yubi_private: RwSignal<String>,
    /// Yubico secret key.
    yubi_secret: RwSignal<String>,
}

impl Form {
    /// Defaults, with the label prefilled from the device.
    fn new(label: Option<String>) -> Self {
        let label = Field {
            on: RwSignal::new(true),
            val: RwSignal::new(label.unwrap_or_default()),
        };
        Self {
            label,
            url: Field::new(""),
            username: Field::new(""),
            password: Field::new(""),
            confirm: RwSignal::new(String::new()),
            delay1: Field::new("0"),
            delay2: Field::new("0"),
            delay3: Field::new("0"),
            next_key4: Field::new("0"),
            next_key1: Field::new("0"),
            next_key2: Field::new("0"),
            next_key5: Field::new("0"),
            next_key3: Field::new("0"),
            speed: Field::new("4"),
            totp: Field::new(""),
            yubi: Field::new(""),
            yubi_public: RwSignal::new(String::new()),
            yubi_private: RwSignal::new(String::new()),
            yubi_secret: RwSignal::new(String::new()),
        }
    }

    /// Checked fields as a core [`SlotForm`].
    fn to_slot_form(self) -> SlotForm {
        SlotForm {
            label: self.label.text(),
            url: self.url.text(),
            username: self.username.text(),
            password: self
                .password
                .text()
                .map(|p| (p, self.confirm.get_untracked())),
            delay1: self.delay1.num(),
            delay2: self.delay2.num(),
            delay3: self.delay3.num(),
            next_key4: self.next_key4.num(),
            next_key1: self.next_key1.num(),
            next_key2: self.next_key2.num(),
            next_key5: self.next_key5.num(),
            next_key3: self.next_key3.num(),
            type_speed: self.speed.num(),
            totp: self.totp.text(),
            yubikey: self.yubi.on.get_untracked().then(|| Yubikey {
                public_id: self.yubi_public.get_untracked(),
                private_id: self.yubi_private.get_untracked(),
                secret_key: self.yubi_secret.get_untracked(),
            }),
        }
    }

    /// Empties the password, TOTP and Yubico inputs.
    fn clear_secrets(self) {
        for s in [
            self.password.val,
            self.confirm,
            self.totp.val,
            self.yubi_public,
            self.yubi_private,
            self.yubi_secret,
        ] {
            s.set(String::new());
        }
    }
}

/// Editor tab: `basic`, `mfa` or `advanced` (prefs `slot_editor_mode`).
fn tab_label(mode: &str, duo_no_pin: bool) -> &'static str {
    match mode {
        "mfa" => "Multi-factor",
        "advanced" => "Full Configuration (Advanced)",
        _ if duo_no_pin => "Static Password",
        _ => "Basic Login",
    }
}

/// The slot editor for `slot` (1–24).
#[component]
pub fn SlotEditor(
    /// Slot index.
    slot_id: u8,
    /// Closes the editor.
    on_close: Callback<()>,
) -> impl IntoView {
    let slot = slot_id;
    let app = use_app();
    let start_epoch = app.snapshot.with_untracked(|s| s.session_epoch);
    let duo_no_pin = app
        .snapshot
        .with_untracked(|s| s.kind == DeviceKind::Duo && !s.pin_set);
    let modes: &[&str] = if duo_no_pin {
        &["basic", "mfa"]
    } else {
        &["basic", "mfa", "advanced"]
    };
    let saved = app.prefs.with_untracked(|p| p.slot_editor_mode.clone());
    let mode = RwSignal::new(
        modes
            .iter()
            .find(|m| **m == saved)
            .copied()
            .unwrap_or("basic"),
    );
    let form = Form::new(untrack(|| slot_label(app, slot)));
    let error = RwSignal::new(None::<String>);
    let saving = RwSignal::new(false);
    let gen_open = RwSignal::new(false);

    let select_mode = move |m: &'static str| {
        mode.set(m);
        let prefs = Prefs {
            slot_editor_mode: m.into(),
            ..app.prefs.get_untracked()
        };
        spawn_local(async move {
            let _ = app.save_prefs(prefs).await;
        });
    };

    // Esc closes only when nothing is stacked on top (generator, confirm, working).
    let close = Callback::new(move |()| {
        let busy = gen_open.get_untracked()
            || app.confirm.with_untracked(Option::is_some)
            || app.working.with_untracked(Option::is_some);
        if !busy {
            on_close.run(());
        }
    });
    // Ends a save/wipe: closes on success, shows the error otherwise (skipped if the session reset).
    let finish = move |res: Result<(), DeviceError>| {
        if app.snapshot.with_untracked(|s| s.session_epoch) != start_epoch {
            return;
        }
        saving.set(false);
        match res {
            Ok(()) => {
                form.clear_secrets();
                on_close.run(());
            }
            Err(e) => error.set(Some(e.to_string())),
        }
    };

    let save = move |_| {
        error.set(None);
        let cmds = match build_slot_commands(slot, &form.to_slot_form(), duo_no_pin) {
            Ok(c) => c,
            Err(e) => return error.set(Some(e.to_string())),
        };
        saving.set(true);
        spawn_local(async move {
            let res = app
                .working("Saving slot configuration…", async move {
                    for cmd in cmds {
                        backend().send(cmd).await?;
                    }
                    refresh_labels(app).await
                })
                .await;
            finish(res);
        });
    };

    let wipe = move |_| {
        spawn_local(async move {
            let message =
                format!("Permanently wipe all data in slot {slot}? This cannot be undone.");
            if !app.confirm("Wipe Slot", message, "Wipe Slot", true).await {
                return;
            }
            saving.set(true);
            let res = app
                .working("Wiping slot…", async move {
                    backend().send(wipe_slot_command(slot)).await?;
                    refresh_labels(app).await
                })
                .await;
            finish(res);
        });
    };

    let advanced = move || mode.get() == "advanced";
    view! {
        <Modal title=format!("OnlyKey Slot {slot} Configuration") on_close=close>
            <div class="slot-editor" class:slot-editor--advanced=advanced>
                <button
                    type="button"
                    class="slot-editor-close"
                    on:click=move |_| on_close.run(())
                >
                    "close ✕"
                </button>
                {duo_no_pin
                    .then(|| {
                        view! {
                            <Notice>
                                "Duo without PIN: static password " <em>"or"</em>
                                " MFA per slot — not both."
                            </Notice>
                        }
                    })}
                <div class="slot-editor-tabs" role="tablist">
                    {modes
                        .iter()
                        .map(|m| {
                            let m: &'static str = m;
                            view! {
                                <button
                                    type="button"
                                    role="tab"
                                    class="slot-editor-tab"
                                    class:active=move || mode.get() == m
                                    aria-selected=move || (mode.get() == m).to_string()
                                    on:click=move |_| select_mode(m)
                                >
                                    {tab_label(m, duo_no_pin)}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <p class="muted small">"Check the box next to the fields you want to set"</p>
                {move || match mode.get() {
                    "advanced" => {
                        view! {
                            <div class="slot-editor-advanced-cols">
                                <div class="slot-editor-body">
                                    <TextField label="Label (up to 16 chars)" f=form.label max=16 placeholder="e.g. GitHub" />
                                    <TextField label="URL (up to 56 chars)" f=form.url max=56 placeholder="https://..." />
                                    <DelayRow context="after URL" f=form.delay1 />
                                    <RadioRow label="Tab before UserName" f=form.next_key4 options=&NEXTKEY_BEFORE_FIELD_OPTIONS />
                                    <TextField label="UserName (up to 56 chars)" f=form.username max=56 />
                                    <RadioRow label="After UserName" f=form.next_key1 options=&NEXTKEY_AFTER_FIELD_OPTIONS />
                                    <DelayRow context="after username" f=form.delay2 />
                                    <PasswordRow form compact=true gen_open />
                                    <RadioRow label="After Password" f=form.next_key2 options=&NEXTKEY_AFTER_FIELD_OPTIONS />
                                    <TypeSpeedRow f=form.speed />
                                </div>
                                <div class="slot-editor-body">
                                    <MfaFields form />
                                </div>
                            </div>
                        }
                            .into_any()
                    }
                    "mfa" => {
                        view! {
                            <div class="slot-editor-body">
                                <TextField label="Label (up to 16 chars)" f=form.label max=16 placeholder="e.g. GitHub" />
                                <MfaFields form />
                            </div>
                        }
                            .into_any()
                    }
                    _ => {
                        view! {
                            <div class="slot-editor-body">
                                <TextField label="Label (up to 16 chars)" f=form.label max=16 placeholder="e.g. GitHub" />
                                {(!duo_no_pin)
                                    .then(|| {
                                        view! {
                                            <TextField label="UserName (up to 56 chars)" f=form.username max=56 />
                                            <RadioRow label="After UserName" f=form.next_key1 options=&NEXTKEY_AFTER_FIELD_OPTIONS />
                                        }
                                    })}
                                <PasswordRow form compact=false gen_open />
                                {(!duo_no_pin)
                                    .then(|| {
                                        view! {
                                            <RadioRow label="After Password" f=form.next_key2 options=&NEXTKEY_AFTER_FIELD_OPTIONS />
                                        }
                                    })}
                                <TypeSpeedRow f=form.speed />
                            </div>
                        }
                            .into_any()
                    }
                }}
                {move || {
                    error
                        .get()
                        .map(|e| view! { <Notice kind=NoticeKind::Error>{e}</Notice> })
                }}
                <div class="slot-editor-actions">
                    <Button kind=ButtonKind::Danger disabled=saving on:click=wipe>
                        "Wipe All Slot Data"
                    </Button>
                    // Room for the future "Fill from 1Password" button (task 15).
                    <div class="slot-editor-actions-end">
                        <Button kind=ButtonKind::Secondary on:click=move |_| on_close.run(())>
                            "Cancel"
                        </Button>
                        <Button disabled=saving on:click=save>
                            {move || if saving.get() { "Saving..." } else { "Set Slot" }}
                        </Button>
                    </div>
                </div>
            </div>
            {move || {
                gen_open
                    .get()
                    .then(|| {
                        view! {
                            <PasswordGenerator
                                on_close=Callback::new(move |()| gen_open.set(false))
                                on_apply=Callback::new(move |pw: String| {
                                    form.password.val.set(pw.clone());
                                    form.confirm.set(pw);
                                    form.password.on.set(true);
                                })
                            />
                        }
                    })
            }}
        </Modal>
    }
}

/// Checkbox + label cell, then the control cell.
#[component]
fn Row(
    /// Row label.
    label: &'static str,
    /// Enable checkbox.
    on: RwSignal<bool>,
    /// The control.
    children: Children,
) -> impl IntoView {
    view! {
        <label class="slot-editor-row-label">
            <input type="checkbox" bind:checked=on />
            <span>{label}</span>
        </label>
        <div class="slot-editor-control">{children()}</div>
    }
}

/// Plain text field row.
#[component]
fn TextField(
    /// Row label.
    label: &'static str,
    /// Field.
    f: Field,
    /// `maxlength`.
    max: usize,
    /// Placeholder.
    #[prop(optional)]
    placeholder: &'static str,
) -> impl IntoView {
    view! {
        <Row label on=f.on>
            <input
                type="text"
                class="slot-input-text"
                autocomplete="off"
                spellcheck="false"
                maxlength=max
                placeholder=placeholder
                bind:value=f.val
            />
        </Row>
    }
}

/// "Delay …" checkbox with a one-digit 0–9 input.
#[component]
fn DelayRow(
    /// Words after "Delay".
    context: &'static str,
    /// Field.
    f: Field,
) -> impl IntoView {
    let label = format!("Delay {context}");
    view! {
        <div class="slot-editor-inline-row">
            <label class="slot-editor-inline-label">
                <input type="checkbox" bind:checked=f.on />
                <span>{label.clone()}</span>
            </label>
            <input
                type="text"
                inputmode="numeric"
                maxlength="1"
                class="slot-input-narrow"
                aria-label=label
                prop:value=move || f.val.get()
                on:input=move |ev| {
                    let v: String = event_target_value(&ev)
                        .chars()
                        .filter(char::is_ascii_digit)
                        .take(1)
                        .collect();
                    f.val.set(if v.is_empty() { "0".into() } else { v });
                }
            />
            <span class="slot-editor-inline-hint">"0-9 seconds"</span>
        </div>
    }
}

/// Checkbox + radio buttons for a NEXTKEY field.
#[component]
fn RadioRow(
    /// Row label.
    label: &'static str,
    /// Field (value is the option number as text).
    f: Field,
    /// (value, label) options.
    options: &'static [(u8, &'static str)],
) -> impl IntoView {
    let name = format!("slot-{label}");
    view! {
        <Row label on=f.on>
            <div class="slot-editor-radios" role="radiogroup">
                {options
                    .iter()
                    .map(|(v, l)| {
                        let v = v.to_string();
                        let mine = v.clone();
                        view! {
                            <label class="slot-editor-radio">
                                <input
                                    type="radio"
                                    name=name.clone()
                                    prop:checked=move || f.val.get() == mine
                                    on:change=move |_| f.val.set(v.clone())
                                />
                                {*l}
                            </label>
                        }
                    })
                    .collect_view()}
            </div>
        </Row>
    }
}

/// Password + re-entry + "Gen"; `compact` puts all three on one line (Advanced tab).
#[component]
fn PasswordRow(
    /// Editor fields.
    form: Form,
    /// One-line layout.
    compact: bool,
    /// Opens the password generator.
    gen_open: RwSignal<bool>,
) -> impl IntoView {
    let input = move |value: RwSignal<String>, placeholder: &'static str| {
        view! {
            <input
                type="password"
                class="slot-input-text"
                autocomplete="new-password"
                maxlength="56"
                placeholder=placeholder
                bind:value=value
            />
        }
    };
    let generate = view! {
        <button type="button" class="slot-gen" on:click=move |_| gen_open.set(true)>
            "Gen"
        </button>
    };
    view! {
        <Row label="Password (up to 56 chars)" on=form.password.on>
            {if compact {
                view! {
                    <div class="slot-editor-password-row">
                        {input(form.password.val, "")} {input(form.confirm, "Re-enter")}
                        {generate}
                    </div>
                }
                    .into_any()
            } else {
                view! {
                    <div class="slot-editor-password-row">{input(form.password.val, "")} {generate}</div>
                    {input(form.confirm, "Re-enter Password")}
                }
                    .into_any()
            }}
        </Row>
    }
}

/// "Keyboard Type Speed" checkbox with a 1–10 input.
#[component]
fn TypeSpeedRow(
    /// Field.
    f: Field,
) -> impl IntoView {
    view! {
        <div class="slot-editor-inline-row">
            <label class="slot-editor-inline-label">
                <input type="checkbox" bind:checked=f.on />
                <span>"Keyboard Type Speed"</span>
            </label>
            <input
                type="number"
                min="1"
                max="10"
                class="slot-input-speed"
                aria-label="Keyboard type speed"
                bind:value=f.val
            />
            <span class="slot-editor-inline-hint">"1-10, 4=default"</span>
            <HelpTip href=TYPE_SPEED_HREF tooltip=TYPE_SPEED_TIP />
        </div>
    }
}

/// The two-factor rows (Multi-factor tab and the Advanced right column).
#[component]
fn MfaFields(
    /// Editor fields.
    form: Form,
) -> impl IntoView {
    let yubi_input = move |value: RwSignal<String>, placeholder: &'static str| {
        view! {
            <input
                type="text"
                class="mono"
                autocomplete="off"
                spellcheck="false"
                placeholder=placeholder
                aria-label=placeholder
                bind:value=value
            />
        }
    };
    view! {
        <div class="slot-editor-section">"Two-factor authentication"</div>
        <RadioRow label="Tab after Password" f=form.next_key2 options=&TAB_OR_NONE />
        <DelayRow context="before MFA" f=form.delay3 />
        <RadioRow label="Tab before OTP" f=form.next_key5 options=&NEXTKEY_BEFORE_FIELD_OPTIONS />
        <Row label="OATH-TOTP (Google Authenticator)" on=form.totp.on>
            <input
                type="text"
                class="slot-input-text mono"
                autocomplete="off"
                spellcheck="false"
                placeholder="TOTP Secret"
                bind:value=form.totp.val
            />
        </Row>
        <RadioRow label="Return after OTP" f=form.next_key3 options=&NEXTKEY_AFTER_OTP_OPTIONS />
        <Row label="Yubikey OTP" on=form.yubi.on>
            <div class="slot-yubi-inputs">
                {yubi_input(form.yubi_public, "Public Identity")}
                {yubi_input(form.yubi_private, "Private Identity")}
                {yubi_input(form.yubi_secret, "Secret Key")}
            </div>
        </Row>
    }
}
