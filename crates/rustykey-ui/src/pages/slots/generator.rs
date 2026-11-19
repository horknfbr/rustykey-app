//! Password generator dialog (`PasswordGeneratorDialog.tsx`), using the browser CSPRNG.

use crate::components::{Button, ButtonKind, Modal, Notice, NoticeKind};
use getrandom::SysRng;
use leptos::prelude::*;
use onlykey_core::password::{PasswordOptions, generate};
use rand_core::UnwrapErr;

/// Generator options, generated password, "Use Password" fills both password fields.
#[component]
pub fn PasswordGenerator(
    /// Closes the dialog.
    on_close: Callback<()>,
    /// Receives the chosen password.
    on_apply: Callback<String>,
) -> impl IntoView {
    let d = PasswordOptions::default();
    let length = RwSignal::new(d.length.to_string());
    let sets = [
        ("Uppercase", RwSignal::new(d.upper)),
        ("Lowercase", RwSignal::new(d.lower)),
        ("Digits", RwSignal::new(d.digits)),
        ("Special", RwSignal::new(d.special)),
        ("Punctuation", RwSignal::new(d.punct)),
        ("Braces", RwSignal::new(d.braces)),
        ("Space", RwSignal::new(d.space)),
    ];
    let omit = RwSignal::new(String::new());
    let generated = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    let run = move || {
        error.set(None);
        let on = |i: usize| sets[i].1.get_untracked();
        let opts = PasswordOptions {
            length: length.get_untracked().trim().parse().unwrap_or(6),
            upper: on(0),
            lower: on(1),
            digits: on(2),
            special: on(3),
            punct: on(4),
            braces: on(5),
            space: on(6),
            omit: omit.get_untracked(),
        };
        match generate(&opts, &mut UnwrapErr(SysRng)) {
            Ok(pw) => generated.set(pw),
            Err(e) => error.set(Some(e.to_string())),
        }
    };
    let apply = move |_| {
        let pw = generated.get_untracked();
        if pw.is_empty() {
            return run();
        }
        generated.set(String::new());
        on_apply.run(pw);
        on_close.run(());
    };

    view! {
        <Modal title="Password Generator" on_close=on_close>
            <label class="slot-gen-length">
                <span>"Length (6–56)"</span>
                <input type="number" min="6" max="56" bind:value=length />
            </label>
            <div class="slot-gen-sets">
                {sets
                    .into_iter()
                    .map(|(label, on)| {
                        view! {
                            <label class="check-row">
                                <input type="checkbox" bind:checked=on />
                                <span>{label}</span>
                            </label>
                        }
                    })
                    .collect_view()}
            </div>
            <label class="form-row">
                <span class="form-label">"Omit characters"</span>
                <input
                    type="text"
                    class="mono"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="e.g. 0O1lI"
                    bind:value=omit
                />
            </label>
            <label class="form-row">
                <span class="form-label">"Generated password"</span>
                <input
                    type="text"
                    class="mono"
                    readonly
                    autocomplete="off"
                    placeholder="Click Generate"
                    prop:value=move || generated.get()
                />
            </label>
            {move || error.get().map(|e| view! { <Notice kind=NoticeKind::Error>{e}</Notice> })}
            <div class="modal-actions">
                <Button kind=ButtonKind::Secondary on:click=move |_| on_close.run(())>
                    "Cancel"
                </Button>
                <Button kind=ButtonKind::Secondary on:click=move |_| run()>
                    "Generate"
                </Button>
                <Button on:click=apply>"Use Password"</Button>
            </div>
        </Modal>
    }
}
