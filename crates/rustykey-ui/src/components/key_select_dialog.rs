//! PrivateKeySelectDialog: pick which key of a bundle to load, and into which slot (`PrivateKeySelectDialog.tsx`).

use super::{Button, ButtonKind, Modal};
use leptos::prelude::*;
use onlykey_core::keys::{CandidateSummary, KeyKind};
use onlykey_core::protocol::{ECC_SLOTS, RSA_SLOTS};

/// Default target slot for a key kind: RSA 1 or ECC 101.
fn default_slot(kind: KeyKind) -> u8 {
    match kind {
        KeyKind::Rsa => RSA_SLOTS[0],
        KeyKind::Ecc => ECC_SLOTS[0],
    }
}

/// Modal listing `candidates` (radio each) with a slot dropdown and "Load Key"; calls `on_choose((index, slot))` or `on_cancel`.
#[component]
pub fn KeySelectDialog(
    /// Keys found in the bundle.
    candidates: Vec<CandidateSummary>,
    /// Called with (candidate index, slot).
    on_choose: Callback<(usize, u8)>,
    /// Called when the user cancels.
    on_cancel: Callback<()>,
) -> impl IntoView {
    let first = candidates.first().map(|c| (c.index, default_slot(c.kind)));
    let selected = RwSignal::new(first.map(|f| f.0));
    let slot = RwSignal::new(first.map_or(RSA_SLOTS[0], |f| f.1));
    let slots = RSA_SLOTS
        .iter()
        .map(|s| (*s, format!("RSA {s}")))
        .chain(ECC_SLOTS.iter().map(|s| (*s, format!("ECC {s}"))))
        .collect::<Vec<_>>();
    view! {
        <Modal title="Select Private Key" on_close=on_cancel>
            <p class="modal-text">
                "Multiple keys were found. Choose which key to load and the target slot."
            </p>
            <div class="key-candidates">
                {candidates
                    .into_iter()
                    .map(|c| {
                        let (index, kind) = (c.index, c.kind);
                        view! {
                            <label class="key-candidate">
                                <input
                                    type="radio"
                                    name="keyCandidate"
                                    prop:checked=move || selected.get() == Some(index)
                                    on:change=move |_| {
                                        selected.set(Some(index));
                                        slot.set(default_slot(kind));
                                    }
                                />
                                <div>
                                    <div class="key-candidate-name">{c.name}</div>
                                    <div class="muted small mono">
                                        {format!("type {} · {} bytes", c.base_type, c.len)}
                                    </div>
                                </div>
                            </label>
                        }
                    })
                    .collect_view()}
            </div>
            <label class="form-row">
                <span class="form-label">"Target slot"</span>
                <select
                    prop:value=move || slot.get().to_string()
                    on:change=move |ev| {
                        if let Ok(v) = event_target_value(&ev).parse() {
                            slot.set(v);
                        }
                    }
                >
                    {slots
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
            <div class="modal-actions">
                <Button kind=ButtonKind::Secondary on:click=move |_| on_cancel.run(())>
                    "Cancel"
                </Button>
                <Button
                    disabled=Signal::derive(move || selected.get().is_none())
                    on:click=move |_| {
                        if let Some(i) = selected.get_untracked() {
                            on_choose.run((i, slot.get_untracked()));
                        }
                    }
                >
                    "Load Key"
                </Button>
            </div>
        </Modal>
    }
}
