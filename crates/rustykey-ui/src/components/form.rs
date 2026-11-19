//! Labelled form rows bound to page-local signals (keep secrets in page-local signals only).

use leptos::prelude::*;

/// Text or password input with a max length.
#[component]
pub fn TextRow(
    /// Label text.
    #[prop(into)]
    label: String,
    /// Bound value.
    value: RwSignal<String>,
    /// `maxlength`.
    max_len: usize,
    /// Mask the input.
    #[prop(optional)]
    password: bool,
    /// Placeholder.
    #[prop(into, optional)]
    placeholder: String,
    /// Disables the input.
    #[prop(into, optional)]
    disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <label class="form-row">
            <span class="form-label">{label}</span>
            <input
                type=if password { "password" } else { "text" }
                autocomplete="off"
                spellcheck="false"
                maxlength=max_len
                placeholder=placeholder
                disabled=disabled
                bind:value=value
            />
        </label>
    }
}

/// Checkbox with a label to its right.
#[component]
pub fn CheckboxRow(
    /// Label text.
    #[prop(into)]
    label: String,
    /// Bound state.
    checked: RwSignal<bool>,
    /// Disables the box.
    #[prop(into, optional)]
    disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <label class="check-row">
            <input type="checkbox" disabled=disabled bind:checked=checked />
            <span>{label}</span>
        </label>
    }
}

/// Dropdown; `options` are (value, label).
#[component]
pub fn SelectRow(
    /// Label text.
    #[prop(into)]
    label: String,
    /// Bound selected value.
    value: RwSignal<String>,
    /// (value, label) pairs.
    options: Vec<(String, String)>,
    /// Disables the dropdown.
    #[prop(into, optional)]
    disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <label class="form-row">
            <span class="form-label">{label}</span>
            <select
                disabled=disabled
                prop:value=value
                on:change=move |ev| value.set(event_target_value(&ev))
            >
                {options
                    .into_iter()
                    .map(|(v, l)| {
                        let selected = v.clone();
                        view! {
                            <option value=v selected=move || value.get() == selected>
                                {l}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
        </label>
    }
}

/// Radio buttons sharing `name`; `options` are (value, label).
#[component]
pub fn RadioGroup(
    /// HTML `name` (unique per page).
    #[prop(into)]
    name: String,
    /// Bound selected value.
    value: RwSignal<String>,
    /// (value, label) pairs.
    options: Vec<(String, String)>,
) -> impl IntoView {
    view! {
        <div class="radio-group" role="radiogroup">
            {options
                .into_iter()
                .map(|(v, l)| {
                    let mine = v.clone();
                    let set = v.clone();
                    view! {
                        <label class="check-row">
                            <input
                                type="radio"
                                name=name.clone()
                                value=v
                                prop:checked=move || value.get() == mine
                                on:change=move |_| value.set(set.clone())
                            />
                            <span>{l}</span>
                        </label>
                    }
                })
                .collect_view()}
        </div>
    }
}

/// Number input clamped to `min..=max` on change.
#[component]
pub fn NumberRow(
    /// Label text.
    #[prop(into)]
    label: String,
    /// Bound value.
    value: RwSignal<i32>,
    /// Lowest allowed.
    min: i32,
    /// Highest allowed.
    max: i32,
    /// Disables the input.
    #[prop(into, optional)]
    disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <label class="form-row">
            <span class="form-label">{label}</span>
            <input
                type="number"
                min=min
                max=max
                disabled=disabled
                prop:value=move || value.get().to_string()
                on:change=move |ev| {
                    let v = event_target_value(&ev).parse().unwrap_or(min);
                    value.set(i32::clamp(v, min, max));
                }
            />
        </label>
    }
}
