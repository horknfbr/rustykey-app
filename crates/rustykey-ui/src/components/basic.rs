//! Button, HelpTip and Notice (`components/ui/forms.tsx`, `HelpTip.tsx`).

use crate::backend::{Backend, backend};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Button look: `SetButton` (primary), plain (secondary), `CautionButton` (danger).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonKind {
    /// Accent fill; the action.
    #[default]
    Primary,
    /// Quiet; cancel / back.
    Secondary,
    /// Red; wipes and other irreversible steps.
    Danger,
}

/// A `type="button"` button; add `on:click` at the call site.
#[component]
pub fn Button(
    /// Look.
    #[prop(optional)]
    kind: ButtonKind,
    /// Disables the button.
    #[prop(into, optional)]
    disabled: Signal<bool>,
    /// Label.
    children: Children,
) -> impl IntoView {
    let class = match kind {
        ButtonKind::Primary => "btn btn-primary",
        ButtonKind::Secondary => "btn btn-secondary",
        ButtonKind::Danger => "btn btn-danger",
    };
    view! {
        <button type="button" class=class disabled=disabled>
            {children()}
        </button>
    }
}

/// "?" help icon with a hover tooltip; with `href` it opens the docs in the system browser.
#[component]
pub fn HelpTip(
    /// Tooltip text.
    #[prop(into)]
    tooltip: String,
    /// Docs link (https).
    #[prop(into, optional)]
    href: Option<String>,
) -> impl IntoView {
    match href {
        Some(href) => {
            let url = href.clone();
            view! {
                <a
                    class="help-tip"
                    href=href
                    title=tooltip
                    aria-label="Help"
                    on:click=move |ev| {
                        ev.prevent_default();
                        let url = url.clone();
                        spawn_local(async move { backend().open_url(&url).await });
                    }
                >
                    "?"
                </a>
            }
            .into_any()
        }
        None => view! {
            <span class="help-tip" title=tooltip role="img" aria-label="Help">
                "?"
            </span>
        }
        .into_any(),
    }
}

/// Notice colour and role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NoticeKind {
    /// Neutral hint.
    #[default]
    Info,
    /// Failure (`role="alert"`).
    Error,
    /// Saved / done.
    Success,
}

/// Inline feedback box.
#[component]
pub fn Notice(
    /// Colour and role.
    #[prop(optional)]
    kind: NoticeKind,
    /// Body.
    children: Children,
) -> impl IntoView {
    let (class, role) = match kind {
        NoticeKind::Info => ("notice notice-info", "status"),
        NoticeKind::Error => ("notice notice-error", "alert"),
        NoticeKind::Success => ("notice notice-success", "status"),
    };
    view! {
        <div class=class role=role>
            {children()}
        </div>
    }
}
