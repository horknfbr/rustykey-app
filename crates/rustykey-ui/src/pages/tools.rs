//! Tools page: app update settings, WebCrypt and OnlyKey Agent links (`Tools.tsx`, `AppUpdateSettings.tsx`).
//! Also the small helpers the Keys / Backup / Firmware / Preferences / Advanced pages share.

use crate::backend::{Backend, Platform, PrefsPatch, backend};
use crate::components::{Button, HelpTip};
use crate::state::use_app;
use crate::updates::{Phase, app_check_now, app_updates};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{DeviceKind, Snapshot};
use onlykey_core::device_type::DeviceType;

// ---------- Shared page helpers ----------

/// Device type for the config-mode wording helpers (DUO vs everything else).
pub fn device_type(s: &Snapshot) -> DeviceType {
    if s.kind == DeviceKind::Duo {
        DeviceType::Duo
    } else {
        DeviceType::Classic
    }
}

/// Link that opens `href` in the system browser instead of the webview.
#[component]
pub fn ExtLink(
    /// https URL.
    href: &'static str,
    /// Extra class.
    #[prop(optional)]
    class: &'static str,
    /// Hover text.
    #[prop(optional)]
    title: &'static str,
    /// Link text.
    children: Children,
) -> impl IntoView {
    view! {
        <a
            href=href
            class=class
            title=title
            on:click=move |ev| {
                ev.prevent_default();
                spawn_local(async move { backend().open_url(href).await });
            }
        >
            {children()}
        </a>
    }
}

/// Two-or-more tab switcher (`PseudoTabs.tsx`); `on_change` runs after `active` changes.
#[component]
pub fn PseudoTabs(
    /// (id, label) per tab.
    tabs: &'static [(&'static str, &'static str)],
    /// Selected tab id.
    active: RwSignal<&'static str>,
    /// Called after a switch.
    #[prop(optional)]
    on_change: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        <div class="pseudo-tabs" role="tablist">
            {tabs
                .iter()
                .map(|(id, label)| {
                    let id = *id;
                    view! {
                        <button
                            type="button"
                            role="tab"
                            class="pseudo-tab"
                            class:active=move || active.get() == id
                            aria-selected=move || (active.get() == id).to_string()
                            on:click=move |_| {
                                active.set(id);
                                if let Some(f) = on_change {
                                    f.run(());
                                }
                            }
                        >
                            {*label}
                        </button>
                    }
                })
                .collect_view()}
        </div>
    }
}

/// One setting: title + help, optional description, controls, hint and warning (`PrefRow.tsx`).
#[component]
pub fn PrefRow(
    /// Heading.
    title: &'static str,
    /// (docs link, tooltip text).
    #[prop(optional)]
    tip: Option<(Option<&'static str>, &'static str)>,
    /// Text under the title.
    #[prop(optional, into)]
    description: Option<ViewFn>,
    /// Muted line under the controls.
    #[prop(optional, into)]
    hint: Option<Signal<Option<String>>>,
    /// Red line at the bottom.
    #[prop(optional)]
    warning: Option<&'static str>,
    /// Controls.
    children: Children,
) -> impl IntoView {
    view! {
        <section class="pref-row">
            <h3 class="pref-row-title">
                {title}
                {tip.map(|(href, text)| match href {
                    Some(h) => view! { <HelpTip tooltip=text href=h /> }.into_any(),
                    None => view! { <HelpTip tooltip=text /> }.into_any(),
                })}
            </h3>
            {description.map(|d| view! { <p class="pref-row-desc">{d.run()}</p> })}
            <div class="pref-row-actions">{children()}</div>
            {hint.map(|h| move || h.get().map(|t| view! { <p class="pref-row-hint">{t}</p> }))}
            {warning.map(|w| view! { <p class="pref-row-warning">{w}</p> })}
        </section>
    }
}

// ---------- Tools ----------

/// WebCrypt tools: (label, url, icon, tooltip) (`Tools.tsx:9-15`, `tooltips.ts`).
const WEBCRYPT_TOOLS: [(&str, &str, &str, &str); 5] = [
    (
        "Encrypt Messages",
        "https://apps.onlykey.io/app/encrypt",
        "🔒",
        "Securely encrypt messages in the browser using OnlyKey.",
    ),
    (
        "Decrypt Messages",
        "https://apps.onlykey.io/app/decrypt",
        "🔓",
        "Securely decrypt OpenPGP encrypted messages in the browser using OnlyKey",
    ),
    (
        "Encrypt Files",
        "https://apps.onlykey.io/app/encrypt-file",
        "📁",
        "Securely encrypt files in the browser using OnlyKey.",
    ),
    (
        "Decrypt Files",
        "https://apps.onlykey.io/app/decrypt-file",
        "📂",
        "Securely decrypt OpenPGP encrypted files in the browser using OnlyKey.",
    ),
    (
        "Password Vault",
        "https://apps.onlykey.io/app/vault",
        "🗝️",
        "Store passwords and other secrets encrypted in this browser with a key derived on your OnlyKey. Reading one back needs your OnlyKey. Needs firmware 3.1.0 or later.",
    ),
];

/// OnlyKey Agent docs (`TOOLTIPS.agent.href`).
const AGENT_URL: &str = "https://docs.crp.to/onlykey-agent.html";

/// Tool button grid.
fn tool_grid(
    tools: &'static [(&'static str, &'static str, &'static str, &'static str)],
) -> impl IntoView {
    view! {
        <div class="tool-btn-grid">
            {tools
                .iter()
                .map(|(label, href, icon, tip)| {
                    view! {
                        <ExtLink href=href class="tool-btn" title=tip>
                            <span class="tool-btn-icon" aria-hidden="true">
                                {*icon}
                            </span>
                            <span>{*label}</span>
                        </ExtLink>
                    }
                })
                .collect_view()}
        </div>
    }
}

/// App updates row: version, auto-check checkbox, "Check now", status (`AppUpdateSettings.tsx`).
#[component]
fn AppUpdateSettings() -> impl IntoView {
    let app = use_app();
    let s = app_updates();
    let current = env!("CARGO_PKG_VERSION");
    let auto = move || app.prefs.with(|p| p.auto_update);
    let busy = {
        let phase = s.phase.clone();
        move || phase.get().busy()
    };
    let status = {
        let s = s.clone();
        Signal::derive(move || {
            let latest = s.latest.get();
            match s.phase.get() {
                Phase::Checking => Some("Checking for updates…".into()),
                Phase::Downloading => Some(format!(
                    "Downloading {}…",
                    latest.unwrap_or_else(|| "update".into())
                )),
                Phase::Available => Some(format!(
                    "Version {} is available.",
                    latest.unwrap_or_default()
                )),
                Phase::Applying | Phase::Ready => Some(format!(
                    "Version {} is downloaded and verified.",
                    latest.unwrap_or_default()
                )),
                Phase::UpToDate => Some(format!("RustyKey {current} is up to date.")),
                _ => s.error.get(),
            }
        })
    };
    view! {
        <section class="tools-section">
            <PrefRow
                title="App updates"
                description=move || format!("This computer is running RustyKey {current}.")
                hint=status
            >
                <label class="check-row">
                    <input
                        type="checkbox"
                        prop:checked=auto
                        on:change=move |ev| {
                            // Turning it on starts the auto-check from `UpdateHosts`.
                            let patch = PrefsPatch {
                                auto_update: Some(event_target_checked(&ev)),
                                ..PrefsPatch::default()
                            };
                            spawn_local(async move {
                                let _ = app.save_prefs(patch).await;
                            });
                        }
                    />
                    <span>"Automatically check for app updates"</span>
                </label>
                <Button disabled=Signal::derive(busy) on:click=move |_| app_check_now()>
                    "Check now"
                </Button>
            </PrefRow>
        </section>
    }
}

/// Tools page.
#[component]
pub fn ToolsPage() -> impl IntoView {
    let desktop = backend().platform() == Platform::Desktop;
    view! {
        <h2 class="page-title">"Tools"</h2>
        {desktop.then(|| view! { <AppUpdateSettings /> })}
        <section class="tools-section">
            <h3 class="tools-section-title">
                "Securely use OpenPGP in the browser with OnlyKey WebCrypt "
                <HelpTip
                    href="https://docs.crp.to/webcrypt.html"
                    tooltip="OnlyKey WebCrypt provides a way to securely use OpenPGP in the browser. The Webcrypt app loads everything necessary to encrypt messages and files directly in the local browser without the need to send messages or files over the Internet. Data between OnlyKey and the browser is end-to-end encrypted. For OnlyKey firmware v3.0.4 or earlier, use apps.crp.to."
                />
            </h3>
            {tool_grid(&WEBCRYPT_TOOLS)}
        </section>
        <section class="tools-section">
            <h3 class="tools-section-title">
                "Securely use OpenPGP, SSH, Git signing and age on a local computer with OnlyKey Agent "
                <HelpTip
                    href=AGENT_URL
                    tooltip="OnlyKey Agent (onlykey-agent) uses keys that stay on your OnlyKey for OpenPGP, SSH, Git signing and age on a local computer. Keys are generated on or derived by the OnlyKey and never written to disk."
                />
            </h3>
            {tool_grid(&[(
                "OnlyKey Agent",
                AGENT_URL,
                "💻",
                "One agent for everything on this computer: GPG signing, encryption and decryption (email, Git commits, software packages, pass, post-quantum composite keys); SSH logins, Git push, SSH-signed commits, file transfers and tunnels; and age file encryption. Works with keys stored on the OnlyKey or derived from it.",
            )])}
        </section>
    }
}
