//! RustyKey UI entry point: app state, layout, session-keyed pages, global overlays.

mod backend;
mod components;
mod overlays;
mod pages;
mod shell;
mod state;
mod updates;

use components::{ConfirmDialog, WorkingDialog};
use leptos::prelude::*;
use overlays::{DeviceDialogs, DisconnectedOverlay, LockScreen};
use pages::{
    advanced::AdvancedPage, backup::BackupPage, firmware::FirmwarePage, keys::KeysPage,
    preferences::PreferencesPage, setup::SetupPage, slots::SlotsPage, tools::ToolsPage,
};
use shell::{DeviceMessages, Sidebar};
use state::{AppState, Tab, use_app};

/// Remounts `children` whenever `session_epoch` changes, dropping their local state (typed PINs etc.).
#[component]
fn SessionKeyed(
    /// Content to remount.
    children: ChildrenFn,
) -> impl IntoView {
    let app = use_app();
    move || {
        // `get`, not `track`: a memo that is never read never subscribes to its source,
        // so `track` alone would not rerun on a new epoch and secrets would outlive the session.
        let _ = app.epoch.get();
        children()
    }
}

/// The selected tab's page.
#[component]
fn CurrentPage() -> impl IntoView {
    let app = use_app();
    move || match app.tab.get() {
        Tab::Setup => view! { <SetupPage /> }.into_any(),
        Tab::Slots => view! { <SlotsPage /> }.into_any(),
        Tab::Keys => view! { <KeysPage /> }.into_any(),
        Tab::Backup => view! { <BackupPage /> }.into_any(),
        Tab::Firmware => view! { <FirmwarePage /> }.into_any(),
        Tab::Preferences => view! { <PreferencesPage /> }.into_any(),
        Tab::Advanced => view! { <AdvancedPage /> }.into_any(),
        Tab::Tools => view! { <ToolsPage /> }.into_any(),
    }
}

/// Root view: sidebar, page area with overlays, message terminal, dialogs.
#[component]
fn App() -> impl IntoView {
    AppState::start();
    view! {
        <div class="app">
            <Sidebar />
            <div class="main">
                <SessionKeyed>
                    <div class="page-area">
                        <main class="page">
                            <CurrentPage />
                        </main>
                        <LockScreen />
                        <DisconnectedOverlay />
                    </div>
                    <WorkingDialog />
                </SessionKeyed>
                <DeviceMessages />
            </div>
        </div>
        <ConfirmDialog />
        <DeviceDialogs />
        <updates::UpdateHosts />
    }
}

/// Mounts the app.
fn main() {
    mount_to_body(App);
}
