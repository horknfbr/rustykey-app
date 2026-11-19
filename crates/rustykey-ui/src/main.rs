//! RustyKey UI entry point: mounts the Leptos app into the page body.

use leptos::prelude::*;

/// Sidebar tab names, in display order.
const TABS: [&str; 8] = [
    "Setup",
    "Slots",
    "Keys",
    "Backup",
    "Firmware",
    "Preferences",
    "Advanced",
    "Tools",
];

/// Root view: static sidebar skeleton with the title and tab names.
#[component]
fn App() -> impl IntoView {
    view! {
        <div class="app">
            <nav class="sidebar">
                <h1>"RustyKey"</h1>
                <ul>
                    {TABS
                        .iter()
                        .enumerate()
                        .map(|(i, tab)| view! { <li class:active=i == 0>{*tab}</li> })
                        .collect_view()}
                </ul>
            </nav>
            <main></main>
        </div>
    }
}

/// Mounts the app.
fn main() {
    mount_to_body(App);
}
