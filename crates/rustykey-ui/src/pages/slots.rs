//! Slots page: Classic / DUO slot grid that opens the slot editor (`SlotGrid.tsx`).

mod editor;
mod generator;

use crate::backend::{Backend, backend};
use crate::components::HelpTip;
use crate::state::{AppState, use_app};
use editor::SlotEditor;
use leptos::prelude::*;
use onlykey_core::api::{Command, DeviceError, DeviceKind, Reply};
use onlykey_core::protocol::{CLASSIC_SLOT_ROWS, DUO_PROFILE_COLUMNS, DUO_PROFILES, SlotCell};

/// Shown when the device reports no label for a slot.
const EMPTY_SLOT_LABEL: &str = "<empty>";
/// Slots tooltip (`tooltips.ts` slots).
const SLOTS_TIP: &str = "On the OnlyKey you have multiple buttons and each button has two slots assigned that can be activated by holding the button for less than or more than one second. Each slot can be set with a Label, URL, Username, Password, and multi-factor authentication. Slots with no label are shown as '<empty>' in the app. For security, only labels are read from the device — not other login fields — so '<empty>' does not indicate whether a slot is in use.";
/// Slots docs link.
const SLOTS_HREF: &str = "https://docs.crp.to/usersguide.html#slots";

/// Reads the labels again and stores them in the snapshot.
async fn refresh_labels(app: AppState) -> Result<(), DeviceError> {
    if let Reply::Labels { labels } = backend().send(Command::GetLabels).await? {
        app.snapshot.update(|s| s.labels = labels);
    }
    Ok(())
}

/// The slot's label, or `None` when the device sent none / "empty".
fn slot_label(app: AppState, index: u8) -> Option<String> {
    app.snapshot.with(|s| {
        s.labels[usize::from(index) - 1]
            .clone()
            .filter(|l| !l.is_empty() && !l.eq_ignore_ascii_case("empty"))
    })
}

/// Slots page.
#[component]
pub fn SlotsPage() -> impl IntoView {
    let app = use_app();
    let selected = RwSignal::new(None::<u8>);
    let on_select = Callback::new(move |i: u8| selected.set(Some(i)));
    let is_duo = move || app.snapshot.with(|s| s.kind == DeviceKind::Duo);
    view! {
        <h2 class="page-title">"Configure Slots"</h2>
        <div class="slots-content">
            <p class="slots-intro">
                "Slots are where you store login information such as a login URL, username, password, and two-factor. "
                <HelpTip href=SLOTS_HREF tooltip=SLOTS_TIP />
            </p>
            <p class="slots-label-note">
                {format!(
                    "Slots shown as {EMPTY_SLOT_LABEL} have no label set on the device. For security, the app only receives slot labels — not URLs, usernames, passwords, or other fields — so {EMPTY_SLOT_LABEL} does not mean a slot is unused.",
                )}
            </p>
            <hr class="slots-divider" />
            {move || {
                if is_duo() {
                    view! { <DuoLayout on_select /> }.into_any()
                } else {
                    view! { <ClassicLayout on_select /> }.into_any()
                }
            }}
            <p class="slots-footer">
                "Set a label on a slot and it will appear on the button above. Test new settings on a login page with a keyboard before relying on them in production."
            </p>
        </div>
        {move || {
            selected
                .get()
                .map(|slot| {
                    view! { <SlotEditor slot_id=slot on_close=Callback::new(move |()| selected.set(None)) /> }
                })
        }}
    }
}

/// Dark and light device photos; CSS shows the one for the theme.
#[component]
fn DevicePhoto(
    /// Image path without the `.ext`; `-light` is appended for the light one.
    base: &'static str,
    /// File extension.
    ext: &'static str,
    /// Alt text of the dark photo.
    alt: &'static str,
    /// Image class.
    class: &'static str,
) -> impl IntoView {
    view! {
        <img
            src=format!("{base}.{ext}")
            alt=alt
            class=format!("{class} slots-device-img--dark")
            draggable="false"
        />
        <img
            src=format!("{base}-light.{ext}")
            alt=""
            aria-hidden="true"
            class=format!("{class} slots-device-img--light")
            draggable="false"
        />
    }
}

/// Classic: photo in the middle, buttons 1/3/5 left and 2/4/6 right.
#[component]
fn ClassicLayout(
    /// Opens the editor for a slot index.
    on_select: Callback<u8>,
) -> impl IntoView {
    view! {
        <div class="slots-classic-wrap">
            <div class="slots-classic-grid">
                {CLASSIC_SLOT_ROWS
                    .iter()
                    .enumerate()
                    .map(|(i, row)| {
                        view! {
                            <SlotColumn cells=&row.left align="right" on_select />
                            {(i == 0)
                                .then(|| {
                                    view! {
                                        <div class="slots-classic-device-wrap">
                                            <DevicePhoto
                                                base="assets/onlykey-photo"
                                                ext="png"
                                                alt="OnlyKey device"
                                                class="slots-classic-device"
                                            />
                                        </div>
                                    }
                                })}
                            <SlotColumn cells=&row.right align="left" on_select />
                        }
                    })
                    .collect_view()}
            </div>
        </div>
    }
}

/// DUO: profile colour buttons, photo, then columns 1 | 3 | 2 for the profile.
#[component]
fn DuoLayout(
    /// Opens the editor for a slot index.
    on_select: Callback<u8>,
) -> impl IntoView {
    let profile = RwSignal::new(0usize);
    view! {
        <div class="slots-duo-wrap">
            <div class="slots-duo-profile">
                <span class="slots-duo-profile-label">"Profile:"</span>
                {DUO_PROFILES
                    .iter()
                    .enumerate()
                    .map(|(i, (id, name))| {
                        view! {
                            <button
                                type="button"
                                title=format!("{name} profile")
                                aria-label=format!("{name} profile")
                                aria-pressed=move || (profile.get() == i).to_string()
                                class=format!("slots-profile-dot slots-profile-dot--{id}")
                                class:slots-profile-dot--active=move || profile.get() == i
                                on:click=move |_| profile.set(i)
                            ></button>
                        }
                    })
                    .collect_view()}
            </div>
            <div class="slots-duo-device-wrap">
                <DevicePhoto
                    base="assets/duo-photo"
                    ext="jpg"
                    alt="OnlyKey Duo device"
                    class="slots-duo-device"
                />
            </div>
            <div class="slots-duo-columns">
                {move || {
                    DUO_PROFILE_COLUMNS[profile.get()]
                        .iter()
                        .map(|col| {
                            view! { <SlotColumn cells=col align="center" on_select /> }
                        })
                        .collect_view()
                }}
            </div>
        </div>
    }
}

/// A column of slot buttons.
#[component]
fn SlotColumn(
    /// Cells top to bottom.
    cells: &'static [SlotCell; 2],
    /// `left`, `right` or `center`.
    align: &'static str,
    /// Opens the editor for a slot index.
    on_select: Callback<u8>,
) -> impl IntoView {
    let class = if align == "center" {
        "slots-duo-col".to_string()
    } else {
        format!("slots-classic-col slots-classic-col--{align}")
    };
    view! {
        <div class=class>
            {cells
                .iter()
                .map(|cell| view! { <SlotPill cell=*cell align on_select /> })
                .collect_view()}
        </div>
    }
}

/// One slot button: `1a GitHub`, or `1a <empty>`.
#[component]
fn SlotPill(
    /// Button id and slot index.
    cell: SlotCell,
    /// `left`, `right` or `center`.
    align: &'static str,
    /// Opens the editor for a slot index.
    on_select: Callback<u8>,
) -> impl IntoView {
    let app = use_app();
    let label = move || slot_label(app, cell.index);
    view! {
        <div class=format!("slot-pill-wrap slot-pill-wrap--{align}")>
            <button
                type="button"
                class="slot-pill"
                class:slot-pill--empty=move || label().is_none()
                title=move || match label() {
                    Some(l) => format!("{}: {l}", cell.id),
                    None => format!("Slot {}: no label set", cell.id),
                }
                on:click=move |_| on_select.run(cell.index)
            >
                <span class="slot-pill-text">
                    {move || {
                        format!(
                            "{} {}",
                            cell.id,
                            label().unwrap_or_else(|| EMPTY_SLOT_LABEL.into()),
                        )
                    }}
                </span>
            </button>
        </div>
    }
}
