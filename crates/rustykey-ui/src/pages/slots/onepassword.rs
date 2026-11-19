//! 1Password pieces of the Slots page (desktop only): sync panel, per-slot link badge, and the
//! slot editor's item picker. Secrets from `op_item_form` go straight into the editor's signals.

use crate::backend::{Backend, Platform, backend};
use crate::components::{Button, Modal, Notice, NoticeKind};
use crate::state::use_app;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::DeviceState;
use onlykey_core::onepassword::{
    ItemFill, LinkStatus, LinkedSlot, OpLogin, OpStatus, SlotSyncResult,
};

/// Tagged items from `op_list`, shared with the slot pills through context.
#[derive(Clone, Copy)]
pub struct OpLinks(pub RwSignal<Vec<LinkedSlot>>);

/// True when this build runs in the desktop app (1Password controls show only there).
pub fn op_supported() -> bool {
    backend().platform() == Platform::Desktop
}

/// Badge text and class suffix for `slot`, worst status first; `None` when no item is tagged.
fn badge(links: &[LinkedSlot], slot: u8) -> Option<(&'static str, &'static str)> {
    let rank = |s: LinkStatus| match s {
        LinkStatus::Synced => 0,
        LinkStatus::NeverSynced | LinkStatus::OutOfDate => 1,
        LinkStatus::Duplicate => 2,
    };
    let status = links
        .iter()
        .filter(|l| l.slot == slot)
        .map(|l| l.status)
        .max_by_key(|s| rank(*s))?;
    Some(match status {
        LinkStatus::Synced => ("linked", "linked"),
        LinkStatus::NeverSynced | LinkStatus::OutOfDate => ("out of date", "stale"),
        LinkStatus::Duplicate => ("duplicate", "duplicate"),
    })
}

/// Badge next to a slot pill: linked / out of date / duplicate. Renders nothing without links.
#[component]
pub fn LinkBadge(
    /// Slot number 1–24 (`slot` is reserved by the view macro).
    index: u8,
) -> impl IntoView {
    let slot = index;
    let links = use_context::<OpLinks>();
    move || {
        let links = links?;
        links.0.with(|l| {
            let titles: Vec<String> = l
                .iter()
                .filter(|x| x.slot == slot)
                .map(|x| x.title.clone())
                .collect();
            badge(l, slot).map(|(text, class)| {
                view! {
                    <span
                        class=format!("slot-link-badge slot-link-badge--{class}")
                        title=format!("1Password: {}", titles.join(", "))
                    >
                        {text}
                    </span>
                }
            })
        })
    }
}

/// "Sync from 1Password" with its disabled reason, results list and help text.
/// Loads `op_status`, then `op_list` into `links`.
#[component]
pub fn SyncPanel(
    /// Where the tagged items go (read by [`LinkBadge`]).
    links: RwSignal<Vec<LinkedSlot>>,
) -> impl IntoView {
    let app = use_app();
    let status = RwSignal::new(None::<OpStatus>);
    let list_error = RwSignal::new(None::<String>);
    let results = RwSignal::new(None::<Result<Vec<SlotSyncResult>, String>>);
    let syncing = RwSignal::new(false);

    let load_links = move || {
        spawn_local(async move {
            match backend().op_list().await {
                Ok(l) => {
                    list_error.set(None);
                    links.set(l);
                }
                Err(e) => list_error.set(Some(e)),
            }
        });
    };
    spawn_local(async move {
        let s = backend().op_status().await.unwrap_or_else(|e| OpStatus {
            error: Some(e),
            ..OpStatus::default()
        });
        let available = s.available;
        status.set(Some(s));
        if available
            && app
                .snapshot
                .with_untracked(|s| s.state == DeviceState::Unlocked)
        {
            load_links();
        }
    });

    let reason = move || -> Option<String> {
        match status.get() {
            None => Some("Looking for the 1Password CLI…".into()),
            Some(s) if !s.available => s
                .error
                .or(Some("The 1Password CLI is not available.".into())),
            Some(_) if app.snapshot.with(|s| s.state != DeviceState::Unlocked) => {
                Some("Unlock your OnlyKey to sync.".into())
            }
            Some(_) => None,
        }
    };
    let sync = move |_| {
        results.set(None);
        syncing.set(true);
        spawn_local(async move {
            let res = app
                .working("Syncing from 1Password…", backend().op_sync(None))
                .await;
            syncing.set(false);
            results.set(Some(res));
            load_links();
        });
    };

    view! {
        <section class="op-sync">
            <div class="op-sync-row">
                <Button
                    disabled=Signal::derive(move || syncing.get() || reason().is_some())
                    on:click=sync
                >
                    "Sync from 1Password"
                </Button>
                {move || reason().map(|r| view! { <span class="muted small">{r}</span> })}
            </div>
            {move || list_error.get().map(|e| view! { <p class="muted small">{e}</p> })}
            {move || {
                results
                    .get()
                    .map(|res| match res {
                        Err(e) => view! { <Notice kind=NoticeKind::Error>{e}</Notice> }.into_any(),
                        Ok(r) if r.is_empty() => {
                            view! {
                                <Notice>"No 1Password items are tagged onlykey/slot-N yet."</Notice>
                            }
                                .into_any()
                        }
                        Ok(r) => {
                            view! {
                                <ul class="op-sync-results">
                                    {r
                                        .into_iter()
                                        .map(|r| {
                                            view! {
                                                <li class:error=!r.ok>
                                                    {format!(
                                                        "Slot {}: {} {}",
                                                        r.slot,
                                                        if r.ok { "✓" } else { "✕" },
                                                        r.message,
                                                    )}
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            }
                                .into_any()
                        }
                    })
            }}
            <p class="muted small">
                "Tag a 1Password item onlykey/slot-N (N = 1–24; Classic uses 1–12) to link it to slot N. "
                "Sync is one way, from 1Password to the OnlyKey: it writes the label (a custom field named \"onlykey label\", else the title), URL, username, password and TOTP. "
                "It never wipes a slot; removing a tag leaves the slot as it is."
            </p>
        </section>
    }
}

/// Searchable list of 1Password Login titles; picking one loads its values into `on_fill`.
#[component]
pub fn OpPicker(
    /// Closes the picker.
    on_close: Callback<()>,
    /// Gets the picked item's values (the picker closes after).
    on_fill: Callback<ItemFill>,
) -> impl IntoView {
    let logins = RwSignal::new(None::<Result<Vec<OpLogin>, String>>);
    let query = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    spawn_local(async move {
        logins.set(Some(backend().op_logins().await));
    });

    let pick = move |id: String| {
        error.set(None);
        busy.set(true);
        spawn_local(async move {
            let res = backend().op_item_form(&id).await;
            busy.set(false);
            match res {
                Ok(fill) => {
                    on_fill.run(fill);
                    on_close.run(());
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };
    let shown = move || -> Vec<OpLogin> {
        let q = query.get().to_lowercase();
        logins.with(|l| match l {
            Some(Ok(l)) => l
                .iter()
                .filter(|x| q.is_empty() || x.title.to_lowercase().contains(&q))
                .cloned()
                .collect(),
            _ => Vec::new(),
        })
    };

    view! {
        <Modal title="Fill from 1Password" on_close>
            <div class="op-picker">
                <input
                    type="search"
                    class="op-picker-search"
                    placeholder="Search 1Password logins"
                    aria-label="Search 1Password logins"
                    autocomplete="off"
                    spellcheck="false"
                    bind:value=query
                />
                {move || match logins.get() {
                    None => Some(view! { <p class="muted small">"Loading 1Password logins…"</p> }.into_any()),
                    Some(Err(e)) => Some(view! { <Notice kind=NoticeKind::Error>{e}</Notice> }.into_any()),
                    Some(Ok(_)) => None,
                }}
                <ul class="op-picker-list" role="listbox">
                    {move || {
                        shown()
                            .into_iter()
                            .map(|l| {
                                let id = l.id.clone();
                                view! {
                                    <li>
                                        <button
                                            type="button"
                                            class="op-picker-item"
                                            disabled=move || busy.get()
                                            on:click=move |_| pick(id.clone())
                                        >
                                            <span>{l.title}</span>
                                            <span class="muted small">{l.vault}</span>
                                        </button>
                                    </li>
                                }
                            })
                            .collect_view()
                    }}
                </ul>
                {move || error.get().map(|e| view! { <Notice kind=NoticeKind::Error>{e}</Notice> })}
                <p class="muted small">
                    "Fills the form only; click Set Slot to write it to the OnlyKey."
                </p>
            </div>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A linked row for `slot` with `status`.
    fn row(slot: u8, status: LinkStatus) -> LinkedSlot {
        LinkedSlot {
            slot,
            item_id: "i".into(),
            title: "t".into(),
            vault: "v".into(),
            version: 1,
            status,
        }
    }

    /// The worst status of a slot wins; untagged slots get no badge.
    #[test]
    fn badge_priority() {
        let l = [
            row(1, LinkStatus::Synced),
            row(2, LinkStatus::NeverSynced),
            row(3, LinkStatus::Synced),
            row(3, LinkStatus::Duplicate),
        ];
        assert_eq!(badge(&l, 1), Some(("linked", "linked")));
        assert_eq!(badge(&l, 2), Some(("out of date", "stale")));
        assert_eq!(badge(&l, 3), Some(("duplicate", "duplicate")));
        assert_eq!(badge(&l, 4), None);
    }
}
