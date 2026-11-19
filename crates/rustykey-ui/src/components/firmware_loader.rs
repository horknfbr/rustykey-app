//! Firmware loader shared by the Firmware page and Setup step 11: file pick, load to device, download latest, use downloaded
//! (`Firmware.tsx:48-216`, `Setup.tsx` `FirmwareStep`).

use super::Button;
use super::restore_form::FilePick;
use crate::backend::{Backend, Platform, backend};
use crate::state::{AppState, use_app};
use crate::updates::{apply_firmware, fw, fw_check_now, fw_safe_moment};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::DeviceState;
use onlykey_core::firmware::{parse_blocks, supports_app_update};

/// Firmware may be loaded now: bootloader, uninitialized, or firmware that supports in-app update (`canLoadFirmware`).
pub fn can_load_firmware(app: AppState) -> bool {
    app.snapshot.with(|s| {
        matches!(
            s.state,
            DeviceState::Bootloader | DeviceState::Uninitialized
        ) || supports_app_update(s.firmware.as_deref().unwrap_or(""))
    })
}

/// Firmware file / download loader; `in_setup` hides controls Setup does not show.
#[component]
pub fn FirmwareLoader(
    /// True inside the Setup wizard.
    #[prop(optional)]
    in_setup: bool,
) -> impl IntoView {
    let app = use_app();
    let store = fw();
    let desktop = backend().platform() == Platform::Desktop;
    let file = RwSignal::new(None::<(String, String)>);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let status = RwSignal::new(None::<String>);
    let bootloader = move || app.snapshot.with(|s| s.state == DeviceState::Bootloader);
    let fresh = move || {
        matches!(
            app.snapshot.with(|s| s.state),
            DeviceState::Bootloader | DeviceState::Uninitialized
        )
    };
    // Setup does not gate on in-app support; the Firmware page does.
    let can_load = move || in_setup || can_load_firmware(app);
    let show_download = move || desktop && if in_setup { fresh() } else { can_load() };
    let downloaded = {
        let store = store.clone();
        move || {
            let latest = store.latest.get()?;
            let has_blocks = store
                .blocks
                .with(|b| b.as_ref().is_some_and(|b| !b.is_empty()));
            (in_setup && fresh() && has_blocks).then(|| format!("Use downloaded {latest}"))
        }
    };

    // Runs one load: `blocks` produces the firmware, then it is applied with page status lines.
    let run = move |blocks: Box<dyn std::future::Future<Output = Result<Vec<Vec<u8>>, String>>>| {
        loading.set(true);
        error.set(None);
        status.set(None);
        spawn_local(async move {
            let result = async {
                let blocks = Box::into_pin(blocks).await?;
                status.set(Some(if bootloader() {
                    "Sending firmware blocks...".into()
                } else {
                    "Triggering reboot to bootloader — do not remove OnlyKey...".into()
                }));
                apply_firmware(app, blocks).await
            }
            .await;
            match result {
                Ok(true) => status.set(Some("Firmware load complete!".into())),
                Ok(false) => status.set(Some(
                    "Device rebooting to bootloader. Reconnect and the update will resume automatically.".into(),
                )),
                Err(e) => {
                    status.set(None);
                    error.set(Some(e));
                }
            }
            loading.set(false);
        });
    };

    let load_file = move |_| {
        let Some((_, text)) = file.try_update(Option::take).flatten() else {
            return;
        };
        run(Box::new(async move {
            parse_blocks(&text).map_err(|e| e.to_string())
        }));
    };
    let download_latest = {
        let store = store.clone();
        move |_| {
            let latest = store.latest.get_untracked();
            run(Box::new(async move {
                let blocks = backend().fw_download().await?;
                status.set(Some(match latest {
                    Some(v) => format!("Downloaded firmware {v}. Starting update..."),
                    None => "Downloaded firmware. Starting update...".into(),
                }));
                Ok(blocks)
            }));
        }
    };
    let use_downloaded = {
        let store = store.clone();
        move |_| {
            let blocks = store.blocks.get_untracked();
            run(Box::new(async move {
                blocks
                    .map(|b| b.to_vec())
                    .ok_or_else(|| "Could not parse firmware file.".to_string())
            }));
        }
    };
    let check_disabled = {
        let store = store.clone();
        move || {
            loading.get()
                || store.phase.get().busy()
                || !{
                    app.snapshot.track();
                    app.working.track();
                    untrack(|| fw_safe_moment(app))
                }
        }
    };
    let store_error = store.error.clone();
    let display_error = move || {
        error.get().or_else(|| {
            status
                .with(Option::is_none)
                .then(|| store_error.get())
                .flatten()
        })
    };
    let version = move || app.snapshot.with(|s| s.firmware.clone());

    view! {
        <div class="stack">
            <FilePick
                accept=&["okfw", "txt", "hex"]
                file=file
                disabled=Signal::derive(move || loading.get() || !can_load())
            />
            <div class="button-row">
                <Button
                    disabled=Signal::derive(move || loading.get() || file.with(Option::is_none) || !can_load())
                    attr:title=move || file.with(Option::is_none).then_some("Select a firmware file first")
                    on:click=load_file
                >
                    {move || if in_setup && loading.get() { "Please wait…" } else { "Load Firmware to OnlyKey" }}
                </Button>
                <Show when=show_download>
                    <Button disabled=loading on:click=download_latest.clone()>
                        "Download Latest Firmware"
                    </Button>
                </Show>
                {move || downloaded().map(|label| view! {
                    <Button disabled=loading on:click=use_downloaded.clone()>{label}</Button>
                })}
                <Show when=move || !in_setup && desktop>
                    <Button
                        disabled=Signal::derive(check_disabled.clone())
                        on:click=move |_| {
                            error.set(None);
                            status.set(None);
                            fw_check_now(app);
                        }
                    >
                        "Check now"
                    </Button>
                </Show>
            </div>
            <Show when=move || !in_setup && version().is_some()>
                <p class="muted small">
                    "Current firmware: " <strong>{version}</strong> " "
                    {move || if bootloader() { "(Bootloader Mode)" } else { "" }}
                </p>
            </Show>
            {move || loading.get().then(|| {
                let pct = app.working.with(|w| w.as_ref().and_then(|w| w.progress)).filter(|p| *p > 0);
                view! {
                    <p class="muted small">
                        {status.get().unwrap_or_else(|| "Processing...".into())} " "
                        {pct.map(|p| format!("({p}%)"))}
                    </p>
                }
            })}
            {move || display_error().map(|e| view! { <p class="critical-text">{e}</p> })}
            {move || (!loading.get()).then(|| status.get()).flatten().map(|s| view! { <p class="status-success">{s}</p> })}
        </div>
    }
}
