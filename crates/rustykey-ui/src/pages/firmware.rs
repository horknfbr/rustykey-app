//! Firmware page: auto-check preference, instructions by device state, and the firmware loader (`Firmware.tsx`).

use super::tools::{ExtLink, device_type};
use crate::backend::{Backend, Platform, backend};
use crate::components::HelpTip;
use crate::components::firmware_loader::{FirmwareLoader, can_load_firmware};
use crate::state::use_app;
use crate::updates::fw_start_auto_check;
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::DeviceState;
use onlykey_core::protocol::config_mode_how_to;

/// Firmware page.
#[component]
pub fn FirmwarePage() -> impl IntoView {
    let app = use_app();
    let desktop = backend().platform() == Platform::Desktop;
    let fresh = move || {
        matches!(
            app.snapshot.with(|s| s.state),
            DeviceState::Bootloader | DeviceState::Uninitialized
        )
    };
    let instructions = move || {
        if fresh() {
            view! {
                <p>
                    "To load a new firmware file to your OnlyKey, click [Choose File], select your firmware file, then click [Load Firmware to OnlyKey]."
                </p>
            }
            .into_any()
        } else if can_load_firmware(app) {
            view! {
                <p>
                    <u>"Step 1"</u>
                    ". "
                    {app.snapshot.with(|s| config_mode_how_to(device_type(s), true))}
                </p>
                <p>
                    <u>"Step 2"</u>
                    ". Click [Choose File], select your firmware file, then click [Load Firmware to OnlyKey]."
                </p>
                <p>
                    <u>"Step 3"</u>
                    ". The OnlyKey will flash white while loading your firmware, then will restart automatically when firmware load is complete."
                </p>
            }
            .into_any()
        } else {
            view! {
                <p>
                    "This version of firmware is outdated and does not support this feature. To load latest firmware follow the loading instructions "
                    <ExtLink href="https://docs.crp.to/usersguide.html#loading-onlykey-firmware">
                        "here"
                    </ExtLink>
                </p>
            }
            .into_any()
        }
    };
    view! {
        <h2 class="page-title">
            "Load Firmware "
            <HelpTip
                href="https://docs.crp.to/upgradeguide.html#download-firmware"
                tooltip="OnlyKey supports auto firmware update through the OnlyKey App. This requires that 'Automatically check for firmware updates' is checked in your OnlyKey App settings. Firmware can also be manually downloaded by clicking here to open the firmware upgrade guide."
            />
        </h2>
        <div class="stack">
            {desktop
                .then(|| {
                    view! {
                        <label class="check-row">
                            <input
                                type="checkbox"
                                prop:checked=move || app.prefs.with(|p| p.auto_update_fw)
                                on:change=move |ev| {
                                    let mut prefs = app.prefs.get_untracked();
                                    prefs.auto_update_fw = event_target_checked(&ev);
                                    spawn_local(async move {
                                        let _ = app.save_prefs(prefs).await;
                                        fw_start_auto_check(app);
                                    });
                                }
                            />
                            <span>"Automatically check for firmware updates"</span>
                        </label>
                    }
                })}
            <fieldset class="step-fieldset">{instructions}</fieldset>
            <FirmwareLoader />
        </div>
    }
}
