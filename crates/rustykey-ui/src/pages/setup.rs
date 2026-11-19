//! Setup wizard (`Setup.tsx`): step 1 landing, Classic keypad PIN steps 2–7, DUO PIN step 2,
//! backup passphrase 8, OpenPGP backup key 9, restore 10, firmware 11.
//!
//! Secrets (typed PINs, passphrases, PGP keys) live only in the signals of the step component
//! that asks for them, so they drop when the step closes or the session epoch changes.

mod backup;
mod pins;

use crate::backend::{Backend, backend};
use crate::components::{Button, ButtonKind, HelpTip};
use crate::state::{AppState, use_app};
use leptos::prelude::*;
use leptos::task::spawn_local;
use onlykey_core::api::{
    Command, DeviceError, DeviceKind, DeviceState, PinKind, PinPhase, Snapshot,
};
use onlykey_core::device_type::DeviceType;
use onlykey_core::protocol::{config_mode_how_to, product_name};
use std::future::Future;

/// `TOOLTIPS.setup.text`.
const SETUP_TIP: &str = "Setup of OnlyKey includes things like setting PINs and backup passphrase. These can be changed later in the OnlyKey app.";
/// `TOOLTIPS.setup.href`.
const SETUP_HREF: &str = "https://docs.crp.to/usersguide.html#onlykey-setup";
/// `TOOLTIPS.setup.duoHref`.
const SETUP_DUO_HREF: &str = "https://docs.crp.to/duousersguide.html#onlykey-setup";

/// Core device type for the config-mode and product-name helpers (DUO, else Classic).
fn device_type(s: &Snapshot) -> DeviceType {
    if s.kind == DeviceKind::Duo {
        DeviceType::Duo
    } else {
        DeviceType::Classic
    }
}

/// Wizard state shared by every step: which step, guided/advanced flags, error line, busy flag
/// and the Classic PIN being entered. Holds no secrets.
#[derive(Clone, Copy)]
struct Wiz {
    /// App state.
    app: AppState,
    /// Open step, 1–11.
    step: RwSignal<u8>,
    /// Guided setup (Next walks through every step) vs one action from the landing page.
    guided: RwSignal<bool>,
    /// "Advanced setup options" checkbox on the uninitialized landing page.
    advanced: RwSignal<bool>,
    /// Error line above the step.
    error: RwSignal<Option<String>>,
    /// A step action is running (Next shows "Please wait…").
    busy: RwSignal<bool>,
    /// Classic PIN whose keypad entry was started last (for Cancel).
    pin_which: RwSignal<Option<PinKind>>,
    /// Device is a DUO.
    duo: Memo<bool>,
    /// Device is in the bootloader.
    bootloader: Memo<bool>,
    /// Device is uninitialized.
    uninitialized: Memo<bool>,
    /// Core device type (DUO / Classic).
    ty: Memo<DeviceType>,
}

impl Wiz {
    /// Creates the wizard state at step 1.
    fn new(app: AppState) -> Self {
        let snap = app.snapshot;
        Self {
            app,
            step: RwSignal::new(1),
            guided: RwSignal::new(false),
            advanced: RwSignal::new(false),
            error: RwSignal::new(None),
            busy: RwSignal::new(false),
            pin_which: RwSignal::new(None),
            duo: Memo::new(move |_| snap.with(|s| s.kind == DeviceKind::Duo)),
            bootloader: Memo::new(move |_| snap.with(|s| s.state == DeviceState::Bootloader)),
            uninitialized: Memo::new(move |_| snap.with(|s| s.state == DeviceState::Uninitialized)),
            ty: Memo::new(move |_| snap.with(device_type)),
        }
    }

    /// Neither uninitialized nor in the bootloader (`isInitialized`).
    fn initialized(self) -> bool {
        !self.uninitialized.get() && !self.bootloader.get()
    }

    /// Untracked [`Self::initialized`] for event handlers.
    fn initialized_now(self) -> bool {
        !self.uninitialized.get_untracked() && !self.bootloader.get_untracked()
    }

    /// Back to step 1 with everything reset (`goToLanding`).
    fn landing(self) {
        self.pin_which.try_set(None);
        self.guided.try_set(false);
        self.error.try_set(None);
        self.busy.try_set(false);
        self.step.try_set(1);
    }

    /// Moves to `step`, or back to the landing page when not in guided setup.
    fn next_or_landing(self, step: u8) {
        if self.guided.try_get_untracked().unwrap_or(false) {
            self.step.try_set(step);
        } else {
            self.landing();
        }
    }

    /// Cancel: on a Classic PIN step stops the keypad wait, then goes to the landing page.
    fn cancel(self) {
        let on_pin_step = !self.duo.get_untracked() && (2..=7).contains(&self.step.get_untracked());
        if let (true, Some(which)) = (on_pin_step, self.pin_which.get_untracked()) {
            spawn_local(async move {
                let _ = backend().send(Command::CancelClassicPin { which }).await;
            });
        }
        self.landing();
    }

    /// Starts keypad entry for `which` in the background; errors other than a cancel show above the step.
    fn pin_prompt(self, which: PinKind) {
        self.pin_which.try_set(Some(which));
        spawn_local(async move {
            let cmd = Command::ClassicPin {
                which,
                phase: PinPhase::Prompt,
            };
            if let Err(e) = backend().send(cmd).await
                && e != DeviceError::PinEntryCancelled
            {
                self.error.try_set(Some(e.to_string()));
            }
        });
    }

    /// Waits for the device to confirm the keypad PIN `which`.
    async fn pin_commit(self, which: PinKind) -> Result<(), String> {
        self.pin_which.try_set(Some(which));
        let cmd = Command::ClassicPin {
            which,
            phase: PinPhase::Commit,
        };
        backend().send(cmd).await.map(drop).map_err(err_text)
    }

    /// Runs a step action: marks busy, clears the error, shows `working` (if given) while `fut`
    /// runs, then shows its error unless it was a PIN cancel.
    fn run(
        self,
        working: Option<&'static str>,
        fut: impl Future<Output = Result<(), String>> + 'static,
    ) {
        self.busy.set(true);
        self.error.set(None);
        spawn_local(async move {
            let out = match working {
                Some(msg) => self.app.working(msg, fut).await,
                None => fut.await,
            };
            if let Err(e) = out
                && e != DeviceError::PinEntryCancelled.to_string()
            {
                self.error.try_set(Some(e));
            }
            self.busy.try_set(false);
        });
    }

    /// Guided Setup "Next" on the landing page (`startGuided`).
    fn start_guided(self) {
        self.guided.set(true);
        self.error.set(None);
        if self.duo.get_untracked() {
            self.step
                .set(if self.advanced.get_untracked() { 2 } else { 8 });
        } else {
            self.step.set(2);
            self.pin_prompt(PinKind::Primary);
        }
    }

    /// Opens one step from the landing page (`startUnguided`); Classic PIN steps start keypad entry.
    fn start_unguided(self, step: u8) {
        self.guided.set(false);
        self.error.set(None);
        self.step.set(step);
        if self.duo.get_untracked() {
            return;
        }
        match step {
            2 => self.pin_prompt(PinKind::Primary),
            4 => self.pin_prompt(PinKind::Second),
            6 => self.pin_prompt(PinKind::SelfDestruct),
            _ => {}
        }
    }
}

/// Error text for a failed device command.
fn err_text(e: DeviceError) -> String {
    e.to_string()
}

/// Sends `commands` in order and stops at the first error.
async fn send_all(commands: Vec<Command>) -> Result<(), String> {
    for cmd in commands {
        backend().send(cmd).await.map_err(err_text)?;
    }
    Ok(())
}

/// Setup wizard page.
#[component]
pub fn SetupPage() -> impl IntoView {
    let app = use_app();
    let wiz = Wiz::new(app);
    Effect::new(move || {
        app.setup_blocks_firmware_prompt
            .set(!matches!(wiz.step.get(), 1 | 11));
    });
    on_cleanup(move || app.setup_blocks_firmware_prompt.set(false));

    let duo_needs_config = move || {
        wiz.duo.get()
            && wiz.initialized()
            && wiz.step.get() == 1
            && app
                .snapshot
                .with(|s| s.locked && s.state != DeviceState::ConfigMode)
    };

    view! {
        <h2 class="page-title">
            {move || {
                let duo = wiz.duo.get();
                let title = if duo {
                    format!("{} Setup", product_name(DeviceType::Duo))
                } else {
                    "OnlyKey Setup".to_string()
                };
                let href = if duo { SETUP_DUO_HREF } else { SETUP_HREF };
                view! {
                    {title}
                    " "
                    <HelpTip href=href tooltip=SETUP_TIP />
                }
            }}
        </h2>
        <div class="setup-body">
            {move || wiz.error.get().map(|e| view! { <p class="critical-text" role="alert">{e}</p> })}
            <Show when=duo_needs_config>
                <p class="critical-text">
                    {format!(
                        "Put your {} into config mode before continuing.",
                        product_name(DeviceType::Duo),
                    )}
                </p>
            </Show>
            {move || match (wiz.step.get(), wiz.duo.get()) {
                (2, true) => view! { <pins::DuoPinStep wiz=wiz /> }.into_any(),
                (n @ 2..=7, false) => view! { <pins::ClassicPinStep wiz=wiz n=n /> }.into_any(),
                (8, _) => view! { <backup::PassphraseStep wiz=wiz /> }.into_any(),
                (9, _) => view! { <backup::PgpStep wiz=wiz /> }.into_any(),
                (10, _) => view! { <backup::RestoreStep wiz=wiz /> }.into_any(),
                (11, _) => view! { <backup::FirmwareStep wiz=wiz /> }.into_any(),
                _ => view! { <Landing wiz=wiz /> }.into_any(),
            }}
        </div>
    }
}

/// Step 1: bootloader / uninitialized intro or the "ready to use" block, plus the action buttons.
#[component]
fn Landing(
    /// Wizard state.
    wiz: Wiz,
) -> impl IntoView {
    let name = move || product_name(wiz.ty.get());
    let duo_name = product_name(DeviceType::Duo);
    let unguided = move |step: u8| move |_: leptos::ev::MouseEvent| wiz.start_unguided(step);
    view! {
        <div id="Step1">
            <Show when=move || wiz.bootloader.get()>
                <p>"The OnlyKey is in bootloader mode. Load firmware to continue setup."</p>
            </Show>
            <Show when=move || wiz.uninitialized.get()>
                <p>
                    "Begin the Guided Setup wizard by clicking [Next] at bottom. Or, if you would like to upgrade firmware on your device, select [Load Firmware]. Advanced users may enable advanced setup options by checking this box: "
                    <input type="checkbox" aria-label="Advanced setup" bind:checked=wiz.advanced />
                </p>
            </Show>
            <Show when=move || wiz.initialized()>
                <div class="setup-ready">
                    <p class="setup-ready-headline">{move || format!("Your {} is ready to use!", name())}</p>
                    <p>"Use the options below to change PINs or backup passphrase."</p>
                    <p class="critical-text">
                        {move || format!(
                            "Before selecting an option below, you must first put your {} into config mode.",
                            name(),
                        )}
                    </p>
                    <p>{move || format!("To do this {}", config_mode_how_to(wiz.ty.get(), false))}</p>
                </div>
            </Show>
            <div class="setup-actions">
                <Show when=move || !wiz.initialized()>
                    <Button on:click=unguided(11)>"Load Firmware"</Button>
                </Show>
                <Show when=move || wiz.initialized()>
                    <Button on:click=unguided(8)>"Set Backup Passphrase"</Button>
                    <Show
                        when=move || wiz.duo.get()
                        fallback=move || {
                            view! {
                                <Button on:click=unguided(2)>"Change Primary PIN"</Button>
                                <Button on:click=unguided(4)>"Change Secondary PIN"</Button>
                                <Button on:click=unguided(6)>"Change Self-Destruct PIN"</Button>
                            }
                        }
                    >
                        <Button on:click=unguided(2)>{format!("Set or Change {duo_name} PINs")}</Button>
                    </Show>
                </Show>
            </div>
            <Show when=move || wiz.uninitialized.get()>
                <div class="setup-nav">
                    <b>"Guided Setup"</b>
                    <Button
                        disabled=Signal::derive(move || wiz.busy.get())
                        on:click=move |_| wiz.start_guided()
                    >
                        {move || if wiz.busy.get() { "Please wait…" } else { "Next" }}
                    </Button>
                </div>
            </Show>
        </div>
    }
}

/// Bottom bar of steps 2–11 (`StepNav`): Next (when the step has an action) and Cancel.
#[component]
fn StepNav(
    /// Wizard state.
    wiz: Wiz,
    /// Next action; `None` shows only Cancel.
    #[prop(optional)]
    on_next: Option<Callback<()>>,
    /// Disables Next (it is also disabled while busy).
    #[prop(into, optional)]
    next_disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <div class="setup-nav">
            {on_next
                .map(|next| {
                    view! {
                        <Button
                            disabled=Signal::derive(move || wiz.busy.get() || next_disabled.get())
                            on:click=move |_| next.run(())
                        >
                            {move || if wiz.busy.get() { "Please wait…" } else { "Next" }}
                        </Button>
                    }
                })}
            <Button kind=ButtonKind::Secondary on:click=move |_| wiz.cancel()>
                "Cancel"
            </Button>
        </div>
    }
}

/// Inline https link opened in the system browser.
#[component]
fn ExtLink(
    /// Target URL.
    href: &'static str,
    /// Link text.
    children: Children,
) -> impl IntoView {
    view! {
        <a
            href=href
            on:click=move |ev| {
                ev.prevent_default();
                spawn_local(async move { backend().open_url(href).await });
            }
        >
            {children()}
        </a>
    }
}
