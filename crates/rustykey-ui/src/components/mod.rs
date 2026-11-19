//! Shared UI pieces for every page (tasks 9–11 reuse these; keep the set small).
//!
//! - [`Modal`]: centred card, dim backdrop, Esc closes unless `dismissible=false`.
//! - [`ConfirmDialog`]: host for [`crate::state::AppState::confirm`] (async `window.confirm`).
//! - [`WorkingDialog`]: spinner, message, optional progress bar; not dismissible. Driven by `AppState::working`.
//! - Form rows: [`TextRow`], [`CheckboxRow`], [`SelectRow`], [`RadioGroup`], [`NumberRow`].
//! - [`Button`] (primary / secondary / danger), [`HelpTip`], [`Notice`] (info / error / success).
//!
//! - Shared flows (stubs owned by task 11, used by Setup in task 9): [`firmware_loader::FirmwareLoader`], [`restore_form::RestoreForm`], [`key_select_dialog::KeySelectDialog`].
//!
//! Components forward `on:` and `attr:` to their root element, e.g. `<Button on:click=...>`.

#![allow(dead_code, unused_imports, reason = "used by the pages in tasks 9-11")]

mod basic;
mod dialogs;
pub mod firmware_loader;
mod form;
pub mod key_select_dialog;
pub mod restore_form;

pub use basic::{Button, ButtonKind, HelpTip, Notice, NoticeKind};
pub use dialogs::{ConfirmDialog, Modal, WorkingDialog};
pub use form::{CheckboxRow, NumberRow, RadioGroup, SelectRow, TextRow};
