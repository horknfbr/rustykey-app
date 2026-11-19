//! 1Password sync (SPEC §1Password sync): runs the `op` CLI without a shell and pushes linked
//! items to the device through the core slot builder. `op` stdout is never logged and lives in
//! zeroizing buffers; only the first line of stderr reaches the user.

use crate::device::DeviceService;
use crate::window;
use onlykey_core::api::{Command as DeviceCommand, DeviceState, Event};
use onlykey_core::onepassword::{
    ItemDetail, ItemFill, ItemSummary, LIST_TAG, Link, LinkedSlot, Links, OpAccount, OpLogin,
    OpStatus, SlotSyncResult, fill_for_item, linked_slots, plan_for_item, sync_targets,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_store::StoreExt as _;
use zeroize::Zeroizing;

/// Longest one `op` call may take (the user may be at the Touch ID prompt).
const TIMEOUT: Duration = Duration::from_secs(60);
/// Own store file, so the UI's whole-object prefs writes never touch links.
const STORE_FILE: &str = "onepassword.json";
/// Store key: optional `--account` value.
const ACCOUNT_KEY: &str = "op_account";
/// Store key: `slot → {item_id, vault_id, version}`.
const LINKS_KEY: &str = "onepassword_links";
/// Shown when no `op` binary is found.
const NOT_FOUND: &str = "The 1Password CLI (op) was not found. Install it, then turn on \"Integrate with 1Password CLI\" in the 1Password app's Developer settings.";
/// Shown when a sync starts while the device is not unlocked.
const NEEDS_UNLOCK: &str = "Unlock your OnlyKey, then sync from 1Password again.";

/// `op` binary name on this OS.
#[cfg(windows)]
const EXE: &str = "op.exe";
/// `op` binary name on this OS.
#[cfg(not(windows))]
const EXE: &str = "op";

/// Set while a sync runs, so the tray and the window cannot overlap.
static SYNCING: AtomicBool = AtomicBool::new(false);

/// Clears [`SYNCING`] when dropped.
struct SyncGuard;

impl SyncGuard {
    /// Claims the sync slot, or explains that one is already running.
    fn acquire() -> Result<Self, String> {
        if SYNCING.swap(true, Ordering::SeqCst) {
            Err("A 1Password sync is already running.".into())
        } else {
            Ok(Self)
        }
    }
}

impl Drop for SyncGuard {
    /// Releases the sync slot.
    fn drop(&mut self) {
        SYNCING.store(false, Ordering::SeqCst);
    }
}

/// The `op` binary: first on `PATH`, then the SPEC install locations.
pub fn find_op() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut fixed = vec![
        PathBuf::from("/opt/homebrew/bin/op"),
        PathBuf::from("/usr/local/bin/op"),
    ];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        fixed.push(PathBuf::from(local).join(r"Microsoft\WinGet\Links\op.exe"));
    }
    fixed.push(PathBuf::from(r"C:\Program Files\1Password CLI\op.exe"));
    std::env::split_paths(&path)
        .map(|dir| dir.join(EXE))
        .chain(fixed)
        .find(|p| p.is_file())
}

/// Reads `r` to the end into a zeroizing buffer, never leaving an unwiped copy behind on growth.
fn read_secret(mut r: impl Read) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(64 * 1024));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = r.read(&mut chunk[..])?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > out.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n) * 2));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// First non-empty stderr line without op's `[ERROR] date time` prefix, or a generic message.
fn first_line(stderr: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(stderr);
    let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty()) else {
        return match code {
            Some(c) => format!("The 1Password CLI failed (exit code {c})."),
            None => "The 1Password CLI was stopped.".into(),
        };
    };
    let line = line.strip_prefix("[ERROR]").unwrap_or(line).trim_start();
    let mut parts = line.splitn(3, ' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(date), Some(time), Some(rest)) if date.contains('/') && time.contains(':') => {
            rest.trim().to_string()
        }
        _ => line.to_string(),
    }
}

/// Runs `op` with `args` (no shell, inherited env, stdin closed), killing it after [`TIMEOUT`].
/// Returns stdout on success, else the filtered first stderr line.
fn run(op: &Path, account: Option<&str>, args: &[String]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut cmd = Command::new(op);
    cmd.arg("--no-color");
    if let Some(account) = account {
        cmd.arg(format!("--account={account}"));
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        /// `CREATE_NO_WINDOW`: no console flash.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start the 1Password CLI: {e}"))?;
    let (Some(stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        return Err("Could not read from the 1Password CLI.".into());
    };
    let out = std::thread::spawn(move || read_secret(stdout));
    let err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The 1Password CLI did not answer within 60 seconds.".into());
            }
            Err(e) => return Err(format!("The 1Password CLI failed: {e}")),
        }
    };
    let stdout = out
        .join()
        .map_err(|_| "Could not read from the 1Password CLI.".to_string())?
        .map_err(|e| format!("Could not read from the 1Password CLI: {e}"))?;
    let stderr = err.join().unwrap_or_default();
    if status.success() {
        Ok(stdout)
    } else {
        Err(first_line(&stderr, status.code()))
    }
}

/// Runs `op` on a blocking thread; `with_account` adds the stored `--account`.
async fn op(
    app: &AppHandle,
    with_account: bool,
    args: &[&str],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let path = find_op().ok_or(NOT_FOUND)?;
    let account = with_account.then(|| stored_account(app)).flatten();
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    tauri::async_runtime::spawn_blocking(move || run(&path, account.as_deref(), &args))
        .await
        .map_err(|e| e.to_string())?
}

/// Parses `op` JSON output; the message never quotes the (possibly secret) bytes.
fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes)
        .map_err(|_| "The 1Password CLI returned output RustyKey cannot read.".to_string())
}

/// True for a 1Password item ID (letters and digits only), so it can never be read as a flag.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The `onepassword.json` store in the app config dir.
fn store(app: &AppHandle) -> Result<std::sync::Arc<tauri_plugin_store::Store<tauri::Wry>>, String> {
    let path = app
        .path()
        .app_config_dir()
        .map_err(|e| e.to_string())?
        .join(STORE_FILE);
    app.store(path).map_err(|e| e.to_string())
}

/// Stored `--account` value, if any.
fn stored_account(app: &AppHandle) -> Option<String> {
    store(app)
        .ok()?
        .get(ACCOUNT_KEY)
        .and_then(|v| v.as_str().map(String::from))
        .filter(|a| !a.is_empty())
}

/// Stored slot links (empty if none or unreadable).
fn stored_links(app: &AppHandle) -> Links {
    store(app)
        .ok()
        .and_then(|s| s.get(LINKS_KEY))
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

/// Saves slot links.
fn save_links(app: &AppHandle, links: &Links) -> Result<(), String> {
    let store = store(app)?;
    store.set(
        LINKS_KEY,
        serde_json::to_value(links).map_err(|e| e.to_string())?,
    );
    store.save().map_err(|e| e.to_string())
}

/// `op_status`: whether `op` runs, its version and accounts. Uses only `--version` and
/// `account list`, which need no unlock (no Touch ID prompt).
#[tauri::command]
pub async fn op_status(app: AppHandle) -> Result<OpStatus, String> {
    let account = stored_account(&app);
    if find_op().is_none() {
        return Ok(OpStatus {
            account,
            error: Some(NOT_FOUND.into()),
            ..OpStatus::default()
        });
    }
    let version = match op(&app, false, &["--version"]).await {
        Ok(out) => String::from_utf8_lossy(&out).trim().to_string(),
        Err(e) => {
            return Ok(OpStatus {
                account,
                error: Some(e),
                ..OpStatus::default()
            });
        }
    };
    let accounts = op(&app, false, &["account", "list", "--format", "json"])
        .await
        .and_then(|out| parse::<Vec<OpAccount>>(&out));
    let (accounts, error) = match accounts {
        Ok(a) => (a, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    Ok(OpStatus {
        available: true,
        version: Some(version),
        accounts,
        account,
        error,
    })
}

/// `op_set_account { account }`: stores the `--account` value (`None` or blank clears it).
#[tauri::command]
pub async fn op_set_account(app: AppHandle, account: Option<String>) -> Result<(), String> {
    let account = account
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty());
    if account
        .as_deref()
        .is_some_and(|a| a.chars().any(char::is_control))
    {
        return Err("That 1Password account name is not valid.".into());
    }
    let store = store(&app)?;
    match account {
        Some(a) => store.set(ACCOUNT_KEY, a),
        None => {
            store.delete(ACCOUNT_KEY);
        }
    }
    store.save().map_err(|e| e.to_string())
}

/// `op_list`: items tagged `onlykey/slot-N` with their link state (no secrets).
#[tauri::command]
pub async fn op_list(app: AppHandle) -> Result<Vec<LinkedSlot>, String> {
    let out = op(
        &app,
        true,
        &["item", "list", "--tags", LIST_TAG, "--format", "json"],
    )
    .await?;
    let items: Vec<ItemSummary> = parse(&out)?;
    Ok(linked_slots(&items, &stored_links(&app)))
}

/// `op_logins`: Login items for the editor's picker (titles only), sorted by title.
#[tauri::command]
pub async fn op_logins(app: AppHandle) -> Result<Vec<OpLogin>, String> {
    let out = op(
        &app,
        true,
        &["item", "list", "--categories", "Login", "--format", "json"],
    )
    .await?;
    let items: Vec<ItemSummary> = parse(&out)?;
    let mut logins: Vec<OpLogin> = items
        .into_iter()
        .map(|i| OpLogin {
            id: i.id,
            title: i.title,
            vault: i.vault.name,
        })
        .collect();
    logins.sort_by_key(|l| l.title.to_lowercase());
    Ok(logins)
}

/// Reads one item with its secrets revealed.
async fn item_detail(app: &AppHandle, id: &str, vault: Option<&str>) -> Result<ItemDetail, String> {
    if !valid_id(id) || vault.is_some_and(|v| !valid_id(v)) {
        return Err("That is not a 1Password item ID.".into());
    }
    let vault = vault.map(|v| format!("--vault={v}"));
    let mut args = vec!["item", "get", id, "--reveal", "--format", "json"];
    args.extend(vault.as_deref());
    let out = op(app, true, &args).await?;
    parse(&out)
}

/// `op_item_form { id }`: one item mapped to slot editor values. Sends secrets to the webview,
/// so it runs only on the user's explicit "Fill from 1Password".
#[tauri::command]
pub async fn op_item_form(app: AppHandle, id: String) -> Result<ItemFill, String> {
    let item = item_detail(&app, &id, None).await?;
    fill_for_item(&item).map_err(|e| e.to_string())
}

/// Writes one linked item to `slot`; stops at the first device error. Returns the new link.
async fn sync_one(app: &AppHandle, slot: u8, item: &ItemSummary) -> Result<Link, String> {
    let svc = app.state::<DeviceService>();
    let snap = svc.snapshot();
    if snap.state != DeviceState::Unlocked {
        return Err(NEEDS_UNLOCK.into());
    }
    let detail = item_detail(
        app,
        &item.id,
        Some(&item.vault.id)
            .filter(|v| !v.is_empty())
            .map(String::as_str),
    )
    .await?;
    let (planned, cmds) =
        plan_for_item(&detail, snap.kind, snap.pin_set).map_err(|e| e.to_string())?;
    if planned != slot {
        return Err("The item's slot tag changed during sync; sync again.".into());
    }
    let link = Link {
        item_id: detail.id.clone(),
        vault_id: detail.vault.id.clone(),
        version: detail.version,
    };
    drop(detail);
    for cmd in cmds {
        svc.send(cmd).await.map_err(|e| e.to_string())?;
    }
    Ok(link)
}

/// Syncs all linked slots (or just `slots`) from 1Password; never wipes a slot. Needs the device
/// unlocked. Ends with one `GetLabels` when anything was written.
pub async fn sync(app: &AppHandle, slots: Option<Vec<u8>>) -> Result<Vec<SlotSyncResult>, String> {
    let _guard = SyncGuard::acquire()?;
    if app.state::<DeviceService>().snapshot().state != DeviceState::Unlocked {
        return Err(NEEDS_UNLOCK.into());
    }
    let out = op(
        app,
        true,
        &["item", "list", "--tags", LIST_TAG, "--format", "json"],
    )
    .await?;
    let items: Vec<ItemSummary> = parse(&out)?;
    let mut links = stored_links(app);
    let mut results = Vec::new();
    for (slot, target) in sync_targets(&items, slots.as_deref()) {
        let outcome = match target {
            Ok(item) => sync_one(app, slot, item)
                .await
                .map(|link| (link, item.title.clone())),
            Err(e) => Err(e.to_string()),
        };
        results.push(match outcome {
            Ok((link, title)) => {
                links.insert(slot, link);
                SlotSyncResult {
                    slot,
                    ok: true,
                    message: format!("Wrote \"{title}\"."),
                }
            }
            Err(message) => SlotSyncResult {
                slot,
                ok: false,
                message,
            },
        });
    }
    if results.iter().any(|r| r.ok) {
        save_links(app, &links)?;
        let _ = app
            .state::<DeviceService>()
            .send(DeviceCommand::GetLabels)
            .await;
    }
    Ok(results)
}

/// `op_sync { slots }`: [`sync`] for the webview.
#[tauri::command]
pub async fn op_sync(
    app: AppHandle,
    slots: Option<Vec<u8>>,
) -> Result<Vec<SlotSyncResult>, String> {
    sync(&app, slots).await
}

/// Tray "Sync from 1Password": syncs every linked slot, posts each result to the device terminal,
/// and shows the window when anything failed.
pub fn sync_from_tray(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let say = |text: String| {
            let _ = app.emit("device://event", Event::Message { text });
        };
        let failed = match sync(&app, None).await {
            Ok(results) if results.is_empty() => {
                say("1Password: no items are tagged onlykey/slot-N.".into());
                false
            }
            Ok(results) => {
                for r in &results {
                    say(format!("1Password slot {}: {}", r.slot, r.message));
                }
                results.iter().any(|r| !r.ok)
            }
            Err(e) => {
                say(format!("1Password: {e}"));
                true
            }
        };
        if failed {
            window::show(&app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// op's `[ERROR] date time` prefix is dropped; only the first non-empty line is kept.
    #[test]
    fn stderr_first_line() {
        let e = b"\n[ERROR] 2026/11/19 10:00:00 \"nope\" isn't an item. Specify the item with its UUID\nmore\n";
        assert_eq!(
            first_line(e, Some(1)),
            "\"nope\" isn't an item. Specify the item with its UUID"
        );
        assert_eq!(first_line(b"plain failure\n", Some(1)), "plain failure");
        assert_eq!(
            first_line(b"", Some(3)),
            "The 1Password CLI failed (exit code 3)."
        );
    }

    /// Item IDs that could be read as flags or paths are refused.
    #[test]
    fn item_ids() {
        assert!(valid_id("abcdefghijklmnopqrstuvwxyz"));
        for bad in ["", "--help", "a b", "a/b", &"a".repeat(65)] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    /// Reading grows the buffer without losing bytes.
    #[test]
    fn read_secret_grows() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(*read_secret(&data[..]).unwrap(), data);
    }

    /// Stdout comes back on success; a failing exit with no stderr gets the generic message.
    #[cfg(unix)]
    #[test]
    fn run_success_and_failure() {
        let echo = Path::new("/bin/echo");
        assert_eq!(
            &*run(echo, None, &["hi".into()]).unwrap(),
            b"--no-color hi\n"
        );
        let fail = run(Path::new("/usr/bin/false"), None, &[]).unwrap_err();
        assert_eq!(fail, "The 1Password CLI failed (exit code 1).");
    }

    /// Live check of `op_status`'s calls on a machine with `op`; never runs item commands.
    #[test]
    #[ignore = "needs the 1Password CLI installed"]
    fn live_op_status() {
        let op = find_op().expect("op on PATH or a SPEC path");
        let version = run(&op, None, &["--version".into()]).expect("op --version");
        let accounts: Vec<OpAccount> = parse(
            &run(
                &op,
                None,
                &[
                    "account".into(),
                    "list".into(),
                    "--format".into(),
                    "json".into(),
                ],
            )
            .expect("op account list"),
        )
        .expect("account list JSON");
        println!(
            "available=true version={} accounts={}",
            String::from_utf8_lossy(&version).trim(),
            accounts.len()
        );
    }
}
