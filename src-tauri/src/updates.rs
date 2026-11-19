//! App updates (`tauri-plugin-updater`, signed `latest.json` on GitHub Releases) and firmware fetch from the
//! trustcrypto GitHub release (allowlist on every redirect hop and the final URL, SHA-256 required and checked).
//!
//! Error texts are a contract with the UI: `crates/rustykey-ui/src/updates.rs` (`serious`) pops the dialog on an
//! automatic check only when the message contains "SHA-256", "refused", "parsed" or "installer". Integrity,
//! location, parse and install failures must keep one of those words; plain network failures must not.

use crate::device::DeviceService;
use onlykey_core::api::DeviceState;
use onlykey_core::firmware::{self, FW_API_URL, FirmwareError, ReleaseCheck};
use serde::Serialize;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tauri::{AppHandle, State, ipc::Channel};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Timeout of an app or firmware release check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout of a firmware file download.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Redirect hops a firmware fetch may follow.
const MAX_REDIRECTS: usize = 10;
/// Where a non-self-updating install (Linux `.deb`) sends the user.
const RELEASE_PAGE: &str = "https://github.com/horknfbr/rustykey-app/releases/latest";
/// Any firmware network failure (TS `asFirmwareUpdateError` fallback); no UI keyword, stays quiet on auto-checks.
const NETWORK_ERROR: &str = "Could not reach the firmware server.";

/// Session-only update state, managed by Tauri; nothing here is persisted.
#[derive(Default)]
pub struct Updates {
    /// Result of the last successful app check (`Some(None)` = up to date).
    app: Mutex<Option<Option<Update>>>,
    /// Body of the last successful firmware release lookup.
    fw_release: Mutex<Option<String>>,
    /// Verified firmware blocks and the release version they came from.
    fw_blocks: Mutex<Option<(String, Vec<Vec<u8>>)>>,
}

/// A newer app release, as the UI's `AppUpdate` decodes it (snake_case fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppUpdate {
    /// Release version.
    version: String,
    /// Release notes (may be empty).
    notes: String,
    /// This install can update itself; false on a Linux `.deb`.
    can_install: bool,
    /// Release page to open when it cannot.
    release_url: String,
}

/// A newer firmware release, as the UI's `FirmwareRelease` decodes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirmwareRelease {
    /// Release version with a leading `v`.
    version: String,
}

/// One `app_update_install` progress message.
#[derive(Clone, Serialize)]
pub struct InstallProgress {
    /// Bytes downloaded so far.
    received: u64,
    /// Total bytes, if the server said.
    total: Option<u64>,
}

/// Locks `m`, ignoring poisoning (the data is plain cache).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Returns the cached value unless `force` or nothing is cached; otherwise runs `fetch` and caches a success.
/// This is the host half of "once per session unless forced".
async fn cached_or_fetch<T, F>(
    slot: &Mutex<Option<T>>,
    force: bool,
    fetch: impl FnOnce() -> F,
) -> Result<T, String>
where
    T: Clone,
    F: Future<Output = Result<T, String>>,
{
    if !force && let Some(value) = lock(slot).clone() {
        return Ok(value);
    }
    let value = fetch().await?;
    *lock(slot) = Some(value.clone());
    Ok(value)
}

/// False only on Linux outside an AppImage: the updater replaces the AppImage file, not a `.deb` install.
fn can_self_update(linux: bool, in_appimage: bool) -> bool {
    !linux || in_appimage
}

/// [`can_self_update`] for this process (`APPIMAGE` is set by the AppImage runtime).
fn this_install_can_update() -> bool {
    can_self_update(
        cfg!(target_os = "linux"),
        std::env::var_os("APPIMAGE").is_some(),
    )
}

/// One updater request (15 s) against the endpoint in `tauri.conf.json`; errors as UI text.
async fn check_app<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<Option<Update>, String> {
    let failed = |e: tauri_plugin_updater::Error| format!("Could not check for app updates: {e}");
    let updater = app
        .updater_builder()
        .timeout(CHECK_TIMEOUT)
        .build()
        .map_err(failed)?;
    updater.check().await.map_err(failed)
}

/// `app_update_check { force }`: asks the updater endpoint (15 s) once per session unless `force`; `None` = up to date.
#[tauri::command]
pub async fn app_update_check(
    app: AppHandle,
    force: bool,
    state: State<'_, Updates>,
) -> Result<Option<AppUpdate>, String> {
    let update = cached_or_fetch(&state.app, force, || check_app(&app)).await?;
    Ok(update.map(|u| AppUpdate {
        version: u.version,
        notes: u.body.unwrap_or_default(),
        can_install: this_install_can_update(),
        release_url: RELEASE_PAGE.into(),
    }))
}

/// `app_update_install { onProgress }`: downloads (signature checked by the plugin) and installs the update found
/// by the last check, streaming progress, then restarts the app. Never returns `Ok`.
#[tauri::command]
pub async fn app_update_install(
    app: AppHandle,
    on_progress: Channel<InstallProgress>,
    state: State<'_, Updates>,
) -> Result<(), String> {
    if !this_install_can_update() {
        return Err(
            "This installation cannot update itself. Download the new version from the release page."
                .into(),
        );
    }
    let Some(mut update) = lock(&state.app).clone().flatten() else {
        return Err("No app update to install. Check for updates first.".into());
    };
    // The check's 15 s limit would cut off the installer download.
    update.timeout = None;
    let mut received = 0u64;
    update
        .download_and_install(
            |chunk, total| {
                received += chunk as u64;
                let _ = on_progress.send(InstallProgress { received, total });
            },
            || {},
        )
        .await
        .map_err(|e| format!("The update installer failed: {e}"))?;
    app.restart()
}

/// True when a redirect to `url` may be followed after `hops` earlier hops.
fn redirect_allowed(url: &str, hops: usize) -> bool {
    hops < MAX_REDIRECTS && firmware::is_allowed_firmware_url(url)
}

/// Redirect policy for firmware fetches: every hop must pass [`redirect_allowed`].
fn redirect_hop(attempt: reqwest::redirect::Attempt) -> reqwest::redirect::Action {
    if redirect_allowed(attempt.url().as_str(), attempt.previous().len()) {
        attempt.follow()
    } else {
        attempt.error(FirmwareError::HostNotAllowed)
    }
}

/// HTTP client for GitHub firmware fetches: rustls (ring), a User-Agent (GitHub API requires one), checked redirects.
fn fw_client() -> Result<reqwest::Client, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Fails only if another thread installed one first, which is just as good.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::Client::builder()
        .user_agent(concat!("RustyKey/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::custom(redirect_hop))
        .build()
        .map_err(|_| NETWORK_ERROR.to_string())
}

/// GETs an allowlisted firmware URL (`fetchFirmware`): request URL guard, checked hops, final URL guard, 2xx.
/// `failed` prefixes an HTTP status error.
async fn fw_get(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    failed: &str,
) -> Result<reqwest::Response, String> {
    firmware::guard_request_url(url).map_err(|e| e.to_string())?;
    let mut request = client.get(url).timeout(timeout);
    if url == FW_API_URL {
        request = request.header(reqwest::header::ACCEPT, "application/vnd.github+json");
    }
    let response = request.send().await.map_err(|e| {
        if e.is_redirect() {
            FirmwareError::HostNotAllowed.to_string()
        } else {
            NETWORK_ERROR.to_string()
        }
    })?;
    firmware::guard_final_url(response.url().as_str()).map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("{failed} ({}).", response.status().as_u16()));
    }
    Ok(response)
}

/// Fetches the latest firmware release JSON (15 s).
async fn fetch_release(client: &reqwest::Client) -> Result<String, String> {
    fw_get(
        client,
        FW_API_URL,
        CHECK_TIMEOUT,
        "Firmware release lookup failed",
    )
    .await?
    .text()
    .await
    .map_err(|_| NETWORK_ERROR.to_string())
}

/// Classifies `release_json` against the device's `current` version (`checkFirmwareUpdate`).
fn release_result(current: &str, release_json: &str) -> Result<Option<FirmwareRelease>, String> {
    match firmware::check_release(current, release_json) {
        ReleaseCheck::Current { .. } => Ok(None),
        ReleaseCheck::Available { latest, .. } => Ok(Some(FirmwareRelease { version: latest })),
        ReleaseCheck::InvalidRelease => Err(FirmwareError::InvalidRelease.to_string()),
        ReleaseCheck::MissingStdAsset => Err(firmware::select_release_asset(release_json)
            .err()
            .unwrap_or(FirmwareError::InvalidRelease)
            .to_string()),
    }
}

/// `fw_check { force }`: latest GitHub release (fetched once per session unless `force`) vs the connected
/// device's firmware; `None` = up to date.
#[tauri::command]
pub async fn fw_check(
    force: bool,
    state: State<'_, Updates>,
    device: State<'_, DeviceService>,
) -> Result<Option<FirmwareRelease>, String> {
    let snapshot = device.snapshot();
    if snapshot.state == DeviceState::Disconnected {
        return Err("No OnlyKey connected.".into());
    }
    let current = snapshot.firmware.unwrap_or_default();
    let json = cached_or_fetch(&state.fw_release, force, || async {
        fetch_release(&fw_client()?).await
    })
    .await?;
    release_result(&current, &json)
}

/// Checks downloaded `bytes` against the asset's SHA-256 and parses them into blocks; errors as UI text.
fn verify_firmware(asset: &firmware::ReleaseAsset, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    firmware::verify_download(bytes, &asset.sha256).map_err(|e| e.to_string())
}

/// `fw_download`: the latest STD firmware (60 s, allowlisted hops, SHA-256 required and matched) as blocks for
/// `LoadFirmware`; cached for the session per release version.
#[tauri::command]
pub async fn fw_download(state: State<'_, Updates>) -> Result<Vec<Vec<u8>>, String> {
    let client = fw_client()?;
    let json = cached_or_fetch(&state.fw_release, false, || fetch_release(&client)).await?;
    let asset = firmware::select_release_asset(&json).map_err(|e| e.to_string())?;
    if let Some((version, blocks)) = lock(&state.fw_blocks).as_ref()
        && *version == asset.version
    {
        return Ok(blocks.clone());
    }
    let bytes = fw_get(
        &client,
        &asset.download_url,
        DOWNLOAD_TIMEOUT,
        "Firmware download failed",
    )
    .await?
    .bytes()
    .await
    .map_err(|_| NETWORK_ERROR.to_string())?;
    let blocks = verify_firmware(&asset, &bytes)?;
    *lock(&state.fw_blocks) = Some((asset.version, blocks.clone()));
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    //! Canned-data tests (no network) plus one ignored live GitHub check.

    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A tiny firmware file: header line, two hex blocks.
    const FILE: &[u8] = b"BEGIN SIGNED FIRMWARE\n0102\n0304\n";

    /// Lowercase hex SHA-256 of `bytes`.
    fn sha(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Release JSON for v3.0.5 with the STD asset and an optional `digest`.
    fn release(digest: Option<&str>) -> String {
        serde_json::json!({
            "tag_name": "v3.0.5",
            "body": "",
            "assets": [{
                "name": "Signed_OnlyKey_3_0_5_STD.txt",
                "browser_download_url":
                    "https://github.com/trustcrypto/OnlyKey-Firmware/releases/download/v3.0.5/Signed_OnlyKey_3_0_5_STD.txt",
                "digest": digest,
            }],
        })
        .to_string()
    }

    /// Allowed hosts are followed on every hop; anything else, http, or too many hops is refused.
    #[test]
    fn redirect_hops() {
        for ok in [
            "https://github.com/trustcrypto/OnlyKey-Firmware/releases/download/v3.0.5/x.txt",
            "https://objects.githubusercontent.com/github-production-release-asset/1",
            "https://release-assets.githubusercontent.com/abc",
            "https://api.github.com/repos/trustcrypto/OnlyKey-Firmware/releases/latest",
        ] {
            assert!(redirect_allowed(ok, 0), "{ok}");
        }
        for bad in [
            "http://objects.githubusercontent.com/x",
            "https://evil.example.com/x",
            "https://github.com/someone/else/releases/download/x",
            "https://objects.githubusercontent.com.evil.com/x",
            "not a url",
        ] {
            assert!(!redirect_allowed(bad, 0), "{bad}");
        }
        assert!(!redirect_allowed(
            "https://objects.githubusercontent.com/x",
            MAX_REDIRECTS
        ));
        // A refused hop reads as "refused" so an auto-check still shows it.
        assert!(
            FirmwareError::HostNotAllowed
                .to_string()
                .contains("refused")
        );
    }

    /// Matching digest gives blocks; missing or wrong digest is refused with "SHA-256" in the message.
    #[test]
    fn digest_rules() {
        let good = firmware::select_release_asset(&release(Some(&format!("sha256:{}", sha(FILE)))))
            .unwrap();
        assert_eq!(
            verify_firmware(&good, FILE).unwrap(),
            vec![vec![1, 2], vec![3, 4]]
        );

        let missing = firmware::select_release_asset(&release(None)).unwrap_err();
        assert!(missing.to_string().contains("SHA-256"));

        let wrong = firmware::select_release_asset(&release(Some(&sha(b"other")))).unwrap();
        assert!(
            verify_firmware(&wrong, FILE)
                .unwrap_err()
                .contains("SHA-256")
        );
    }

    /// Release JSON maps to up to date / available / errors.
    #[test]
    fn release_results() {
        let json = release(Some(&sha(FILE)));
        assert_eq!(release_result("v3.0.5", &json), Ok(None));
        assert_eq!(
            release_result("v3.0.4", &json),
            Ok(Some(FirmwareRelease {
                version: "v3.0.5".into()
            }))
        );
        assert!(release_result("v3.0.4", "{").is_err());
        let no_std = r#"{"tag_name":"v3.0.5","assets":[]}"#;
        assert!(
            release_result("v3.0.4", no_std)
                .unwrap_err()
                .contains("Signed_OnlyKey_3_0_5_STD.txt")
        );
    }

    /// Fetches once, then serves the cache until forced; failures are not cached.
    #[test]
    fn once_per_session() {
        let slot = Mutex::new(None);
        let calls = AtomicUsize::new(0);
        let run = |force: bool, ok: bool| {
            tauri::async_runtime::block_on(cached_or_fetch(&slot, force, || async {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if ok { Ok(n) } else { Err("net".to_string()) }
            }))
        };
        assert_eq!(run(false, false), Err("net".into()));
        assert_eq!(run(false, true), Ok(2));
        assert_eq!(run(false, true), Ok(2));
        assert_eq!(run(true, true), Ok(3));
        assert_eq!(run(false, true), Ok(3));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// Only Linux outside an AppImage cannot self-update.
    #[test]
    fn can_install_detection() {
        assert!(can_self_update(false, false));
        assert!(can_self_update(true, true));
        assert!(!can_self_update(true, false));
    }

    /// Live: the real GitHub release parses and selects an STD asset with a digest. `cargo test -- --ignored`.
    #[test]
    #[ignore = "network"]
    fn live_github_release() {
        let json =
            tauri::async_runtime::block_on(async { fetch_release(&fw_client()?).await }).unwrap();
        let asset = firmware::select_release_asset(&json).unwrap();
        println!(
            "latest firmware: {} ({}, sha256 {})",
            asset.version, asset.filename, asset.sha256
        );
        assert_eq!(
            release_result("v0.0.1", &json).unwrap().unwrap().version,
            asset.version
        );
        let blocks = tauri::async_runtime::block_on(async {
            let client = fw_client()?;
            let res = fw_get(&client, &asset.download_url, DOWNLOAD_TIMEOUT, "failed").await?;
            println!("final firmware URL host: {:?}", res.url().host_str());
            verify_firmware(&asset, &res.bytes().await.map_err(|e| e.to_string())?)
        })
        .unwrap();
        println!("downloaded and verified {} blocks", blocks.len());
    }

    /// Live: the app update check (real `tauri.conf.json` updater config) against the not yet published release
    /// fails with readable text that does not pop a dialog on an automatic check.
    #[test]
    #[ignore = "network"]
    fn live_app_update_check() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), conf["plugins"]["updater"].clone());
        let app = tauri::test::mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .unwrap();
        let result = tauri::async_runtime::block_on(check_app(app.handle()));
        let Err(message) = result else {
            panic!("expected the unpublished release to fail")
        };
        println!("app update check error: {message}");
        assert!(
            !["SHA-256", "refused", "parsed", "installer"]
                .iter()
                .any(|k| message.contains(k))
        );
    }
}
