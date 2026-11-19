//! Host commands the webview cannot do itself: native file pick/save and opening https links.

use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt as _;
use tauri_plugin_opener::OpenerExt as _;

/// Largest text file `pick_text_file` reads.
const MAX_TEXT_BYTES: u64 = 4 * 1024 * 1024;

/// True for an absolute `https://` URL with a host; everything else is refused.
pub fn is_https(url: &str) -> bool {
    tauri::Url::parse(url).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some())
}

/// `pick_text_file { filters }`: asks for a UTF-8 text file (≤ 4 MB); `None` on cancel.
#[tauri::command]
pub async fn pick_text_file(
    app: AppHandle,
    filters: Vec<String>,
) -> Result<Option<(String, String)>, String> {
    let mut dialog = app.dialog().file();
    if !filters.is_empty() {
        let exts: Vec<&str> = filters.iter().map(String::as_str).collect();
        dialog = dialog.add_filter("Text", &exts);
    }
    let Some(picked) = dialog.blocking_pick_file() else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > MAX_TEXT_BYTES {
        return Err("File is too large (over 4 MB).".into());
    }
    let text = std::fs::read_to_string(&path).map_err(|_| "File is not UTF-8 text.".to_string())?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Some((name, text)))
}

/// `save_text_file { defaultName, text }`: asks where to save and writes `text`; false on cancel.
#[tauri::command]
pub async fn save_text_file(
    app: AppHandle,
    default_name: String,
    text: String,
) -> Result<bool, String> {
    let Some(picked) = app
        .dialog()
        .file()
        .set_file_name(default_name)
        .blocking_save_file()
    else {
        return Ok(false);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| e.to_string())?;
    Ok(true)
}

/// `open_url { url }`: opens an https URL in the system browser; other schemes are refused.
#[tauri::command]
pub async fn open_url(app: AppHandle, url: String) -> Result<(), String> {
    if !is_https(&url) {
        return Err("Only https links can be opened.".into());
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::is_https;

    /// Only absolute https URLs pass.
    #[test]
    fn https_only() {
        assert!(is_https("https://apps.onlykey.io/app/encrypt"));
        for bad in [
            "http://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "HTTPS:/",
            "/relative",
            "",
            "ftp://x.y",
        ] {
            assert!(!is_https(bad), "{bad}");
        }
    }
}
