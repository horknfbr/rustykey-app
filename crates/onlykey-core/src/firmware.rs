//! Firmware file to blocks, version compare, in-app-support rule, release-asset selection and digest extraction.
//!
//! Pure parts of `parseFirmwareData` (`src/api/device/utils.ts`), `src/desktop/firmwareCheck.ts` and
//! `src/desktop/firmwareDownload.ts`. The HTTP lives in src-tauri.

use crate::encoding::{bytes_to_hex, hex_to_bytes};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use url::Url;

/// GitHub API URL of the latest firmware release.
pub const FW_API_URL: &str =
    "https://api.github.com/repos/trustcrypto/OnlyKey-Firmware/releases/latest";

/// Message for any refused download location.
const REFUSED_LOCATION: &str =
    "Firmware download refused: the location is not an allowed HTTPS GitHub path.";

/// Firmware file or release problem; `Display` is the original wording, [`FirmwareError::code`] the TS code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareError {
    /// URL is not HTTPS.
    NotHttps,
    /// URL host/path is not on the allowlist.
    HostNotAllowed,
    /// Release JSON unreadable or without a tag.
    InvalidRelease,
    /// The STD asset is missing or has no download URL (carries the file name).
    MissingAsset(String),
    /// The STD asset URL is not HTTPS (carries the file name).
    AssetNotHttps(String),
    /// Neither asset digest nor release body gives a SHA-256.
    MissingSha256,
    /// Downloaded bytes do not hash to the expected SHA-256.
    Sha256Mismatch,
    /// File text is not firmware (carries the message).
    InvalidFirmware(String),
}

impl FirmwareError {
    /// The `FirmwareUpdateErrorCode` string the TS app uses for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotHttps | Self::AssetNotHttps(_) => "not-https",
            Self::HostNotAllowed => "host-not-allowed",
            Self::InvalidRelease | Self::MissingAsset(_) => "invalid-release",
            Self::MissingSha256 => "missing-sha256",
            Self::Sha256Mismatch => "sha256-mismatch",
            Self::InvalidFirmware(_) => "invalid-firmware",
        }
    }
}

impl fmt::Display for FirmwareError {
    /// Writes the message the TS app throws for this error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHttps | Self::HostNotAllowed => f.write_str(REFUSED_LOCATION),
            Self::InvalidRelease => {
                f.write_str("Could not determine latest firmware version from GitHub.")
            }
            Self::MissingAsset(name) | Self::AssetNotHttps(name) => {
                write!(f, "Firmware release is missing HTTPS asset {name}.")
            }
            Self::MissingSha256 => f.write_str("Firmware release is missing a SHA-256 digest."),
            Self::Sha256Mismatch => {
                f.write_str("Firmware file SHA-256 does not match the GitHub release digest.")
            }
            Self::InvalidFirmware(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for FirmwareError {}

/// Firmware file text to blocks: optional "BEGIN SIGNED FIRMWARE" first line dropped, then each
/// non-blank line not starting with `--` is one block of hex-decoded bytes.
pub fn parse_blocks(text: &str) -> Result<Vec<Vec<u8>>, FirmwareError> {
    let mut lines = text.split('\n').peekable();
    if lines
        .peek()
        .is_some_and(|l| l.contains("BEGIN SIGNED FIRMWARE"))
    {
        lines.next();
    }
    lines
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("--"))
        .map(|l| hex_to_bytes(l).map_err(|e| FirmwareError::InvalidFirmware(e.to_string())))
        .collect()
}

/// JS `parseInt(s, 10)`: leading whitespace, optional sign, then digits; `None` for NaN.
fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let (neg, rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit);
    let mut any = false;
    let n = digits.fold(0i64, |acc, d| {
        any = true;
        acc.saturating_mul(10).saturating_add(i64::from(d - b'0'))
    });
    any.then_some(if neg { -n } else { n })
}

/// `[major, minor, patch]` with a leading `v`, any `-`/`+` label and c/n/p suffixes stripped; junk is 0.
pub fn version_tuple(version: &str) -> [i64; 3] {
    let v = version.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut out = [0; 3];
    for (slot, part) in out.iter_mut().zip(core.split('.')) {
        let part = part
            .strip_suffix(['c', 'n', 'p', 'C', 'N', 'P'])
            .unwrap_or(part);
        *slot = parse_int(part).unwrap_or(0);
    }
    out
}

/// Compares firmware versions numerically by [`version_tuple`].
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    version_tuple(a).cmp(&version_tuple(b))
}

/// In-app update is supported when the version has ≥ 10 chars and char 9 is not `.` or char 10 > 6.
pub fn supports_app_update(version: &str) -> bool {
    let c: Vec<char> = version.chars().collect();
    if c.len() < 10 {
        return false;
    }
    let minor = c.get(10).map_or(Some(0), |ch| ch.to_digit(10));
    c[9] != '.' || minor.is_some_and(|d| d > 6)
}

/// Release asset name for a version: `Signed_OnlyKey_<M>_<m>_<p>_STD.txt` (NaN parts print as "NaN").
pub fn firmware_filename(version: &str) -> String {
    let v = version.strip_prefix('v').unwrap_or(version);
    let mut parts = v.split('.');
    let mut next = || {
        let p = parts.next().filter(|p| !p.is_empty()).unwrap_or("0");
        parse_int(p).map_or_else(|| "NaN".to_string(), |n| n.to_string())
    };
    let (major, minor, patch) = (next(), next(), next());
    format!("Signed_OnlyKey_{major}_{minor}_{patch}_STD.txt")
}

/// True for an absolute `https:` URL.
fn is_https(url: &str) -> bool {
    Url::parse(url).is_ok_and(|u| u.scheme() == "https")
}

/// Allowed final (post-redirect) firmware URL: HTTPS on the trustcrypto/OnlyKey-Firmware API or
/// github.com paths, or on a GitHub release CDN host.
pub fn is_allowed_firmware_url(url: &str) -> bool {
    let Ok(u) = Url::parse(url) else {
        return false;
    };
    if u.scheme() != "https" {
        return false;
    }
    match u.host_str() {
        Some("api.github.com") => u.path().starts_with("/repos/trustcrypto/OnlyKey-Firmware/"),
        Some("github.com") => u.path().starts_with("/trustcrypto/OnlyKey-Firmware/"),
        Some(host) => matches!(
            host,
            "objects.githubusercontent.com"
                | "release-assets.githubusercontent.com"
                | "github-releases.githubusercontent.com"
        ),
        None => false,
    }
}

/// Allowed request URL: exactly [`FW_API_URL`], or an HTTPS github.com release download path.
pub fn is_allowed_firmware_request_url(url: &str) -> bool {
    if url == FW_API_URL {
        return true;
    }
    Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str() == Some("github.com")
            && u.path()
                .starts_with("/trustcrypto/OnlyKey-Firmware/releases/download/")
    })
}

/// Check before fetching a firmware URL (`fetchFirmware` request guard).
pub fn guard_request_url(url: &str) -> Result<(), FirmwareError> {
    if !is_https(url) {
        Err(FirmwareError::NotHttps)
    } else if !is_allowed_firmware_request_url(url) {
        Err(FirmwareError::HostNotAllowed)
    } else {
        Ok(())
    }
}

/// Check on the final URL after redirects (`fetchFirmware` response guard).
pub fn guard_final_url(url: &str) -> Result<(), FirmwareError> {
    if !is_https(url) {
        Err(FirmwareError::NotHttps)
    } else if !is_allowed_firmware_url(url) {
        Err(FirmwareError::HostNotAllowed)
    } else {
        Ok(())
    }
}

/// Lowercase, trimmed, without a `sha256:` prefix.
fn normalize_sha256(value: &str) -> String {
    let v = value.trim().to_lowercase();
    v.strip_prefix("sha256:").map(str::to_string).unwrap_or(v)
}

/// True for exactly 64 hex chars of the given case rule.
fn is_hex64(s: &str, lower_only: bool) -> bool {
    s.len() == 64
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || (b'a'..=b'f').contains(&b)
                || (!lower_only && (b'A'..=b'F').contains(&b))
        })
}

/// SHA-256 listed next to `filename` in a release body: on the same line, or on one of the next
/// three lines (stopping at another `.txt` name). Lowercased.
pub fn checksum_from_release_body(body: &str, filename: &str) -> Option<String> {
    if body.is_empty() || filename.is_empty() {
        return None;
    }
    let lines: Vec<&str> = body.split('\n').map(str::trim).collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with(filename) {
            continue;
        }
        let same_line = (0..line.len().saturating_sub(63))
            .filter_map(|s| line.get(s..s + 64))
            .find(|w| is_hex64(w, false));
        if let Some(hash) = same_line {
            return Some(hash.to_lowercase());
        }
        for next in lines.iter().take((i + 4).min(lines.len())).skip(i + 1) {
            if is_hex64(next, false) {
                return Some(next.to_lowercase());
            }
            if next.to_lowercase().ends_with(".txt") && *next != filename {
                break;
            }
        }
    }
    None
}

/// The STD firmware asset of a release and its expected SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// Release version with a leading `v` (e.g. `v3.0.4-prod`).
    pub version: String,
    /// Asset file name.
    pub filename: String,
    /// `browser_download_url` (HTTPS; still pass it through [`guard_request_url`]).
    pub download_url: String,
    /// Expected lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
}

/// Picks the STD asset from GitHub release JSON and its digest (asset `digest`, else the body).
pub fn select_release_asset(release_json: &str) -> Result<ReleaseAsset, FirmwareError> {
    let release: Value =
        serde_json::from_str(release_json).map_err(|_| FirmwareError::InvalidRelease)?;
    let tag = release["tag_name"].as_str().unwrap_or("");
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    if tag.is_empty() {
        return Err(FirmwareError::InvalidRelease);
    }
    let version = format!("v{tag}");
    let filename = firmware_filename(&version);
    let asset = release["assets"].as_array().and_then(|a| {
        a.iter()
            .find(|a| a["name"].as_str() == Some(filename.as_str()))
    });
    let url = asset
        .and_then(|a| a["browser_download_url"].as_str())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| FirmwareError::MissingAsset(filename.clone()))?;
    if !is_https(url) {
        return Err(FirmwareError::AssetNotHttps(filename));
    }
    let from_digest = asset
        .and_then(|a| a["digest"].as_str())
        .map(normalize_sha256)
        .filter(|d| is_hex64(d, true));
    let sha256 = from_digest
        .or_else(|| checksum_from_release_body(release["body"].as_str().unwrap_or(""), &filename))
        .ok_or(FirmwareError::MissingSha256)?;
    Ok(ReleaseAsset {
        version,
        filename,
        download_url: url.to_string(),
        sha256,
    })
}

/// Checks downloaded bytes against the expected SHA-256 and parses them into non-empty blocks.
pub fn verify_download(bytes: &[u8], expected_sha256: &str) -> Result<Vec<Vec<u8>>, FirmwareError> {
    let actual = bytes_to_hex(&Sha256::digest(bytes)).to_lowercase();
    if actual != expected_sha256 {
        return Err(FirmwareError::Sha256Mismatch);
    }
    let blocks = parse_blocks(&String::from_utf8_lossy(bytes))?;
    if blocks.is_empty() {
        return Err(FirmwareError::InvalidFirmware(
            "Downloaded firmware file could not be parsed.".into(),
        ));
    }
    Ok(blocks)
}

/// Outcome of comparing the current firmware with a fetched release (`checkFirmwareUpdate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseCheck {
    /// Current is the same or newer.
    Current {
        /// Release version.
        latest: String,
    },
    /// A newer release with an STD asset exists.
    Available {
        /// Release version.
        latest: String,
        /// STD asset file name.
        filename: String,
    },
    /// Release JSON unreadable or without a tag.
    InvalidRelease,
    /// Newer release, but no STD asset.
    MissingStdAsset,
}

/// Classifies a release for an auto/forced check. Callers first skip unsupported firmware:
/// `!supports_app_update(current) && is_initialized` means "unsupported" without fetching.
pub fn check_release(current: &str, release_json: &str) -> ReleaseCheck {
    let Ok(release) = serde_json::from_str::<Value>(release_json) else {
        return ReleaseCheck::InvalidRelease;
    };
    let tag = release["tag_name"].as_str().unwrap_or("");
    if tag.is_empty() {
        return ReleaseCheck::InvalidRelease;
    }
    let latest = if tag.starts_with('v') {
        tag.to_string()
    } else {
        format!("v{tag}")
    };
    let filename = firmware_filename(&latest);
    let has_std = release["assets"].as_array().is_some_and(|a| {
        a.iter()
            .any(|a| a["name"].as_str() == Some(filename.as_str()))
    });
    if compare_versions(current, &latest) != Ordering::Less {
        ReleaseCheck::Current { latest }
    } else if !has_std {
        ReleaseCheck::MissingStdAsset
    } else {
        ReleaseCheck::Available { latest, filename }
    }
}

#[cfg(test)]
mod tests {
    //! Ports of `firmwareCheck.test.ts` and `firmwareDownload.test.ts` (pure parts) and the
    //! firmware cases of `utils.test.ts`.

    use super::*;
    use serde_json::json;

    /// STD asset file name for 3.0.4.
    const STD: &str = "Signed_OnlyKey_3_0_4_STD.txt";
    /// IN_TRVL asset file name for 3.0.4.
    const IN_TRVL: &str = "Signed_OnlyKey_3_0_4_IN_TRVL.txt";
    /// Signed firmware file used by the download tests.
    const SIGNED_BODY: &str = "-----BEGIN SIGNED FIRMWARE-----\naabbccdd\n";

    /// The STD download URL.
    fn https() -> String {
        format!(
            "https://github.com/trustcrypto/OnlyKey-Firmware/releases/download/v3.0.4-prod/{STD}"
        )
    }

    /// sha256 hex of bytes.
    fn sha(bytes: &[u8]) -> String {
        bytes_to_hex(&Sha256::digest(bytes)).to_lowercase()
    }

    /// The live-layout release JSON, with top-level overrides.
    fn api_release(overrides: Value) -> String {
        let signed = sha(SIGNED_BODY.as_bytes());
        let mut r = json!({
            "tag_name": "v3.0.4-prod",
            "body": format!("**SHA 256 checksums**\r\n\r\n{STD}\r\n{signed}\r\n\r\n{IN_TRVL}\r\n{}\r\n", "a".repeat(64)),
            "assets": [{ "name": STD, "browser_download_url": https(), "digest": null }],
        });
        for (k, v) in overrides.as_object().unwrap() {
            r[k] = v.clone();
        }
        r.to_string()
    }

    /// supportsAppFirmwareUpdate: length then the 5.6 index check (12).
    #[test]
    fn supports_app_firmware_update_uses_length_lt_10_then_the_5_6_index_check() {
        assert!(!supports_app_update(""));
        assert!(!supports_app_update("v1"));
        assert!(!supports_app_update("v0.2-beta.6"));
        assert!(!supports_app_update("123456789.5"));
        assert!(supports_app_update("v2.1.2 STD"));
        assert!(supports_app_update("v3.0.4-prodc"));
        assert!(supports_app_update("123456789.7"));
        assert!(supports_app_update("123456789x0"));
    }

    /// Extra: exactly 10 chars with '.' at 9 reads char 10 as '0'; a non-digit is NaN.
    #[test]
    fn supports_app_update_edges() {
        assert!(!supports_app_update("123456789."));
        assert!(!supports_app_update("123456789.x"));
    }

    /// firmwareVersionTuple / compareFirmwareVersion (13).
    #[test]
    fn firmware_version_tuple_compares_numeric_x_y_z_after_stripping_labels() {
        assert_eq!(version_tuple("v3.0.4-prodc"), [3, 0, 4]);
        assert_eq!(version_tuple("v3.0.4-prod"), [3, 0, 4]);
        assert_eq!(version_tuple("v3.0.4-prodp"), [3, 0, 4]);
        assert_eq!(version_tuple("v3.0.4"), [3, 0, 4]);
        assert_eq!(version_tuple("v2.1.2 STD"), [2, 1, 2]);
        assert_eq!(version_tuple("v0.2-beta.6"), [0, 2, 0]);
        assert_eq!(
            compare_versions("v3.0.4-prodc", "v3.0.4-prod"),
            Ordering::Equal
        );
        assert_eq!(compare_versions("v3.0.4-prodp", "v3.0.4"), Ordering::Equal);
        assert_eq!(
            compare_versions("v2.1.2 STD", "v3.0.4-prod"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("v3.0.4-prod", "v3.0.3-prod"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("v0.2-beta.6", "v3.0.4-prod"),
            Ordering::Less
        );
    }

    /// Extra: suffix letters on a bare number are stripped; junk parts are 0.
    #[test]
    fn version_tuple_strips_suffix_letters() {
        assert_eq!(version_tuple("V3.1.2c"), [3, 1, 2]);
        assert_eq!(version_tuple("3.1n"), [3, 1, 0]);
        assert_eq!(version_tuple("x.y.z"), [0, 0, 0]);
        assert_eq!(compare_versions("", "v0.0.0"), Ordering::Equal);
    }

    /// checkFirmwareUpdate (6): v3.0.4-prodc vs v3.0.4-prod is current.
    #[test]
    fn check_firmware_update_treats_v3_0_4_prodc_vs_api_v3_0_4_prod_as_current() {
        assert_eq!(
            check_release("v3.0.4-prodc", &api_release(json!({}))),
            ReleaseCheck::Current {
                latest: "v3.0.4-prod".into()
            }
        );
    }

    /// checkFirmwareUpdate (7): v2.1.2 STD has an update available.
    #[test]
    fn check_firmware_update_returns_available_for_v2_1_2_std_vs_v3_0_4_prod() {
        assert_eq!(
            check_release("v2.1.2 STD", &api_release(json!({}))),
            ReleaseCheck::Available {
                latest: "v3.0.4-prod".into(),
                filename: STD.into()
            }
        );
    }

    /// checkFirmwareUpdate (8): v0.2-beta.6 is unsupported, so the caller never fetches.
    #[test]
    fn check_firmware_update_returns_unsupported_for_v0_2_beta_6_without_fetching() {
        assert!(!supports_app_update("v0.2-beta.6"));
    }

    /// checkFirmwareUpdate (8b): an uninitialized empty version still checks and finds an update.
    #[test]
    fn check_firmware_update_fetches_for_uninitialized_empty_version_and_returns_available() {
        assert_eq!(
            check_release("", &api_release(json!({}))),
            ReleaseCheck::Available {
                latest: "v3.0.4-prod".into(),
                filename: STD.into()
            }
        );
    }

    /// checkFirmwareUpdate (10): missing tag_name.
    #[test]
    fn check_firmware_update_returns_unavailable_invalid_release_when_tag_name_is_missing() {
        let json = json!({ "assets": [{ "name": STD }] }).to_string();
        assert_eq!(
            check_release("v2.1.2 STD", &json),
            ReleaseCheck::InvalidRelease
        );
        assert_eq!(
            check_release("v2.1.2 STD", "not json"),
            ReleaseCheck::InvalidRelease
        );
    }

    /// checkFirmwareUpdate (10b): only IN_TRVL published.
    #[test]
    fn check_firmware_update_returns_unavailable_missing_std_asset_when_only_in_trvl_is_published()
    {
        let json =
            api_release(json!({ "assets": [{ "name": IN_TRVL, "browser_download_url": "x" }] }));
        assert_eq!(
            check_release("v2.1.2 STD", &json),
            ReleaseCheck::MissingStdAsset
        );
    }

    /// buildFirmwareFilename: dotted and -prod tags.
    #[test]
    fn build_firmware_filename_maps_dotted_and_prod_tags_to_the_std_signed_txt_name() {
        assert_eq!(firmware_filename("v3.0.4"), STD);
        assert_eq!(firmware_filename("v3.0.4-prod"), STD);
        assert_eq!(firmware_filename("3.0.4"), STD);
        assert_eq!(firmware_filename("v3"), "Signed_OnlyKey_3_0_0_STD.txt");
        assert_eq!(
            firmware_filename("vx.1.2"),
            "Signed_OnlyKey_NaN_1_2_STD.txt"
        );
    }

    /// parseFirmwareChecksumFromReleaseBody: 64-hex line after the file name.
    #[test]
    fn parse_firmware_checksum_from_release_body_reads_the_64_hex_line_after_the_matching_filename()
    {
        let r: Value = serde_json::from_str(&api_release(json!({}))).unwrap();
        let body = r["body"].as_str().unwrap();
        assert_eq!(
            checksum_from_release_body(body, STD),
            Some(sha(SIGNED_BODY.as_bytes()))
        );
        assert_eq!(
            checksum_from_release_body(body, IN_TRVL),
            Some("a".repeat(64))
        );
    }

    /// parseFirmwareChecksumFromReleaseBody: same line.
    #[test]
    fn parse_firmware_checksum_from_release_body_accepts_filename_and_hash_on_the_same_line() {
        let h = sha(SIGNED_BODY.as_bytes());
        assert_eq!(
            checksum_from_release_body(&format!("{STD}  {h}"), STD),
            Some(h)
        );
    }

    /// parseFirmwareChecksumFromReleaseBody: missing pieces.
    #[test]
    fn parse_firmware_checksum_from_release_body_returns_null_when_body_filename_hash_is_missing() {
        assert_eq!(checksum_from_release_body("", STD), None);
        assert_eq!(checksum_from_release_body("no hashes here", STD), None);
        assert_eq!(
            checksum_from_release_body(&format!("{STD}\nnot-a-hash"), STD),
            None
        );
    }

    /// Extra: lookahead stops at another .txt name and at three lines.
    #[test]
    fn checksum_lookahead_limits() {
        let h = "B".repeat(64);
        assert_eq!(
            checksum_from_release_body(&format!("{STD}\n{IN_TRVL}\n{h}"), STD),
            None
        );
        assert_eq!(
            checksum_from_release_body(&format!("{STD}\n\n\n\n{h}"), STD),
            None
        );
        assert_eq!(
            checksum_from_release_body(&format!("{STD}\n\n\n{h}"), STD),
            Some("b".repeat(64))
        );
    }

    /// downloadLatestFirmware: verifies the asset digest against raw file bytes.
    #[test]
    fn download_latest_firmware_verifies_the_github_asset_digest_against_raw_file_bytes() {
        let h = sha(SIGNED_BODY.as_bytes());
        let json = api_release(json!({
            "tag_name": "v3.0.4", "body": "",
            "assets": [{ "name": STD, "browser_download_url": https(), "digest": format!("sha256:{h}") }],
        }));
        let asset = select_release_asset(&json).unwrap();
        assert_eq!(asset.version, "v3.0.4");
        assert_eq!(asset.sha256, h);
        assert_eq!(asset.download_url, https());
        assert_eq!(
            verify_download(SIGNED_BODY.as_bytes(), &asset.sha256).unwrap(),
            vec![vec![0xaa, 0xbb, 0xcc, 0xdd]]
        );
    }

    /// downloadLatestFirmware: body checksum when digest is null.
    #[test]
    fn download_latest_firmware_uses_the_release_body_checksum_when_asset_digest_is_null() {
        let asset = select_release_asset(&api_release(json!({}))).unwrap();
        assert_eq!(asset.version, "v3.0.4-prod");
        assert_eq!(asset.sha256, sha(SIGNED_BODY.as_bytes()));
    }

    /// downloadLatestFirmware: a valid digest beats a conflicting body checksum.
    #[test]
    fn download_latest_firmware_prefers_a_valid_asset_digest_over_a_conflicting_body_checksum() {
        let h = sha(SIGNED_BODY.as_bytes());
        let json = api_release(json!({
            "body": format!("{STD}\n{}", "b".repeat(64)),
            "assets": [{ "name": STD, "browser_download_url": https(), "digest": format!("SHA256:{h}") }],
        }));
        assert_eq!(select_release_asset(&json).unwrap().sha256, h);
    }

    /// downloadLatestFirmware: no tag.
    #[test]
    fn download_latest_firmware_throws_when_the_release_has_no_tag() {
        let e = select_release_asset(&json!({ "assets": [] }).to_string()).unwrap_err();
        assert_eq!(e, FirmwareError::InvalidRelease);
        assert!(
            e.to_string()
                .contains("Could not determine latest firmware")
        );
    }

    /// downloadLatestFirmware: no digest and no body checksum.
    #[test]
    fn download_latest_firmware_throws_when_digest_is_null_and_the_release_body_has_no_checksum() {
        let json = json!({
            "tag_name": "v3.0.4", "body": "no checksums",
            "assets": [{ "name": STD, "browser_download_url": https(), "digest": null }],
        });
        let e = select_release_asset(&json.to_string()).unwrap_err();
        assert!(e.to_string().contains("missing a SHA-256 digest"));
    }

    /// downloadLatestFirmware: bytes do not match the digest.
    #[test]
    fn download_latest_firmware_throws_when_the_downloaded_bytes_do_not_match_the_digest() {
        let e = verify_download(SIGNED_BODY.as_bytes(), &"c".repeat(64)).unwrap_err();
        assert!(e.to_string().contains("does not match"));
        assert_eq!(e.code(), "sha256-mismatch");
    }

    /// downloadLatestFirmware: body checksum does not match the bytes.
    #[test]
    fn download_latest_firmware_throws_when_the_body_checksum_does_not_match_the_downloaded_bytes()
    {
        let json = api_release(json!({ "body": format!("{STD}\n{}", "d".repeat(64)) }));
        let asset = select_release_asset(&json).unwrap();
        assert!(
            verify_download(SIGNED_BODY.as_bytes(), &asset.sha256)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    /// downloadLatestFirmware: asset URL not HTTPS.
    #[test]
    fn download_latest_firmware_throws_when_the_asset_url_is_not_https() {
        let json = api_release(json!({
            "assets": [{ "name": STD, "browser_download_url": "http://evil.example/fw.txt", "digest": sha(SIGNED_BODY.as_bytes()) }],
        }));
        let e = select_release_asset(&json).unwrap_err();
        assert!(e.to_string().contains("missing HTTPS asset"));
        assert_eq!(e.code(), "not-https");
    }

    /// downloadLatestFirmware: no STD asset.
    #[test]
    fn download_latest_firmware_throws_when_the_asset_list_does_not_include_the_std_file() {
        let e = select_release_asset(&api_release(json!({ "assets": [] }))).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("Firmware release is missing HTTPS asset {STD}.")
        );
        assert_eq!(e.code(), "invalid-release");
    }

    /// downloadLatestFirmware: downloaded file is not hex firmware.
    #[test]
    fn download_latest_firmware_throws_when_the_downloaded_file_is_not_hex_firmware() {
        let html = b"<html>not firmware</html>";
        let e = verify_download(html, &sha(html)).unwrap_err();
        assert!(e.to_string().contains("Invalid hex"));
    }

    /// downloadLatestFirmware: signed file with no blocks.
    #[test]
    fn download_latest_firmware_throws_when_the_signed_file_has_no_firmware_blocks() {
        let empty = b"-----BEGIN SIGNED FIRMWARE-----\n\n";
        let e = verify_download(empty, &sha(empty)).unwrap_err();
        assert!(e.to_string().contains("could not be parsed"));
    }

    /// fetchFirmware (D3): non-HTTPS request URL.
    #[test]
    fn fetch_firmware_refuses_a_non_https_request_url() {
        let url = format!(
            "http://github.com/trustcrypto/OnlyKey-Firmware/releases/download/v3.0.4-prod/{STD}"
        );
        assert_eq!(guard_request_url(&url), Err(FirmwareError::NotHttps));
    }

    /// fetchFirmware (D6): non-HTTPS final URL.
    #[test]
    fn fetch_firmware_refuses_a_final_response_url_that_is_not_https() {
        let e = guard_final_url(
            "http://objects.githubusercontent.com/github-production-release-asset/x",
        );
        assert_eq!(e.unwrap_err().code(), "not-https");
    }

    /// fetchFirmware (D5): CDN final URL after a github.com request.
    #[test]
    fn fetch_firmware_allows_objects_githubusercontent_com_after_a_github_com_download_request() {
        assert_eq!(guard_request_url(&https()), Ok(()));
        assert_eq!(
            guard_final_url(
                "https://objects.githubusercontent.com/github-production-release-asset/abc"
            ),
            Ok(())
        );
        assert_eq!(guard_request_url(FW_API_URL), Ok(()));
        assert_eq!(guard_final_url(FW_API_URL), Ok(()));
    }

    /// downloadLatestFirmware (D2): non-GitHub download host is refused before fetching.
    #[test]
    fn download_latest_firmware_refuses_a_browser_download_url_on_a_non_git_hub_host() {
        let json = api_release(json!({
            "body": "",
            "assets": [{ "name": STD, "browser_download_url": "https://evil.example/fw.txt", "digest": format!("sha256:{}", sha(SIGNED_BODY.as_bytes())) }],
        }));
        let asset = select_release_asset(&json).unwrap();
        assert_eq!(
            guard_request_url(&asset.download_url).unwrap_err().code(),
            "host-not-allowed"
        );
    }

    /// Extra: allowlist edge cases (WHATWG parsing, paths normalised before the prefix check).
    #[test]
    fn firmware_url_allowlist_edges() {
        assert!(is_allowed_firmware_url(
            "https://GitHub.com/trustcrypto/OnlyKey-Firmware/x"
        ));
        assert!(is_allowed_firmware_url(
            "https://release-assets.githubusercontent.com/a"
        ));
        assert!(is_allowed_firmware_url(
            "https://github-releases.githubusercontent.com/a"
        ));
        assert!(!is_allowed_firmware_url(
            "https://github.com/trustcrypto/OnlyKey-Firmware/../evil/x"
        ));
        assert!(!is_allowed_firmware_url("https://github.com/other/repo"));
        assert!(!is_allowed_firmware_url(
            "https://api.github.com/repos/other/x"
        ));
        assert!(!is_allowed_firmware_url(
            "https://evil.example/trustcrypto/OnlyKey-Firmware/"
        ));
        assert!(!is_allowed_firmware_url("not a url"));
        assert!(!is_allowed_firmware_request_url(
            "https://github.com/trustcrypto/OnlyKey-Firmware/archive/x"
        ));
        assert!(!is_allowed_firmware_request_url(
            "https://objects.githubusercontent.com/a"
        ));
    }

    /// utils: firmware files drop the signed header, blanks and `--` lines.
    #[test]
    fn utils_parses_firmware_files_and_drops_the_signed_header() {
        let text = "-----BEGIN SIGNED FIRMWARE-----\naabbcc\n\n-- skip\nddee\n";
        assert_eq!(
            parse_blocks(text).unwrap(),
            vec![vec![0xaa, 0xbb, 0xcc], vec![0xdd, 0xee]]
        );
    }

    /// utils: non-hex blocks are rejected.
    #[test]
    fn utils_rejects_firmware_files_with_non_hex_blocks() {
        let e = parse_blocks("-----BEGIN SIGNED FIRMWARE-----\nnot-hex\n").unwrap_err();
        assert!(e.to_string().contains("Invalid hex"));
    }

    /// Extra: header only counts on the first line; CRLF is fine.
    #[test]
    fn parse_blocks_header_and_crlf() {
        assert_eq!(
            parse_blocks("aa\r\nbb\r\n").unwrap(),
            vec![vec![0xaa], vec![0xbb]]
        );
        assert_eq!(
            parse_blocks("BEGIN SIGNED FIRMWARE\naa").unwrap(),
            vec![vec![0xaa]]
        );
        assert!(parse_blocks("aa\nBEGIN SIGNED FIRMWARE\n").is_err());
    }
}
