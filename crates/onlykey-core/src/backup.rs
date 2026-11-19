//! Backup parse, verify (hash chain), file name, restore payload.
//!
//! Ports `src/utils/backupVerify.ts`, `parseBackupData` (`src/api/device/utils.ts:53`),
//! `src/services/backup/backupService.ts` and the file name from `src/components/Backup.tsx:36`.

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use sha2::{Digest, Sha256};
use std::fmt;

/// First line of a device-typed backup.
pub const BACKUP_BEGIN: &str = "-----BEGIN ONLYKEY BACKUP-----";
/// Last line of a device-typed backup.
pub const BACKUP_END: &str = "-----END ONLYKEY BACKUP-----";
/// Message for a backup whose hash line matches.
pub const VERIFIED_MESSAGE: &str = "Successfully verified backup SHA256 hash";

/// Why a backup failed to verify or parse; `Display` is the original wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupError {
    /// Nothing to verify.
    Empty,
    /// Hash mismatch, bad base64, or a hash line missing after data.
    Corrupt,
    /// No hash line at all.
    Unsupported,
    /// Restore file had no payload (or undecodable lines).
    Unparseable,
}

impl fmt::Display for BackupError {
    /// Writes the message the TS app shows for this error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "Backup data cannot be empty.",
            Self::Corrupt => "This backup file is corrupt.",
            Self::Unsupported => "This backup file does not support verification.",
            Self::Unparseable => "Could not parse backup file.",
        })
    }
}

impl std::error::Error for BackupError {}

/// Browser `atob` decoding: ASCII whitespace ignored, padding optional, stray bits allowed.
fn atob(text: &str) -> Option<Vec<u8>> {
    let mut s: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\x0C' | '\r'))
        .collect();
    if s.len().is_multiple_of(4) {
        for _ in 0..2 {
            if s.ends_with('=') {
                s.pop();
            }
        }
    }
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    engine.decode(s).ok()
}

/// The backup block from BEGIN through the first END after it (trimmed); whole text if no BEGIN.
pub fn extract_block(text: &str) -> &str {
    let Some(start) = text.find(BACKUP_BEGIN) else {
        return text.trim();
    };
    match text[start..].find(BACKUP_END) {
        Some(end) => text[start..start + end + BACKUP_END.len()].trim(),
        None => text[start..].trim(),
    }
}

/// Verifies the hash chain: h = 32 zero bytes, h = sha256(h ‖ line bytes) per data line,
/// compared against the `--<base64 sha256>` line. Ok carries [`VERIFIED_MESSAGE`].
pub fn verify(text: &str) -> Result<&'static str, BackupError> {
    let block = extract_block(text);
    if block.is_empty() {
        return Err(BackupError::Empty);
    }
    let mut hash = [0u8; 32];
    for line in block.split('\n').map(str::trim).filter(|l| !l.is_empty()) {
        if !line.contains("--") {
            let bytes = atob(line).ok_or(BackupError::Corrupt)?;
            hash = Sha256::new()
                .chain_update(hash)
                .chain_update(bytes)
                .finalize()
                .into();
        } else if !line.contains("BACKUP") {
            let file_hash = line.get(2..).and_then(atob).ok_or(BackupError::Corrupt)?;
            return if file_hash == hash {
                Ok(VERIFIED_MESSAGE)
            } else {
                Err(BackupError::Corrupt)
            };
        }
    }
    Err(BackupError::Unsupported)
}

/// `onlykey-backup-YYYY-MM-DDTHH-mm.txt` from the caller's local date-time.
pub fn file_name(year: i32, month: u8, day: u8, hour: u8, minute: u8) -> String {
    format!("onlykey-backup-{year}-{month:02}-{day:02}T{hour:02}-{minute:02}.txt")
}

/// OKRESTORE payload: every non-blank line not starting with `--`, base64-decoded and concatenated.
pub fn restore_payload(text: &str) -> Result<Vec<u8>, BackupError> {
    let mut out = Vec::new();
    for line in text.split('\n').map(str::trim) {
        if !line.is_empty() && !line.starts_with("--") {
            out.extend(atob(line).ok_or(BackupError::Unparseable)?);
        }
    }
    if out.is_empty() {
        return Err(BackupError::Unparseable);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Ports of `backupVerify.test.ts`, `backupService.test.ts` and the backup cases of `utils.test.ts`.

    use super::*;
    use base64::engine::general_purpose::STANDARD;

    /// A backup block for payload "Hi" with a matching hash line.
    fn signed_block() -> String {
        let payload = STANDARD.encode("Hi");
        let digest: [u8; 32] = Sha256::new()
            .chain_update([0u8; 32])
            .chain_update(b"Hi")
            .finalize()
            .into();
        format!(
            "{BACKUP_BEGIN}\n{payload}\n--{}\n{BACKUP_END}",
            STANDARD.encode(digest)
        )
    }

    /// verifyBackupData: empty input.
    #[test]
    fn verify_backup_data_should_reject_empty_backup_data() {
        assert_eq!(verify(""), Err(BackupError::Empty));
        assert!(BackupError::Empty.to_string().contains("empty"));
    }

    /// verifyBackupData: no hash line.
    #[test]
    fn verify_backup_data_should_reject_backup_without_verification_hash_line() {
        let r = verify(&format!("{BACKUP_BEGIN}\nYWJj\n{BACKUP_END}"));
        assert_eq!(r, Err(BackupError::Unsupported));
        assert!(
            BackupError::Unsupported
                .to_string()
                .contains("does not support verification")
        );
    }

    /// verifyBackupData: matching trailing hash line.
    #[test]
    fn verify_backup_data_accepts_a_backup_whose_trailing_hash_line_matches() {
        assert_eq!(verify(&signed_block()), Ok(VERIFIED_MESSAGE));
    }

    /// verifyBackupData: junk after the first END is ignored.
    #[test]
    fn verify_backup_data_ignores_duplicated_end_markers_after_the_first_backup_block() {
        let block = signed_block();
        let junk = format!("\nU=\n{BACKUP_END}\nU=\n{BACKUP_END}");
        let text = format!("{block}{junk}");
        assert_eq!(extract_block(&text), block);
        assert_eq!(verify(&text), Ok(VERIFIED_MESSAGE));
    }

    /// Extra: a changed data line breaks the chain.
    #[test]
    fn backup_verify_detects_corrupt_line() {
        let text = signed_block().replace("SGk=", "SGo=");
        assert_eq!(verify(&text), Err(BackupError::Corrupt));
        let text = signed_block().replace("SGk=", "S!k=");
        assert_eq!(verify(&text), Err(BackupError::Corrupt));
        assert_eq!(
            BackupError::Corrupt.to_string(),
            "This backup file is corrupt."
        );
    }

    /// Extra: text without BEGIN is used whole; BEGIN without END runs to the end.
    #[test]
    fn extract_block_edges() {
        assert_eq!(extract_block("  abc \n"), "abc");
        assert_eq!(
            extract_block(&format!("x {BACKUP_BEGIN}\nYQ== ")),
            format!("{BACKUP_BEGIN}\nYQ==")
        );
    }

    /// Extra: atob accepts missing padding and interior whitespace, rejects bad lengths.
    #[test]
    fn atob_matches_browser_rules() {
        assert_eq!(atob("SGk").unwrap(), b"Hi");
        assert_eq!(atob("S Gk=").unwrap(), b"Hi");
        assert_eq!(atob("SGl=").unwrap(), b"Hi");
        assert_eq!(atob("S"), None);
        assert_eq!(atob("SGk=="), None);
        assert_eq!(atob("a==="), None);
    }

    /// restoreBackupFromFile: comments skipped, payload decoded.
    #[test]
    fn restore_backup_from_file_parses_backup_text_and_sends_hex_to_the_device() {
        assert_eq!(
            restore_payload("-- header\nSGk=\n").unwrap(),
            vec![0x48, 0x69]
        );
    }

    /// restoreBackupFromFile: no payload.
    #[test]
    fn restore_backup_from_file_throws_when_the_file_has_no_payload() {
        assert_eq!(
            restore_payload("-- only comments\n\n"),
            Err(BackupError::Unparseable)
        );
        assert!(
            BackupError::Unparseable
                .to_string()
                .contains("Could not parse backup file")
        );
    }

    /// utils: backup files skip comments and blanks.
    #[test]
    fn utils_parses_backup_files_skipping_comments_and_blanks() {
        assert_eq!(
            restore_payload("-- comment\n\nSGk=\n-- end\n").unwrap(),
            b"Hi"
        );
    }

    /// Extra: BEGIN/END lines are skipped, lines concatenate in order.
    #[test]
    fn restore_payload_concatenates_lines() {
        let text = format!("{BACKUP_BEGIN}\r\nSGk=\r\nYQ==\r\n--hash\r\n{BACKUP_END}\r\n");
        assert_eq!(restore_payload(&text).unwrap(), b"Hia");
    }

    /// Extra: the file name is zero-padded local date-time.
    #[test]
    fn backup_file_name_format() {
        assert_eq!(
            file_name(2026, 3, 7, 9, 5),
            "onlykey-backup-2026-03-07T09-05.txt"
        );
    }
}
