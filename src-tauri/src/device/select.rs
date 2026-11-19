//! Picks the OnlyKey HID interface to open (port of `ChromeHidTransport.selectDevice`).

use onlykey_core::protocol::{BOOTLOADER_PRODUCT_ID, USB_IDS};

/// Usage page of the raw app interface on Beta 8+ firmware.
const BETA8_USAGE_PAGE: u16 = 0xFFAB;
/// Serial number every interface of a Beta 8+ device reports.
const BETA8_SERIAL: &str = "1000000000";
/// Interfaces the app never talks to: keyboard (Generic Desktop), FIDO, debug serial.
const NON_APP_USAGE_PAGES: [u16; 3] = [0x01, 0xF1D0, 0xFFC9];

/// One HID collection as the OS enumerates it; several can share a `path` (one interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// USB vendor ID.
    pub vid: u16,
    /// USB product ID.
    pub pid: u16,
    /// Top-level usage page; 0 when the backend does not report one.
    pub usage_page: u16,
    /// Top-level usage.
    pub usage: u16,
    /// USB serial number text.
    pub serial: String,
    /// USB interface number (-1 if unknown).
    pub interface: i32,
    /// OS path to open.
    pub path: String,
}

/// The interface to open: first USB ID (in connect order) with an app interface, never a
/// keyboard/FIDO/debug-only one.
pub fn select(candidates: &[Candidate]) -> Option<&Candidate> {
    USB_IDS.iter().find_map(|&(vid, pid)| {
        let matches: Vec<&Candidate> = candidates
            .iter()
            .filter(|c| c.vid == vid && c.pid == pid)
            .collect();
        if pid == BOOTLOADER_PRODUCT_ID {
            return matches.first().copied();
        }
        let raw = matches.iter().find(|c| c.usage_page == BETA8_USAGE_PAGE);
        raw.or_else(|| {
            matches
                .iter()
                .find(|c| c.serial != BETA8_SERIAL && !is_non_app(c, &matches))
        })
        .copied()
    })
}

/// True if every known usage page on `c`'s interface (same path) is a non-app one.
fn is_non_app(c: &Candidate, all: &[&Candidate]) -> bool {
    let mut pages = all
        .iter()
        .filter(|o| o.path == c.path && o.usage_page != 0)
        .map(|o| o.usage_page)
        .peekable();
    pages.peek().is_some() && pages.all(|p| NON_APP_USAGE_PAGES.contains(&p))
}

#[cfg(test)]
mod tests {
    //! Selection over fake enumeration lists.

    use super::*;

    /// A candidate with the given ids, usage page, serial and path.
    fn cand(vid: u16, pid: u16, page: u16, serial: &str, path: &str) -> Candidate {
        Candidate {
            vid,
            pid,
            usage_page: page,
            usage: 1,
            serial: serial.into(),
            interface: 0,
            path: path.into(),
        }
    }

    /// Classic before Beta 8: one interface, its own serial, no special usage page.
    #[test]
    fn classic_pre_beta8_takes_its_only_interface() {
        let list = [cand(0x16C0, 0x0486, 0xFF00, "4521230", "a")];
        assert_eq!(select(&list).unwrap().path, "a");
    }

    /// Beta 8+: keyboard, FIDO, raw and debug interfaces share serial 1000000000; raw wins.
    #[test]
    fn beta8_prefers_raw_usage_page() {
        let list = [
            cand(0x1D50, 0x60FC, 0x01, BETA8_SERIAL, "kbd"),
            cand(0x1D50, 0x60FC, 0xF1D0, BETA8_SERIAL, "fido"),
            cand(0x1D50, 0x60FC, 0xFFAB, BETA8_SERIAL, "raw"),
            cand(0x1D50, 0x60FC, 0xFFC9, BETA8_SERIAL, "dbg"),
        ];
        assert_eq!(select(&list).unwrap().path, "raw");
    }

    /// DUO PIDs come before the shared 60FC one.
    #[test]
    fn duo_pid_wins_over_shared_pid() {
        let list = [
            cand(0x1D50, 0x60FC, 0xFFAB, BETA8_SERIAL, "beta"),
            cand(0x1D50, 0x614C, 0xFFAB, BETA8_SERIAL, "duo"),
        ];
        assert_eq!(select(&list).unwrap().path, "duo");
    }

    /// Bootloader: first match, whatever it looks like.
    #[test]
    fn bootloader_takes_first_match() {
        let list = [
            cand(0x0000, 0xB001, 0x01, "", "boot0"),
            cand(0x0000, 0xB001, 0xFFAB, "", "boot1"),
        ];
        assert_eq!(select(&list).unwrap().path, "boot0");
    }

    /// Only the keyboard (and other non-app interfaces) enumerated yet: open nothing.
    #[test]
    fn keyboard_only_opens_nothing() {
        let list = [
            cand(0x1D50, 0x60FC, 0x01, "4521230", "kbd"),
            cand(0x1D50, 0x60FC, 0xF1D0, "4521230", "fido"),
        ];
        assert_eq!(select(&list), None);
    }

    /// A keyboard collection sharing a path with an app collection keeps that path eligible.
    #[test]
    fn mixed_path_is_not_non_app() {
        let list = [
            cand(0x16C0, 0x0486, 0x01, "4521230", "a"),
            cand(0x16C0, 0x0486, 0xFF00, "4521230", "a"),
        ];
        assert_eq!(select(&list).unwrap().path, "a");
    }

    /// Beta 8 serial without the raw page is never opened; unknown vendors are ignored.
    #[test]
    fn beta8_serial_without_raw_and_foreign_ids_open_nothing() {
        let list = [
            cand(0x1D50, 0x60FC, 0xFF00, BETA8_SERIAL, "x"),
            cand(0x046D, 0xC52B, 0xFFAB, "1", "logitech"),
        ];
        assert_eq!(select(&list), None);
    }
}
