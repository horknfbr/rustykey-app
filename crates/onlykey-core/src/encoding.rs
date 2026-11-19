//! base32 to bytes, hex to/from modhex, Latin-1 check.

use std::fmt;

/// Why a text-to-bytes conversion failed; `Display` is the original app's wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    /// A character outside the RFC 4648 base32 alphabet (`base32.ts`).
    InvalidBase32,
    /// A character outside the hex (or modhex, when reversing) alphabet (`utils.ts` hexToModhex).
    InvalidModhex,
    /// Odd length or a non-hex character (`utils.ts` hexStringToByteArray).
    InvalidHex,
}

impl fmt::Display for EncodingError {
    /// Writes the message the TS app throws for this error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBase32 => "Invalid Base32 character in TOTP secret.",
            Self::InvalidModhex => "Invalid character sent for hexToModhex conversion",
            Self::InvalidHex => "Invalid hex string.",
        })
    }
}

impl std::error::Error for EncodingError {}

/// Lowercase hex digits, in modhex-table order.
const HEX: &str = "0123456789abcdef";
/// Yubico modhex digits; index i stands for hex digit i.
const MODHEX: &str = "cbdefghijklnrtuv";

/// Decodes a base32 TOTP secret to lowercase hex, one digit per full 4 bits (may be odd length).
///
/// Strips all whitespace and trailing `=`, accepts either case, and rejects anything else (`base32.ts`).
pub fn base32_to_hex(base32: &str) -> Result<String, EncodingError> {
    let cleaned: String = base32.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.trim_end_matches('=');
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut hex = String::new();
    for c in cleaned.chars() {
        let val = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .find(c.to_ascii_uppercase())
            .ok_or(EncodingError::InvalidBase32)?;
        acc = (acc << 5) | val as u32;
        bits += 5;
        while bits >= 4 {
            bits -= 4;
            hex.push(char::from(HEX.as_bytes()[((acc >> bits) & 0xF) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    Ok(hex)
}

/// Decodes a base32 TOTP secret to bytes; a trailing half byte is dropped (`slotConfigService.ts:96`).
pub fn base32_to_bytes(base32: &str) -> Result<Vec<u8>, EncodingError> {
    let hex = base32_to_hex(base32)?;
    let even = &hex[..hex.len() - hex.len() % 2];
    hex_to_bytes(even)
}

/// Converts hex to Yubico modhex, or modhex back to hex when `reverse` is true (lowercase only).
pub fn hex_to_modhex(input: &str, reverse: bool) -> Result<String, EncodingError> {
    let (from, to) = if reverse {
        (MODHEX, HEX)
    } else {
        (HEX, MODHEX)
    };
    input
        .chars()
        .map(|c| {
            from.find(c)
                .map(|i| char::from(to.as_bytes()[i]))
                .ok_or(EncodingError::InvalidModhex)
        })
        .collect()
}

/// Uppercase hex of a byte slice (`utils.ts` arrayToHexString).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Parses a hex string (surrounding whitespace ignored, either case) to bytes; odd length or non-hex fails.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, EncodingError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(EncodingError::InvalidHex);
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| EncodingError::InvalidHex))
        .collect()
}

/// True when every character fits in one byte (U+0000–U+00FF), which is all a slot can store.
pub fn is_latin1(text: &str) -> bool {
    text.chars().all(|c| u32::from(c) <= 0xFF)
}

/// One byte per character for slot text; `None` when any character is above U+00FF.
pub fn latin1_bytes(text: &str) -> Option<Vec<u8>> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    //! Ports of `base32.test.ts`, `utils.test.ts` and `slotTextLatin1.test.ts`.

    use super::*;

    /// base32: RFC 4648 "Hello!" secret decodes.
    #[test]
    fn base32_decodes_the_rfc_4648_hello_secret() {
        assert_eq!(
            base32_to_hex("JBSWY3DPEHPK3PXP").unwrap(),
            "48656c6c6f21deadbeef"
        );
    }

    /// base32: whitespace, trailing padding and lowercase are accepted.
    #[test]
    fn base32_ignores_whitespace_and_trailing_padding() {
        let want = base32_to_hex("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(base32_to_hex("JBSW Y3DP EHPK 3PXP====").unwrap(), want);
        assert_eq!(base32_to_hex("jbswy3dpehpk3pxp").unwrap(), want);
    }

    /// base32: invalid characters (incl. interior `=`) are rejected, not skipped.
    #[test]
    fn base32_rejects_invalid_base32_characters_instead_of_skipping_them() {
        for bad in [
            "JBSWY3DPEHPK3PXP1",
            "JBSWY3DPEHPK3PXP8",
            "JBSWY3DPEHPK3PXP0",
            "JBSW=Y3DP",
        ] {
            assert_eq!(base32_to_hex(bad), Err(EncodingError::InvalidBase32));
        }
        assert_eq!(
            EncodingError::InvalidBase32.to_string(),
            "Invalid Base32 character in TOTP secret."
        );
    }

    /// base32: empty or padding-only input decodes to nothing.
    #[test]
    fn base32_returns_an_empty_string_for_empty_or_padding_only_input() {
        assert_eq!(base32_to_hex("").unwrap(), "");
        assert_eq!(base32_to_hex("====").unwrap(), "");
    }

    /// Extra: odd hex digit count is kept in hex and dropped in bytes (one char = 5 bits = 1 digit).
    #[test]
    fn base32_to_bytes_drops_a_trailing_half_byte() {
        assert_eq!(base32_to_hex("J").unwrap(), "4");
        assert_eq!(base32_to_bytes("J").unwrap(), Vec::<u8>::new());
        assert_eq!(
            base32_to_bytes("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
    }

    /// utils: hex to modhex and back.
    #[test]
    fn utils_converts_hex_to_modhex_and_back() {
        assert_eq!(
            hex_to_modhex("0123456789abcdef", false).unwrap(),
            "cbdefghijklnrtuv"
        );
        assert_eq!(
            hex_to_modhex("cbdefghijklnrtuv", true).unwrap(),
            "0123456789abcdef"
        );
    }

    /// utils: invalid modhex input is rejected.
    #[test]
    fn utils_rejects_invalid_hex_to_modhex_characters() {
        assert_eq!(
            hex_to_modhex("zz", false),
            Err(EncodingError::InvalidModhex)
        );
        assert!(
            EncodingError::InvalidModhex
                .to_string()
                .contains("Invalid character")
        );
    }

    /// utils: byte arrays and hex strings round-trip.
    #[test]
    fn utils_round_trips_byte_arrays_and_hex_strings() {
        assert_eq!(bytes_to_hex(&[0, 15, 255]), "000FFF");
        assert_eq!(hex_to_bytes("000fff").unwrap(), vec![0, 15, 255]);
    }

    /// utils: non-hex and odd-length strings are rejected.
    #[test]
    fn utils_rejects_invalid_hex_strings() {
        assert_eq!(hex_to_bytes("gg"), Err(EncodingError::InvalidHex));
        assert_eq!(hex_to_bytes("abc"), Err(EncodingError::InvalidHex));
        assert!(
            EncodingError::InvalidHex
                .to_string()
                .contains("Invalid hex")
        );
    }

    /// slotTextLatin1: ASCII and the whole Latin-1 range are accepted.
    #[test]
    fn first_non_latin1_index_accepts_ascii_and_the_whole_latin_1_range() {
        assert!(is_latin1(""));
        assert!(is_latin1("Password1!"));
        assert!(is_latin1("Grüße àéîõü ß ÿ"));
        assert!(is_latin1("\u{ff}"));
    }

    /// slotTextLatin1: anything above U+00FF is caught.
    #[test]
    fn first_non_latin1_index_finds_the_first_character_above_u_00ff() {
        for bad in ["\u{100}", "price 5€", "ab\u{1F600}", "Œuvre"] {
            assert!(!is_latin1(bad));
            assert_eq!(latin1_bytes(bad), None);
        }
    }

    /// slotTextLatin1: Latin-1 text is sent one byte per character.
    #[test]
    fn set_slot_sends_latin_1_text_one_byte_per_character() {
        assert_eq!(
            latin1_bytes("pässwörd").unwrap(),
            vec![0x70, 0xe4, 0x73, 0x73, 0x77, 0xf6, 0x72, 0x64]
        );
    }
}
