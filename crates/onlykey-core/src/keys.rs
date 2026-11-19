//! OpenPGP + SSH/PEM parsing, key type byte, bundle candidates, Auto Load rules.
//!
//! Ports `keyMaterial.ts`, `keyParser.ts`, `keySlots.ts`, `services/keyImport/*`, `keyService.ts`
//! and the key validation in `Setup.tsx` / `Advanced.tsx`. Every entry point returns the
//! `Command`s to send; nothing here talks to the device.

mod openpgp;
mod ssh;
#[cfg(test)]
mod tests;

use crate::api::Command;
use crate::encoding::hex_to_bytes;
use crate::protocol::{BACKUP_KEY_SLOT, BACKUP_KEY_TYPE, ECC_SLOTS, FieldId};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

/// Slot dropdown value meaning "Auto Load" (pick slots from the key bundle).
pub const AUTO_LOAD_SLOT: u8 = 99;
/// Type modifier: key is the backup key.
pub const KEY_TYPE_BACKUP: u8 = 128;
/// Type modifier: key is the signature key.
pub const KEY_TYPE_SIGNATURE: u8 = 64;
/// Type modifier: key is the decryption key.
pub const KEY_TYPE_DECRYPTION: u8 = 32;
/// Advanced raw-key type for HMAC-SHA1 (slots 129/130, 20-byte key).
pub const HMAC_SHA1_TYPE: u8 = 9;

/// RSA keys go in slots 1–4; ECC keys in 101–110.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// RSA (device bytes are p ‖ q).
    Rsa,
    /// ECC (device bytes are a 32-byte scalar).
    Ecc,
}

/// One private key found in the input (primary key or a subkey), ready to send.
pub struct KeyCandidate {
    /// "Primary Key" or "Subkey N" (TS names).
    pub name: String,
    /// Source algorithm name, for display (e.g. "RSA", "ECDH", "Ed25519").
    pub algorithm: String,
    /// RSA or ECC; drives slot choice.
    pub kind: KeyKind,
    /// The algorithm can sign.
    pub can_sign: bool,
    /// The algorithm can encrypt/decrypt.
    pub can_encrypt: bool,
    /// Device bytes: RSA p ‖ q, ECC 32-byte scalar.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Type byte before modifiers: RSA 1–4 (size), ECC 1 (25519) / 2 (P-256) / 3 (secp256k1).
    pub base_type: u8,
}

impl KeyCandidate {
    /// Builds a candidate with an empty name (the parser fills it in).
    fn new(
        material: Material,
        algorithm: impl Into<String>,
        can_sign: bool,
        can_encrypt: bool,
    ) -> Self {
        Self {
            name: String::new(),
            algorithm: algorithm.into(),
            kind: material.kind,
            can_sign,
            can_encrypt,
            bytes: material.bytes,
            base_type: material.base_type,
        }
    }

    /// The non-secret description shown in the select dialog.
    fn summary(&self, index: usize) -> CandidateSummary {
        CandidateSummary {
            index,
            name: self.name.clone(),
            algorithm: self.algorithm.clone(),
            kind: self.kind,
            base_type: self.base_type,
            len: self.bytes.len(),
        }
    }
}

/// What the select dialog shows for one candidate ("type N · M bytes"); no key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSummary {
    /// Index to pass back to [`import_selected`].
    pub index: usize,
    /// "Primary Key" or "Subkey N".
    pub name: String,
    /// Source algorithm name.
    pub algorithm: String,
    /// RSA or ECC (the dialog defaults the slot to RSA 1 / ECC 101 from this).
    pub kind: KeyKind,
    /// Type byte before modifiers.
    pub base_type: u8,
    /// Key byte length.
    pub len: usize,
}

/// Why a key could not be turned into commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// Explicit slot but several keys found: show the select dialog, then call [`import_selected`].
    SelectionRequired(Vec<CandidateSummary>),
    /// Anything else; the message is the original app's wording.
    Invalid(String),
}

impl fmt::Display for ImportError {
    /// Writes the TS error message (`KEY_SELECTION_REQUIRED` for the selection case).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionRequired(_) => f.write_str("KEY_SELECTION_REQUIRED"),
            Self::Invalid(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ImportError {}

/// Shorthand for an [`ImportError::Invalid`] with the given message.
fn invalid(msg: impl Into<String>) -> ImportError {
    ImportError::Invalid(msg.into())
}

/// Kind, base type and device bytes of one key (`OnlyKeyKeyMaterial`).
struct Material {
    /// RSA or ECC.
    kind: KeyKind,
    /// Type byte before modifiers.
    base_type: u8,
    /// Device bytes.
    bytes: Zeroizing<Vec<u8>>,
}

/// Drops leading zero bytes, keeping at least one byte.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[first..]
}

/// Left-pads a fixed-width scalar that an encoder shortened (big-endian) back to 32 bytes.
fn left_pad32(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; 32usize.saturating_sub(bytes.len())]);
    out.extend_from_slice(bytes);
    out
}

/// RSA type byte from the stripped prime p: 1=1024, 2=2048, 3=3072, 4=4096 bits (`rsaTypeFromPrime`).
pub fn rsa_type_from_prime(p: &[u8]) -> Result<u8, ImportError> {
    match p.len() {
        64 => Ok(1),
        128 => Ok(2),
        192 => Ok(3),
        256 => Ok(4),
        _ => Err(invalid(
            "Selected key length should be 1024, 2048, 3072, or 4096 bits.",
        )),
    }
}

/// 32-byte ECC scalar; longer input loses leading zeros, other lengths fail (`eccScalar32`).
pub fn ecc_scalar32(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let s = if raw.len() > 32 {
        strip_leading_zeros(raw)
    } else {
        raw
    };
    if s.len() != 32 {
        return Err(invalid("Selected key length should be 32 bytes."));
    }
    Ok(Zeroizing::new(s.to_vec()))
}

/// RSA material: p ‖ q with leading zeros stripped, type from p.
fn rsa_material(p: &[u8], q: &[u8]) -> Result<Material, ImportError> {
    let (p, q) = (strip_leading_zeros(p), strip_leading_zeros(q));
    let base_type = rsa_type_from_prime(p)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(p.len() + q.len()));
    bytes.extend_from_slice(p);
    bytes.extend_from_slice(q);
    Ok(Material {
        kind: KeyKind::Rsa,
        base_type,
        bytes,
    })
}

/// ECC material: the given curve type and a 32-byte scalar.
fn ecc_material(base_type: u8, scalar: &[u8]) -> Result<Material, ImportError> {
    Ok(Material {
        kind: KeyKind::Ecc,
        base_type,
        bytes: ecc_scalar32(scalar)?,
    })
}

/// Error for curves the device does not take (`eccTypeFromAlgorithm`).
fn unsupported_ecc() -> ImportError {
    invalid("Unsupported ECC key type, key is not X25519, NIST256p1, or secp256k1.")
}

/// Every private key in the text: OpenPGP ("-----BEGIN PGP", passphrase required) gives the
/// primary key then each subkey; any other "-----" text is one SSH/PEM key (`parseKeyBundle`).
pub fn parse_candidates(text: &str, passphrase: &str) -> Result<Vec<KeyCandidate>, ImportError> {
    let text = text.trim();
    if text.contains("-----BEGIN PGP") {
        openpgp::parse(text, passphrase)
    } else if text.contains("-----") {
        let mut key = ssh::parse(text, passphrase)?;
        key.name = "Primary Key".into();
        Ok(vec![key])
    } else {
        Err(invalid(
            "Unsupported key format. Use PEM OpenPGP or SSH private keys.",
        ))
    }
}

/// Combines the base type with Backup/Signature/Decryption flags; Auto Load tags RSA slot 1
/// decryption and slot 2 signature, and strips backup on slots 2 and 102 (`applyPrivateKeyTypeModifiers`).
pub fn apply_type_modifiers(
    base_type: u8,
    slot: u8,
    kind: KeyKind,
    set_as_backup: bool,
    set_as_signature: bool,
    set_as_decryption: bool,
    auto_load: bool,
) -> u8 {
    let mut t = base_type;
    if set_as_decryption {
        t |= KEY_TYPE_DECRYPTION;
    }
    if set_as_signature {
        t |= KEY_TYPE_SIGNATURE;
    }
    if set_as_backup {
        t |= KEY_TYPE_BACKUP;
    }
    if auto_load {
        if kind == KeyKind::Rsa && slot == 1 {
            t |= KEY_TYPE_DECRYPTION;
        }
        if kind == KeyKind::Rsa && slot == 2 {
            t |= KEY_TYPE_SIGNATURE;
        }
        if slot == 2 || slot == 102 {
            t &= !KEY_TYPE_BACKUP;
        }
    }
    t
}

/// Auto Load slots as (candidate index, slot): one key → RSA 2 / ECC 101; two or more →
/// signing = candidate 2 if present else 0 → slot 2 (102), decryption = candidate 1 → slot 1 (101).
/// ECC slots are used when either chosen key is ECC (`buildAutoAssignments`).
fn auto_assignments(candidates: &[KeyCandidate]) -> Vec<(usize, u8)> {
    if candidates.len() < 2 {
        let slot = if candidates[0].kind == KeyKind::Rsa {
            2
        } else {
            ECC_SLOTS[0]
        };
        return vec![(0, slot)];
    }
    let signing = if candidates.len() > 2 { 2 } else { 0 };
    let ecc = candidates[signing].kind == KeyKind::Ecc || candidates[1].kind == KeyKind::Ecc;
    let (sign_slot, decrypt_slot) = if ecc {
        (ECC_SLOTS[1], ECC_SLOTS[0])
    } else {
        (2, 1)
    };
    vec![(signing, sign_slot), (1, decrypt_slot)]
}

/// One `SetPrivateKey` per assignment with the type modifiers applied; Auto Load also tags ECC
/// slot 102 signature and 101 decryption (`importPemKey`).
fn set_key_commands(
    candidates: &[KeyCandidate],
    assignments: &[(usize, u8)],
    auto_load: bool,
    set_as_backup: bool,
    set_as_signature: bool,
) -> Vec<Command> {
    assignments
        .iter()
        .map(|&(i, slot)| {
            let key = &candidates[i];
            let ecc = key.kind == KeyKind::Ecc;
            let key_type = apply_type_modifiers(
                key.base_type,
                slot,
                key.kind,
                set_as_backup,
                set_as_signature || (auto_load && ecc && slot == ECC_SLOTS[1]),
                auto_load && ecc && slot == ECC_SLOTS[0],
                auto_load,
            );
            Command::SetPrivateKey {
                slot,
                key_type,
                bytes: key.bytes.to_vec(),
            }
        })
        .collect()
}

/// Keys tab "Save to OnlyKey": parses the key and returns the writes for `slot_choice`
/// (99 = Auto Load). An explicit slot with several keys fails with
/// [`ImportError::SelectionRequired`]; then call [`import_selected`].
pub fn import_key(
    text: &str,
    passphrase: &str,
    slot_choice: u8,
    set_as_backup: bool,
    set_as_signature: bool,
) -> Result<Vec<Command>, ImportError> {
    let candidates = parse_candidates(text, passphrase)?;
    let auto_load = slot_choice == AUTO_LOAD_SLOT;
    let assignments = if auto_load {
        auto_assignments(&candidates)
    } else if candidates.len() < 2 {
        vec![(0, slot_choice)]
    } else {
        let summaries = candidates
            .iter()
            .enumerate()
            .map(|(i, c)| c.summary(i))
            .collect();
        return Err(ImportError::SelectionRequired(summaries));
    };
    Ok(set_key_commands(
        &candidates,
        &assignments,
        auto_load,
        set_as_backup,
        set_as_signature,
    ))
}

/// Select dialog "Load Key": writes candidate `index` to `slot` (no Auto Load tagging).
pub fn import_selected(
    text: &str,
    passphrase: &str,
    index: usize,
    slot: u8,
    set_as_backup: bool,
    set_as_signature: bool,
) -> Result<Vec<Command>, ImportError> {
    let candidates = parse_candidates(text, passphrase)?;
    if index >= candidates.len() {
        return Err(invalid("Selected key not found."));
    }
    Ok(set_key_commands(
        &candidates,
        &[(index, slot)],
        false,
        set_as_backup,
        set_as_signature,
    ))
}

/// Keys tab "Wipe from OnlyKey": Auto Load (99) wipes RSA slot 1 (`wipeKeyInSlot`).
pub fn wipe_key(slot_choice: u8) -> Vec<Command> {
    let slot = if slot_choice == AUTO_LOAD_SLOT {
        1
    } else {
        slot_choice
    };
    vec![Command::WipePrivateKey { slot }]
}

/// Setup backup passphrase checks, in the TS order: non-empty, matches confirm, ≥ 25 characters
/// (UTF-16 units, like JS `length`).
pub fn validate_backup_passphrase(passphrase: &str, confirm: &str) -> Result<(), ImportError> {
    if passphrase.is_empty() {
        return Err(invalid("Passphrase cannot be empty."));
    }
    if passphrase != confirm {
        return Err(invalid("Passphrase fields do not match."));
    }
    if passphrase.encode_utf16().count() < 25 {
        return Err(invalid("Passphrase must be at least 25 characters."));
    }
    Ok(())
}

/// Backup passphrase key: SHA-256 of the UTF-8 passphrase into slot 131, type 161
/// (`setBackupPassphrase`). Validate first with [`validate_backup_passphrase`].
pub fn backup_passphrase_commands(passphrase: &str) -> Vec<Command> {
    vec![Command::SetPrivateKey {
        slot: BACKUP_KEY_SLOT,
        key_type: BACKUP_KEY_TYPE,
        bytes: Sha256::digest(passphrase.as_bytes()).to_vec(),
    }]
}

/// Backup key mode write (`setBackupKeyMode`): 0 permits future backup key changes, 1 locks it.
pub fn backup_key_mode_command(mode: u8) -> Command {
    Command::SetGlobal {
        field: FieldId::BackupKeyMode as u8,
        value: mode,
    }
}

/// Setup step 9 (OpenPGP key as backup key): imports with "Set as backup key" on, then writes
/// the backup key mode. `selection` is the select dialog's (candidate index, slot) once
/// [`ImportError::SelectionRequired`] has been answered (`importPgpBackupKey`).
pub fn pgp_backup_commands(
    text: &str,
    passphrase: &str,
    slot: u8,
    selection: Option<(usize, u8)>,
    set_as_signature: bool,
    backup_key_mode: u8,
) -> Result<Vec<Command>, ImportError> {
    if text.trim().is_empty() {
        return Err(invalid("OpenPGP private key cannot be empty."));
    }
    if passphrase.is_empty() {
        return Err(invalid("Passcode cannot be empty."));
    }
    let mut commands = match selection {
        Some((index, target)) => {
            import_selected(text, passphrase, index, target, true, set_as_signature)?
        }
        None => import_key(text, passphrase, slot, true, set_as_signature)?,
    };
    commands.push(backup_key_mode_command(backup_key_mode));
    Ok(commands)
}

/// Advanced "Add Private Key" (raw hex): whitespace removed, cut to 64 hex (ECC types 1–3) or
/// 40 hex (HMAC type 9), modifiers added; slots 101–110, 129 (HMAC 2), 130 (HMAC 1).
pub fn raw_key_commands(
    key_type: u8,
    slot: u8,
    hex: &str,
    set_as_backup: bool,
    set_as_signature: bool,
    set_as_decryption: bool,
) -> Result<Vec<Command>, ImportError> {
    let (label, len) = if key_type == HMAC_SHA1_TYPE {
        ("HMAC", 40)
    } else {
        ("ECC", 64)
    };
    let key: Zeroizing<String> = Zeroizing::new(
        hex.chars()
            .filter(|c| !c.is_whitespace())
            .take(len)
            .collect(),
    );
    if key.chars().count() != len {
        return Err(invalid(format!(
            "{label} key must be {len} hex characters."
        )));
    }
    let bytes = hex_to_bytes(&key).map_err(|e| invalid(e.to_string()))?;
    let key_type = apply_type_modifiers(
        key_type,
        slot,
        KeyKind::Ecc,
        set_as_backup,
        set_as_signature,
        set_as_decryption,
        false,
    );
    Ok(vec![Command::SetPrivateKey {
        slot,
        key_type,
        bytes,
    }])
}
