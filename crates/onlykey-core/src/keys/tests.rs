//! Ports of `keyMaterial.test.ts`, `keyParser.test.ts`, `keyBundleParser.test.ts`,
//! `keyImportService.test.ts`, `keyService.test.ts` and the key parts of `Advanced.ui.test.tsx` /
//! `Setup.ui.test.tsx`, plus fixture tests against bytes taken from openssl/gpg exports
//! (`tests/fixtures/keys/expected.py`).

use super::*;
use crate::api::Command;

/// Test passphrase for every encrypted fixture.
const PASS: &str = "test-passphrase";

/// Reads a fixture file from `tests/fixtures/keys/`.
fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/keys/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Expected (base type, hex bytes) per candidate for a fixture.
fn expected(name: &str) -> Vec<(u8, String)> {
    fixture(&format!("{name}.expected"))
        .lines()
        .map(|l| {
            let (t, hex) = l.split_once(' ').unwrap();
            (t.parse().unwrap(), hex.to_uppercase())
        })
        .collect()
}

/// Parses a fixture and checks every candidate's type and bytes against its `.expected` file.
fn assert_fixture(name: &str, passphrase: &str, kinds: &[KeyKind]) {
    let got =
        parse_candidates(&fixture(name), passphrase).unwrap_or_else(|e| panic!("{name}: {e}"));
    let want = expected(name);
    assert_eq!(got.len(), want.len(), "{name}: candidate count");
    for (i, (c, (t, hex))) in got.iter().zip(&want).enumerate() {
        assert_eq!(c.base_type, *t, "{name}[{i}] type");
        assert_eq!(
            crate::encoding::bytes_to_hex(&c.bytes),
            *hex,
            "{name}[{i}] bytes"
        );
        assert_eq!(c.kind, kinds[i], "{name}[{i}] kind");
    }
}

/// Error message for a failed parse.
fn parse_err(text: &str, passphrase: &str) -> String {
    match parse_candidates(text, passphrase) {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.to_string(),
    }
}

/// Synthetic candidate for rule tests.
fn cand(kind: KeyKind, base_type: u8, bytes: &[u8]) -> KeyCandidate {
    KeyCandidate {
        name: String::new(),
        algorithm: String::new(),
        kind,
        can_sign: true,
        can_encrypt: true,
        bytes: Zeroizing::new(bytes.to_vec()),
        base_type,
    }
}

/// (slot, type, bytes) of each SetPrivateKey command.
fn writes(cmds: &[Command]) -> Vec<(u8, u8, Vec<u8>)> {
    cmds.iter()
        .map(|c| match c {
            Command::SetPrivateKey {
                slot,
                key_type,
                bytes,
            } => (*slot, *key_type, bytes.clone()),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

use KeyKind::{Ecc, Rsa};

// ---- keyMaterial.test.ts ----

/// rsaTypeFromPrime: p length maps to firmware RSA type 1–4.
#[test]
fn keys_rsa_type_from_prime_maps_p_length_to_type() {
    assert_eq!(rsa_type_from_prime(&[1; 64]), Ok(1));
    assert_eq!(rsa_type_from_prime(&[1; 128]), Ok(2));
    assert_eq!(rsa_type_from_prime(&[1; 192]), Ok(3));
    assert_eq!(rsa_type_from_prime(&[1; 256]), Ok(4));
}

/// rsaTypeFromPrime: other sizes are rejected.
#[test]
fn keys_rsa_type_from_prime_rejects_other_sizes() {
    for len in [20, 129] {
        let err = rsa_type_from_prime(&vec![1; len]).unwrap_err().to_string();
        assert!(err.contains("1024, 2048, 3072, or 4096"), "{err}");
    }
}

/// eccScalar32: 32 bytes pass, a 33-byte MPI loses its leading zero, a scalar starting with 0 stays.
#[test]
fn keys_ecc_scalar32_accepts_and_strips() {
    let s = [7u8; 32];
    assert_eq!(*ecc_scalar32(&s).unwrap(), s.to_vec());
    let mut mpi = vec![0u8];
    mpi.extend_from_slice(&s);
    assert_eq!(*ecc_scalar32(&mpi).unwrap(), s.to_vec());
    let mut zero_start = vec![0u8];
    zero_start.extend_from_slice(&[7; 31]);
    assert_eq!(*ecc_scalar32(&zero_start).unwrap(), zero_start);
}

/// eccScalar32: non-32-byte scalars fail.
#[test]
fn keys_ecc_scalar32_rejects_wrong_length() {
    assert!(
        ecc_scalar32(&[1; 31])
            .unwrap_err()
            .to_string()
            .contains("32 bytes")
    );
}

/// applyPrivateKeyTypeModifiers: ORs backup/signature/decryption.
#[test]
fn keys_modifiers_or_flags() {
    assert_eq!(
        apply_type_modifiers(2, 101, Ecc, true, true, false, false),
        2 | KEY_TYPE_BACKUP | KEY_TYPE_SIGNATURE
    );
}

/// applyPrivateKeyTypeModifiers: Auto Load tags RSA 1/2 purpose and strips signature-slot backup.
#[test]
fn keys_modifiers_auto_load_rules() {
    assert_eq!(
        apply_type_modifiers(2, 1, Rsa, true, false, false, false),
        2 | KEY_TYPE_BACKUP
    );
    assert_eq!(
        apply_type_modifiers(2, 2, Rsa, true, false, false, false),
        2 | KEY_TYPE_BACKUP
    );
    assert_eq!(
        apply_type_modifiers(2, 1, Rsa, true, false, false, true),
        2 | KEY_TYPE_DECRYPTION | KEY_TYPE_BACKUP
    );
    assert_eq!(
        apply_type_modifiers(2, 2, Rsa, true, false, false, true),
        2 | KEY_TYPE_SIGNATURE
    );
    assert_eq!(
        apply_type_modifiers(1, 102, Ecc, true, false, false, true),
        1
    );
}

/// materialFromOpenPgpPacket: RSA 2048 primary + subkeys give p ‖ q, type 2 (not the packet blob).
#[test]
fn keys_openpgp_rsa2048_p_q() {
    assert_fixture("pgp-rsa2048.asc", PASS, &[Rsa, Rsa, Rsa]);
}

/// materialFromOpenPgpPacket: RSA 4096 gives type 4, 512 bytes.
#[test]
fn keys_openpgp_rsa4096_p_q() {
    assert_fixture("pgp-rsa4096.asc", PASS, &[Rsa, Rsa]);
}

/// materialFromOpenPgpPacket: ed25519 seed and cv25519 d (MPI byte order, as openpgp.js) are type 1.
#[test]
fn keys_openpgp_ed25519_cv25519() {
    assert_fixture("pgp-ed25519.asc", PASS, &[Ecc, Ecc]);
}

/// ECC curve selection: OpenPGP NIST P-256 ECDSA + ECDH are type 2.
#[test]
fn keys_openpgp_p256() {
    assert_fixture("pgp-p256.asc", PASS, &[Ecc, Ecc]);
}

/// ECC curve selection: OpenPGP secp256k1 ECDSA is type 3.
#[test]
fn keys_openpgp_secp256k1() {
    assert_fixture("pgp-secp256k1-sign.asc", PASS, &[Ecc, Ecc]);
}

/// Known gap: rpgp 0.21 refuses a whole key that has a secp256k1 ECDH subkey (openpgp.js read it).
#[test]
fn keys_openpgp_secp256k1_ecdh_unsupported_by_rpgp() {
    let err = parse_err(&fixture("pgp-secp256k1-ecdh.asc"), PASS);
    assert!(err.starts_with("Could not read OpenPGP key:"), "{err}");
}

/// ECC curve selection: brainpool is not a device curve.
#[test]
fn keys_openpgp_brainpool_unsupported() {
    let err = parse_err(&fixture("pgp-brainpool.asc"), PASS);
    assert!(err.contains("X25519, NIST256p1, or secp256k1"), "{err}");
}

/// materialFromOpenPgpPacket: DSA has no seed/d/k, so its parameters are unreadable.
#[test]
fn keys_openpgp_dsa_unreadable() {
    assert_eq!(
        parse_err(&fixture("pgp-dsa.asc"), PASS),
        "Could not read key parameters from OpenPGP key."
    );
}

/// materialFromSshKey: OpenSSH RSA gives p ‖ q.
#[test]
fn keys_ssh_rsa_p_q() {
    assert_fixture("ssh-rsa2048", PASS, &[Rsa]);
}

/// materialFromSshKey: OpenSSH ed25519 gives the 32-byte seed `k`, encrypted or not.
#[test]
fn keys_ssh_ed25519_k() {
    assert_fixture("ssh-ed25519", PASS, &[Ecc]);
    assert_fixture("ssh-ed25519-plain", "", &[Ecc]);
}

/// materialFromSshKey: nistp256 ECDSA is type 2.
#[test]
fn keys_ssh_p256_type_2() {
    assert_fixture("ssh-p256", PASS, &[Ecc]);
}

/// materialFromSshKey: nistp384 matches "nist" (type 2) and then fails the 32-byte check, as in TS.
#[test]
fn keys_ssh_p384_wrong_length() {
    assert_eq!(
        parse_err(&fixture("ssh-p384"), ""),
        "Selected key length should be 32 bytes."
    );
}

/// materialFromSshKey: an unknown curve (brainpool) fails.
#[test]
fn keys_pem_brainpool_unsupported() {
    let err = parse_err(&fixture("pem-sec1-brainpool.pem"), "");
    assert!(err.contains("X25519, NIST256p1, or secp256k1"), "{err}");
}

/// materialFromSshKey: an unsupported type (DSA) fails.
#[test]
fn keys_pem_dsa_unsupported() {
    assert_eq!(
        parse_err(&fixture("pem-dsa.pem"), ""),
        "Unsupported SSH key type."
    );
}

/// Bare PEM: PKCS#1 RSA, plain and legacy `Proc-Type` AES-256-CBC encrypted.
#[test]
fn keys_pem_pkcs1_rsa() {
    assert_fixture("pem-pkcs1-rsa2048.pem", "", &[Rsa]);
    assert_fixture("pem-pkcs1-enc-rsa2048.pem", PASS, &[Rsa]);
}

/// Bare PEM: PBES2-encrypted PKCS#8 RSA 1024 (type 1) and P-256.
#[test]
fn keys_pem_pkcs8_encrypted() {
    assert_fixture("pem-pkcs8-enc-rsa1024.pem", PASS, &[Rsa]);
    assert_fixture("pem-pkcs8-enc-p256.pem", PASS, &[Ecc]);
}

/// Bare PEM: SEC1 P-256 (type 2) and secp256k1 (type 3), PKCS#8 Ed25519 (type 1).
#[test]
fn keys_pem_sec1_and_pkcs8_ed25519() {
    assert_fixture("pem-sec1-p256.pem", "", &[Ecc]);
    assert_fixture("pem-sec1-secp256k1.pem", "", &[Ecc]);
    assert_fixture("pem-pkcs8-ed25519.pem", "", &[Ecc]);
}

/// Wrong passphrases give the openpgp.js / sshpk messages.
#[test]
fn keys_wrong_passphrase_messages() {
    assert_eq!(
        parse_err(&fixture("pgp-ed25519.asc"), "wrong"),
        "Error decrypting private key: Incorrect key passphrase"
    );
    for name in [
        "ssh-ed25519",
        "pem-pkcs1-enc-rsa2048.pem",
        "pem-pkcs8-enc-p256.pem",
    ] {
        assert_eq!(
            parse_err(&fixture(name), "wrong"),
            "Incorrect passphrase supplied, could not decrypt key",
            "{name}"
        );
    }
}

/// Encrypted SSH/PEM keys without a passphrase give sshpk's KeyEncryptedError text.
#[test]
fn keys_missing_passphrase_messages() {
    assert_eq!(
        parse_err(&fixture("ssh-rsa2048"), ""),
        "The OpenSSH format key (unnamed) is encrypted (password-protected), and no passphrase was provided in `options`"
    );
    for name in ["pem-pkcs1-enc-rsa2048.pem", "pem-pkcs8-enc-rsa1024.pem"] {
        assert_eq!(
            parse_err(&fixture(name), ""),
            "The PEM format key (unnamed) is encrypted (password-protected), and no passphrase was provided in `options`",
            "{name}"
        );
    }
}

/// A public key block is not a private key (openpgp.js `readPrivateKey`).
#[test]
fn keys_openpgp_public_block_rejected() {
    assert_eq!(
        parse_err(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----",
            PASS
        ),
        "Armored text not of type private key"
    );
}

/// Candidates are named "Primary Key" then "Subkey N" and carry algorithm capabilities.
#[test]
fn keys_candidate_names_and_capabilities() {
    let c = parse_candidates(&fixture("pgp-ed25519.asc"), PASS).unwrap();
    assert_eq!(c[0].name, "Primary Key");
    assert_eq!(c[1].name, "Subkey 1");
    assert!(c[0].can_sign && !c[0].can_encrypt);
    assert!(!c[1].can_sign && c[1].can_encrypt);
    assert_eq!(
        parse_candidates(&fixture("ssh-p256"), PASS).unwrap()[0].name,
        "Primary Key"
    );
}

// ---- keyParser.test.ts ----

/// hashBackupPassphrase: SHA-256 of the passphrase into slot 131 type 161.
#[test]
fn keys_backup_passphrase_is_sha256() {
    let cmds = writes(&backup_passphrase_commands("secret"));
    assert_eq!(cmds.len(), 1);
    let (slot, key_type, bytes) = &cmds[0];
    assert_eq!((*slot, *key_type), (131, 161));
    assert_eq!(
        crate::encoding::bytes_to_hex(bytes),
        "2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B"
    );
}

/// keyParser / keyBundleParser: OpenPGP keys require a passcode.
#[test]
fn keys_openpgp_requires_passcode() {
    let err = parse_err(&fixture("pgp-rsa2048.asc"), "");
    assert_eq!(err, "Passcode is required for OpenPGP keys.");
}

// ---- keyBundleParser.test.ts ----

/// Rejects text that is neither OpenPGP nor SSH/PEM.
#[test]
fn keys_bundle_rejects_unsupported_formats() {
    assert!(parse_err("not-a-key", "").contains("Unsupported key format"));
}

/// A 2048-bit SSH RSA key to explicit slot 3 is type 2, 256 bytes of p ‖ q.
#[test]
fn keys_bundle_ssh_rsa_explicit_slot() {
    let w = writes(&import_key(&fixture("ssh-rsa2048"), PASS, 3, false, false).unwrap());
    let (t, hex) = &expected("ssh-rsa2048")[0];
    assert_eq!(w.len(), 1);
    assert_eq!((w[0].0, w[0].1, w[0].2.len()), (3, 2, 256));
    assert_eq!(
        (*t, crate::encoding::bytes_to_hex(&w[0].2)),
        (2, hex.clone())
    );
}

/// Auto Load puts a single ECC SSH key on ECC slot 101 (type 2, +decryption via importPemKey).
#[test]
fn keys_bundle_single_ecc_auto_loads_to_101() {
    let w = writes(&import_key(&fixture("ssh-p256"), PASS, AUTO_LOAD_SLOT, false, false).unwrap());
    assert_eq!(w.len(), 1);
    assert_eq!((w[0].0, w[0].1), (101, 2 | KEY_TYPE_DECRYPTION));
}

/// Auto Load puts a single RSA key on slot 2 with the signature flag.
#[test]
fn keys_bundle_single_rsa_auto_loads_to_2() {
    let w = writes(
        &import_key(
            &fixture("pem-pkcs1-rsa2048.pem"),
            "",
            AUTO_LOAD_SLOT,
            true,
            false,
        )
        .unwrap(),
    );
    assert_eq!((w[0].0, w[0].1), (2, 2 | KEY_TYPE_SIGNATURE));
}

/// An explicit slot with several OpenPGP keys needs a selection.
#[test]
fn keys_bundle_explicit_slot_requires_selection() {
    match import_key(&fixture("pgp-rsa2048.asc"), PASS, 2, false, false) {
        Err(ImportError::SelectionRequired(s)) => {
            assert_eq!(s.len(), 3);
            assert_eq!(s[0].base_type, 2);
            assert_eq!(s[0].name, "Primary Key");
            assert_eq!(s[2].name, "Subkey 2");
            assert_eq!((s[1].index, s[1].kind, s[1].len), (1, Rsa, 256));
        }
        other => panic!("expected SelectionRequired, got {:?}", other.map(|_| ())),
    }
    assert_eq!(
        ImportError::SelectionRequired(vec![]).to_string(),
        "KEY_SELECTION_REQUIRED"
    );
}

/// Auto Load of an RSA bundle: signing = candidate 2 → slot 2, decryption = candidate 1 → slot 1.
#[test]
fn keys_bundle_auto_assigns_rsa_sign_and_decrypt() {
    let exp = expected("pgp-rsa2048.asc");
    let w = writes(
        &import_key(
            &fixture("pgp-rsa2048.asc"),
            PASS,
            AUTO_LOAD_SLOT,
            false,
            false,
        )
        .unwrap(),
    );
    assert_eq!(w.iter().map(|x| x.0).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(crate::encoding::bytes_to_hex(&w[0].2), exp[2].1);
    assert_eq!(crate::encoding::bytes_to_hex(&w[1].2), exp[1].1);
    assert_eq!(
        (w[0].1, w[1].1),
        (2 | KEY_TYPE_SIGNATURE, 2 | KEY_TYPE_DECRYPTION)
    );
}

/// Auto Load of an ECC bundle: candidates 0 → 102 and 1 → 101, not RSA 1/2.
#[test]
fn keys_bundle_auto_assigns_ecc_to_102_101() {
    let exp = expected("pgp-ed25519.asc");
    let w = writes(
        &import_key(
            &fixture("pgp-ed25519.asc"),
            PASS,
            AUTO_LOAD_SLOT,
            false,
            false,
        )
        .unwrap(),
    );
    assert_eq!(w.iter().map(|x| x.0).collect::<Vec<_>>(), [102, 101]);
    assert_eq!(crate::encoding::bytes_to_hex(&w[0].2), exp[0].1);
    assert_eq!(crate::encoding::bytes_to_hex(&w[1].2), exp[1].1);
}

/// Two-candidate RSA bundle: signing falls back to candidate 0.
#[test]
fn keys_bundle_two_rsa_signing_is_candidate_0() {
    let c = [cand(Rsa, 4, &[1]), cand(Rsa, 4, &[2])];
    assert_eq!(auto_assignments(&c), [(0, 2), (1, 1)]);
    let mixed = [cand(Rsa, 2, &[1]), cand(Ecc, 1, &[2])];
    assert_eq!(auto_assignments(&mixed), [(0, 102), (1, 101)]);
}

// ---- keyImportService.test.ts ----

/// ORs the backup modifier on an Auto Load RSA slot-1 write (2 | 32 | 128 = 162).
#[test]
fn keys_import_ors_backup_on_auto_rsa_slot1() {
    let c = [cand(Rsa, 2, &[1, 2])];
    assert_eq!(
        writes(&set_key_commands(&c, &[(0, 1)], true, true, false)),
        [(1, 162, vec![1, 2])]
    );
}

/// ORs ECC Auto Load signature/decryption flags onto slots 102 and 101.
#[test]
fn keys_import_ecc_auto_flags() {
    let c = [cand(Ecc, 1, &[1]), cand(Ecc, 1, &[2])];
    assert_eq!(
        writes(&set_key_commands(
            &c,
            &[(0, 102), (1, 101)],
            true,
            false,
            false
        )),
        [(102, 1 | 64, vec![1]), (101, 1 | 32, vec![2])]
    );
}

/// ORs the signature modifier when requested.
#[test]
fn keys_import_signature_flag() {
    let c = [cand(Ecc, 1, &[9])];
    assert_eq!(
        writes(&set_key_commands(&c, &[(0, 101)], false, false, true)),
        [(101, 1 | 64, vec![9])]
    );
}

/// A manual RSA-1 load is not tagged as decryption.
#[test]
fn keys_import_manual_rsa1_no_decryption() {
    let c = [cand(Rsa, 2, &[1, 2])];
    assert_eq!(
        writes(&set_key_commands(&c, &[(0, 1)], false, true, false)),
        [(1, 2 | 128, vec![1, 2])]
    );
}

/// Loads the selected candidate into the target slot with no Auto Load tagging.
#[test]
fn keys_import_selected_candidate() {
    let exp = expected("pgp-rsa2048.asc");
    let w =
        writes(&import_selected(&fixture("pgp-rsa2048.asc"), PASS, 1, 3, false, false).unwrap());
    assert_eq!(w.len(), 1);
    assert_eq!((w[0].0, w[0].1), (3, 2));
    assert_eq!(crate::encoding::bytes_to_hex(&w[0].2), exp[1].1);
}

/// Rejects an unknown selected candidate.
#[test]
fn keys_import_unknown_candidate() {
    let err = import_selected(&fixture("pgp-rsa2048.asc"), PASS, 9, 1, false, false).unwrap_err();
    assert_eq!(err.to_string(), "Selected key not found.");
}

// ---- keyService.test.ts ----

/// wipeKeyInSlot: wipes the requested slot; Auto Load 99 maps to RSA slot 1.
#[test]
fn keys_wipe_slot_and_auto_load() {
    assert!(matches!(
        wipe_key(3)[..],
        [Command::WipePrivateKey { slot: 3 }]
    ));
    assert!(matches!(
        wipe_key(99)[..],
        [Command::WipePrivateKey { slot: 1 }]
    ));
}

// ---- Setup.ui.test.tsx (backup passphrase + PGP backup key) ----

/// Backup passphrase validation messages, in order.
#[test]
fn keys_validate_backup_passphrase() {
    let ok = "this passphrase is not complex!!";
    let err = |p, c| validate_backup_passphrase(p, c).unwrap_err().to_string();
    assert_eq!(err("", ""), "Passphrase cannot be empty.");
    assert_eq!(
        err("short", "short"),
        "Passphrase must be at least 25 characters."
    );
    assert_eq!(
        err(ok, "this passphrase is different!!!!"),
        "Passphrase fields do not match."
    );
    assert_eq!(validate_backup_passphrase(ok, ok), Ok(()));
    // 25 UTF-16 units passes, 24 fails.
    assert!(validate_backup_passphrase(&"a".repeat(25), &"a".repeat(25)).is_ok());
    assert!(validate_backup_passphrase(&"a".repeat(24), &"a".repeat(24)).is_err());
}

/// Advanced uninitialized setup locks the backup key (BACKUPKEYMODE 20 = 1).
#[test]
fn keys_backup_key_mode_command() {
    assert!(matches!(
        backup_key_mode_command(1),
        Command::SetGlobal {
            field: 20,
            value: 1
        }
    ));
}

/// PGP backup key requires a key, then a passcode.
#[test]
fn keys_pgp_backup_requires_key_and_passcode() {
    let err = |t, p| {
        pgp_backup_commands(t, p, 1, None, false, 0)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(err("  ", PASS), "OpenPGP private key cannot be empty.");
    assert_eq!(
        err(&fixture("pgp-ed25519.asc"), ""),
        "Passcode cannot be empty."
    );
}

/// PGP backup key: selection required, then the chosen key with backup (+signature) and the key mode.
#[test]
fn keys_pgp_backup_with_signature_flag() {
    let text = fixture("pgp-ed25519.asc");
    assert!(matches!(
        pgp_backup_commands(&text, PASS, 101, None, true, 0),
        Err(ImportError::SelectionRequired(_))
    ));
    let cmds = pgp_backup_commands(&text, PASS, 101, Some((0, 101)), true, 0).unwrap();
    assert_eq!(cmds.len(), 2);
    assert_eq!(writes(&cmds[..1])[0].0, 101);
    assert_eq!(
        writes(&cmds[..1])[0].1,
        1 | KEY_TYPE_BACKUP | KEY_TYPE_SIGNATURE
    );
    assert!(matches!(
        cmds[1],
        Command::SetGlobal {
            field: 20,
            value: 0
        }
    ));
}

// ---- Advanced.ui.test.tsx (raw hex keys) ----

/// Saves a raw ECC key; modifiers add backup and signature.
#[test]
fn keys_raw_ecc_with_modifiers() {
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let w = writes(&raw_key_commands(1, 101, hex, false, false, false).unwrap());
    assert_eq!(w[0].0, 101);
    assert_eq!(w[0].1, 1);
    assert_eq!(w[0].2, crate::encoding::hex_to_bytes(hex).unwrap());
    let w = writes(&raw_key_commands(1, 101, hex, true, true, false).unwrap());
    assert_eq!(w[0].1, 1 + 128 + 64);
}

/// SECP256K1 with the decryption modifier on slot 102.
#[test]
fn keys_raw_secp256k1_decryption() {
    let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let w = writes(&raw_key_commands(3, 102, hex, false, false, true).unwrap());
    assert_eq!((w[0].0, w[0].1), (102, 3 + 32));
}

/// Short HMAC and ECC keys are rejected; whitespace is ignored and extra hex is cut off.
#[test]
fn keys_raw_length_and_whitespace() {
    let err = |t, h: &str| {
        raw_key_commands(t, 130, h, false, false, false)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(err(9, "aabb"), "HMAC key must be 40 hex characters.");
    assert_eq!(err(1, "aabb"), "ECC key must be 64 hex characters.");
    assert_eq!(err(1, &"zz".repeat(32)), "Invalid hex string.");
    let spaced = format!("{} {}ffff", "ab".repeat(10), "cd".repeat(10));
    let w = writes(&raw_key_commands(9, 130, &spaced, false, false, false).unwrap());
    assert_eq!((w[0].0, w[0].1, w[0].2.len()), (130, 9, 20));
}
