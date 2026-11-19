//! SSH/PEM private key → one candidate, covering what `sshpk.parsePrivateKey(pem, 'pem')` reads:
//! OpenSSH, PKCS#1 RSA, SEC1 EC, PKCS#8 (plain or PBES2-encrypted), legacy `Proc-Type` encryption.

use super::{
    ImportError, KeyCandidate, ecc_material, invalid, left_pad32, rsa_material, unsupported_ecc,
};
use base64::Engine as _;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};
use pkcs8::der::Decode;
use pkcs8::der::asn1::ObjectIdentifier;
use ssh_key::private::{EcdsaKeypair, KeypairData};
use zeroize::Zeroizing;

/// rsaEncryption.
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// id-ecPublicKey.
const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// id-Ed25519.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// NIST P-256 (prime256v1).
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// NIST P-384.
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// NIST P-521.
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
/// secp256k1.
const OID_K256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

/// sshpk's wrong-passphrase message.
const BAD_PASSPHRASE: &str = "Incorrect passphrase supplied, could not decrypt key";

/// sshpk `KeyEncryptedError` for an encrypted key with no passphrase.
fn key_encrypted(format: &str) -> ImportError {
    invalid(format!(
        "The {format} format key (unnamed) is encrypted (password-protected), and no passphrase was provided in `options`"
    ))
}

/// sshpk/`materialFromSshKey` error for algorithms the device does not take.
fn unsupported_type() -> ImportError {
    invalid("Unsupported SSH key type.")
}

/// Error for a body that is not the DER/OpenSSH structure its banner names.
fn malformed() -> ImportError {
    invalid("Invalid PEM key data.")
}

/// Parses the first PEM block in `text` and extracts the device bytes.
pub(super) fn parse(text: &str, passphrase: &str) -> Result<KeyCandidate, ImportError> {
    let pem = Pem::parse(text)?;
    let header = |name: &str| {
        pem.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    };
    let mut der = pem.body.clone();
    if header("proc-type") == Some("4,ENCRYPTED") {
        if passphrase.is_empty() {
            return Err(key_encrypted("PEM"));
        }
        let dek = header("dek-info").ok_or_else(malformed)?;
        der = legacy_decrypt(dek, passphrase.as_bytes(), der)?;
    }
    match pem.label.as_str() {
        "OPENSSH PRIVATE KEY" => openssh(&der, passphrase),
        "RSA PRIVATE KEY" => pkcs1(&der),
        "EC PRIVATE KEY" => sec1(&der, None),
        "PRIVATE KEY" => pkcs8(&der),
        "ENCRYPTED PRIVATE KEY" => {
            if passphrase.is_empty() {
                return Err(key_encrypted("PEM"));
            }
            let info = pkcs8::EncryptedPrivateKeyInfo::from_der(&der).map_err(|_| malformed())?;
            let doc = info
                .decrypt(passphrase.as_bytes())
                .map_err(|_| invalid(BAD_PASSPHRASE))?;
            pkcs8(doc.as_bytes())
        }
        _ => Err(unsupported_type()),
    }
}

/// One PEM block: banner label, `Name: value` headers, decoded body.
struct Pem {
    /// Text between `-----BEGIN ` and `-----`.
    label: String,
    /// Encapsulated headers (e.g. `Proc-Type`, `DEK-Info`).
    headers: Vec<(String, String)>,
    /// Base64-decoded body.
    body: Zeroizing<Vec<u8>>,
}

impl Pem {
    /// Finds the first BEGIN/END pair with matching labels, like sshpk's PEM reader.
    fn parse(text: &str) -> Result<Self, ImportError> {
        let mut lines = text.lines().map(str::trim);
        let label = lines
            .by_ref()
            .find_map(|l| l.strip_prefix("-----BEGIN ")?.strip_suffix("-----"))
            .ok_or_else(|| invalid("invalid PEM header"))?
            .trim()
            .to_string();
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut b64 = Zeroizing::new(String::new());
        let mut in_headers = true;
        let mut closed = false;
        for line in lines {
            if line == end {
                closed = true;
                break;
            }
            if in_headers {
                if let Some((k, v)) = line.split_once(": ") {
                    headers.push((k.to_string(), v.to_string()));
                    continue;
                }
                in_headers = false;
            }
            b64.push_str(line);
        }
        if !closed {
            return Err(invalid("invalid PEM footer"));
        }
        let body = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| malformed())?;
        Ok(Self {
            label,
            headers,
            body: Zeroizing::new(body),
        })
    }
}

/// OpenSSL legacy PEM encryption: key = EVP_BytesToKey(MD5, salt = IV[..8], 1 round), CBC + PKCS#7.
fn legacy_decrypt(
    dek_info: &str,
    passphrase: &[u8],
    mut data: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let (cipher, iv_hex) = dek_info.split_once(',').ok_or_else(malformed)?;
    let iv = crate::encoding::hex_to_bytes(iv_hex).map_err(|_| malformed())?;
    let cipher = cipher.trim().to_ascii_uppercase();
    let key_len = match cipher.as_str() {
        "DES-EDE3-CBC" => 24,
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        _ => return Err(invalid(format!("Unsupported PEM cipher: {cipher}"))),
    };
    let salt = iv.get(..8).ok_or_else(malformed)?;
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut prev: Option<Zeroizing<Vec<u8>>> = None;
    while key.len() < key_len {
        let mut h = Md5::new();
        if let Some(p) = &prev {
            h.update(p.as_slice());
        }
        h.update(passphrase);
        h.update(salt);
        let d = Zeroizing::new(h.finalize().to_vec());
        key.extend_from_slice(&d);
        prev = Some(d);
    }
    let key = &key[..key_len];
    let bad = |_| invalid(BAD_PASSPHRASE);
    let len = match cipher.as_str() {
        "DES-EDE3-CBC" => cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, &iv)
            .map_err(|_| malformed())?
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(bad)?
            .len(),
        "AES-128-CBC" => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, &iv)
            .map_err(|_| malformed())?
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(bad)?
            .len(),
        "AES-192-CBC" => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, &iv)
            .map_err(|_| malformed())?
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(bad)?
            .len(),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &iv)
            .map_err(|_| malformed())?
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(bad)?
            .len(),
    };
    data.truncate(len);
    // A wrong key can still leave valid padding; the DER then fails to parse.
    if data.first() != Some(&0x30) {
        return Err(invalid(BAD_PASSPHRASE));
    }
    Ok(data)
}

/// OpenSSH `openssh-key-v1` (bcrypt-pbkdf encryption): RSA p/q, ed25519 seed `k`, ECDSA `d`.
fn openssh(der: &[u8], passphrase: &str) -> Result<KeyCandidate, ImportError> {
    let mut key = ssh_key::PrivateKey::from_bytes(der).map_err(|_| malformed())?;
    if key.is_encrypted() {
        if passphrase.is_empty() {
            return Err(key_encrypted("OpenSSH"));
        }
        key = key
            .decrypt(passphrase)
            .map_err(|_| invalid(BAD_PASSPHRASE))?;
    }
    match key.key_data() {
        KeypairData::Rsa(k) => {
            let p = k
                .private
                .p
                .as_positive_bytes()
                .unwrap_or(k.private.p.as_bytes());
            let q = k
                .private
                .q
                .as_positive_bytes()
                .unwrap_or(k.private.q.as_bytes());
            Ok(KeyCandidate::new(rsa_material(p, q)?, "RSA", true, true))
        }
        KeypairData::Ed25519(k) => {
            let seed = Zeroizing::new(k.private.to_bytes());
            Ok(KeyCandidate::new(
                ecc_material(1, seed.as_slice())?,
                "Ed25519",
                true,
                false,
            ))
        }
        // sshpk maps every "nistp*" curve to type 2; P-384/P-521 then fail the 32-byte check.
        KeypairData::Ecdsa(k) => {
            let d = match k {
                EcdsaKeypair::NistP256 { private, .. } => private.as_slice(),
                EcdsaKeypair::NistP384 { private, .. } => private.as_slice(),
                EcdsaKeypair::NistP521 { private, .. } => private.as_slice(),
            };
            Ok(KeyCandidate::new(ecc_material(2, d)?, "ECDSA", true, false))
        }
        _ => Err(unsupported_type()),
    }
}

/// PKCS#1 `RSAPrivateKey`: prime1 ‖ prime2.
fn pkcs1(der: &[u8]) -> Result<KeyCandidate, ImportError> {
    let k = pkcs1::RsaPrivateKey::from_der(der).map_err(|_| malformed())?;
    Ok(KeyCandidate::new(
        rsa_material(k.prime1.as_bytes(), k.prime2.as_bytes())?,
        "RSA",
        true,
        true,
    ))
}

/// SEC1 `ECPrivateKey`; `curve` comes from the PKCS#8 wrapper when there is one.
fn sec1(der: &[u8], curve: Option<ObjectIdentifier>) -> Result<KeyCandidate, ImportError> {
    let k = sec1::EcPrivateKey::from_der(der).map_err(|_| malformed())?;
    let curve = curve.or_else(|| k.parameters.and_then(|p| p.named_curve()));
    let base_type = match curve {
        Some(OID_P256 | OID_P384 | OID_P521) => 2,
        Some(OID_K256) => 3,
        _ => return Err(unsupported_ecc()),
    };
    Ok(KeyCandidate::new(
        ecc_material(base_type, &left_pad32(k.private_key))?,
        "ECDSA",
        true,
        false,
    ))
}

/// PKCS#8 `PrivateKeyInfo`: RSA, EC or Ed25519 (other algorithms are unsupported).
fn pkcs8(der: &[u8]) -> Result<KeyCandidate, ImportError> {
    let info = pkcs8::PrivateKeyInfo::from_der(der).map_err(|_| malformed())?;
    match info.algorithm.oid {
        OID_RSA => pkcs1(info.private_key),
        OID_EC => sec1(info.private_key, info.algorithm.parameters_oid().ok()),
        OID_ED25519 => {
            // CurvePrivateKey ::= OCTET STRING (32 bytes), DER-wrapped inside privateKey.
            let seed = match info.private_key {
                [0x04, 0x20, seed @ ..] if seed.len() == 32 => seed,
                _ => return Err(malformed()),
            };
            Ok(KeyCandidate::new(
                ecc_material(1, seed)?,
                "Ed25519",
                true,
                false,
            ))
        }
        _ => Err(unsupported_type()),
    }
}
