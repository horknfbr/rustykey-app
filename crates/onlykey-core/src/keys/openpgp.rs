//! OpenPGP private key block → candidates via rpgp; bytes match openpgp.js `privateParams`.

use super::{
    ImportError, KeyCandidate, Material, ecc_material, invalid, left_pad32, rsa_material,
    unsupported_ecc,
};
use pgp::composed::{Deserializable, SignedSecretKey};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{KeyDetails, KeyVersion, Password, PlainSecretParams, PublicParams};
use zeroize::Zeroizing;

/// Parses and decrypts the primary key and every secret subkey, in packet order.
pub(super) fn parse(text: &str, passphrase: &str) -> Result<Vec<KeyCandidate>, ImportError> {
    if passphrase.is_empty() {
        return Err(invalid("Passcode is required for OpenPGP keys."));
    }
    if !text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Err(invalid("Armored text not of type private key"));
    }
    // ponytail: rpgp's own wording; openpgp.js has no single message for a malformed key.
    let (key, _) = SignedSecretKey::from_string(text)
        .map_err(|e| invalid(format!("Could not read OpenPGP key: {e}")))?;
    let pw = Password::from(passphrase);

    let primary = &key.primary_key;
    let mut out = vec![named(
        primary.unlock(&pw, |pub_params, plain| {
            Ok(material(primary.algorithm(), pub_params, plain))
        }),
        primary.algorithm(),
        "Primary Key".into(),
    )?];
    for (i, sub) in key.secret_subkeys.iter().enumerate() {
        let sub = &sub.key;
        out.push(named(
            sub.unlock(&pw, |pub_params, plain| {
                Ok(material(sub.algorithm(), pub_params, plain))
            }),
            sub.algorithm(),
            format!("Subkey {}", i + 1),
        )?);
    }
    Ok(out)
}

/// Turns one unlock result into a named candidate; any unlock failure reads as openpgp.js's wrong-passphrase error.
fn named(
    unlocked: pgp::errors::Result<pgp::errors::Result<Result<Material, ImportError>>>,
    alg: PublicKeyAlgorithm,
    name: String,
) -> Result<KeyCandidate, ImportError> {
    let decrypt_err = |_| invalid("Error decrypting private key: Incorrect key passphrase");
    let material = unlocked.map_err(decrypt_err)?.map_err(decrypt_err)??;
    let mut key = KeyCandidate::new(
        material,
        format!("{alg:?}"),
        alg.can_sign(),
        alg.can_encrypt(),
    );
    key.name = name;
    Ok(key)
}

/// Device bytes from the decrypted secret params: RSA p ‖ q; ECDSA/ECDH/EdDSA-legacy d or seed
/// (MPI left-padded to 32); Ed25519/X25519 the raw 32 bytes (`materialFromOpenPgpPacket`).
fn material(
    alg: PublicKeyAlgorithm,
    pub_params: &PublicParams,
    plain: &PlainSecretParams,
) -> Result<Material, ImportError> {
    let unreadable = || invalid("Could not read key parameters from OpenPGP key.");
    // V6 framing writes the bare algorithm-specific fields (no trailing V4 checksum).
    let mut raw = Zeroizing::new(Vec::new());
    plain
        .to_writer(&mut *raw, KeyVersion::V6)
        .map_err(|_| unreadable())?;
    let mut rest: &[u8] = &raw;
    match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            let _d = mpi(&mut rest).ok_or_else(unreadable)?;
            let p = mpi(&mut rest).ok_or_else(unreadable)?;
            let q = mpi(&mut rest).ok_or_else(unreadable)?;
            rsa_material(p, q)
        }
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::ECDH | PublicKeyAlgorithm::EdDSALegacy => {
            let curve = match pub_params {
                PublicParams::ECDSA(p) => p.curve(),
                PublicParams::ECDH(p) => p.curve(),
                PublicParams::EdDSALegacy(p) => p.curve(),
                _ => return Err(unreadable()),
            };
            let base_type = match curve {
                ECCCurve::Secp256k1 => 3,
                ECCCurve::Curve25519Legacy | ECCCurve::Ed25519Legacy => 1,
                ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 => 2,
                _ => return Err(unsupported_ecc()),
            };
            let scalar = mpi(&mut rest).ok_or_else(unreadable)?;
            ecc_material(base_type, &left_pad32(scalar))
        }
        PublicKeyAlgorithm::Ed25519 | PublicKeyAlgorithm::X25519 => ecc_material(1, &raw),
        PublicKeyAlgorithm::Ed448 | PublicKeyAlgorithm::X448 => Err(unsupported_ecc()),
        _ => Err(unreadable()),
    }
}

/// Reads one OpenPGP MPI (2-byte bit count, then the bytes) and advances `rest`.
fn mpi<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let bits = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
    let len = bits.div_ceil(8);
    let value = rest.get(2..2 + len)?;
    *rest = &rest[2 + len..];
    Some(value)
}
