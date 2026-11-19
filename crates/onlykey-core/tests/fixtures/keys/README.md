# Key import fixtures

Throwaway test keys generated for `onlykey-core` tests only. They protect nothing; never use them for anything real.
Encrypted ones use the passphrase `test-passphrase`.

- `gen.sh` regenerates the keys (gpg 2.5, OpenSSH, OpenSSL); `expected.py` writes each `<fixture>.expected`.
- `.expected`: one line per candidate (`base_type hex`), taken without rpgp/ssh-key: `openssl rsa|pkey -text`
  (PEM, and OpenSSH RSA/ECDSA after `ssh-keygen -p -m PEM`), a small packet walker over the unprotected
  `gpg --export-secret-keys` output (OpenPGP), and the unencrypted OpenSSH blob (ed25519).
- Fixtures without `.expected` cover error paths (DSA, brainpool, P-384, secp256k1 ECDH).
