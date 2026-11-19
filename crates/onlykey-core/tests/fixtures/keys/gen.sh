#!/bin/bash
# Regenerates the throwaway test keys in this folder (OUT), then run expected.py for the .expected files.
# GNUPGHOME must be a short path (gpg-agent socket length limit). Every encrypted key uses "test-passphrase".
set -u
export GNUPGHOME=/private/tmp/claude-501/gk/home
OUT=/private/tmp/claude-501/gk/out
P=test-passphrase
rm -rf $GNUPGHOME $OUT; mkdir -p $GNUPGHOME $OUT; chmod 700 $GNUPGHOME
printf "allow-loopback-pinentry\ns2k-count 65536\n" > $GNUPGHOME/gpg-agent.conf
G="gpg --batch --pinentry-mode loopback --passphrase="
# gen name primary-algo usage [sub-algo usage]... : plain export (for expected.py) + protected armored fixture.
gen() {
  local name=$1; shift; local uid="$name <$name@example.invalid>"
  $G --quick-gen-key "$uid" $1 $2 never 2>/dev/null; shift 2
  local fpr=$(gpg --list-keys --with-colons "$name@example.invalid" | awk -F: '/^fpr/{print $10; exit}')
  while [ $# -ge 2 ]; do $G --quick-add-key $fpr $1 $2 never 2>/dev/null; shift 2; done
  gpg --export-secret-keys "$name@example.invalid" > $OUT/$name.plain.gpg
  gpg --batch --pinentry-mode loopback --passphrase $P --passwd "$name@example.invalid" 2>/dev/null
  gpg --batch --pinentry-mode loopback --passphrase $P --armor --export-secret-keys "$name@example.invalid" > $OUT/$name.asc
}
gen pgp-rsa2048 rsa2048 sign rsa2048 encr rsa2048 sign
gen pgp-rsa4096 rsa4096 sign rsa4096 encr
gen pgp-ed25519 ed25519 sign cv25519 encr
gen pgp-p256 nistp256 sign nistp256 encr
gen pgp-secp256k1-sign secp256k1 sign secp256k1 sign
gen pgp-secp256k1-ecdh secp256k1 sign secp256k1 encr   # rpgp 0.21 rejects (known gap)
gen pgp-dsa dsa2048 sign elg2048 encr                   # error path
gen pgp-brainpool brainpoolP256r1 sign brainpoolP256r1 encr  # error path
cd $OUT
ssh-keygen -q -t ed25519 -N $P -C test -f ssh-ed25519
ssh-keygen -q -t ed25519 -N '' -C test -f ssh-ed25519-plain
ssh-keygen -q -t rsa -b 2048 -N $P -C test -f ssh-rsa2048
ssh-keygen -q -t ecdsa -b 256 -N $P -C test -f ssh-p256
ssh-keygen -q -t ecdsa -b 384 -N '' -C test -f ssh-p384    # error path
rm -f *.pub
T=$(mktemp -d)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $T/rsa.pem
openssl rsa -in $T/rsa.pem -traditional -out pem-pkcs1-rsa2048.pem
openssl rsa -in $T/rsa.pem -traditional -aes256 -passout pass:$P -out pem-pkcs1-enc-rsa2048.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out $T/rsa1024.pem
openssl pkcs8 -topk8 -in $T/rsa1024.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:$P -out pem-pkcs8-enc-rsa1024.pem
openssl ecparam -name prime256v1 -genkey -noout -out pem-sec1-p256.pem
openssl ecparam -name prime256v1 -genkey -noout -out $T/p256.pem
openssl pkcs8 -topk8 -in $T/p256.pem -v2 aes-128-cbc -passout pass:$P -out pem-pkcs8-enc-p256.pem
openssl ecparam -name secp256k1 -genkey -noout -out pem-sec1-secp256k1.pem
openssl genpkey -algorithm ed25519 -out pem-pkcs8-ed25519.pem
openssl ecparam -name brainpoolP256r1 -genkey -noout -out pem-sec1-brainpool.pem   # error path
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -out $T/dsap.pem
openssl genpkey -paramfile $T/dsap.pem -out $T/dsa.pem
openssl pkey -in $T/dsa.pem -traditional -out pem-dsa.pem                          # error path
rm -rf $T
