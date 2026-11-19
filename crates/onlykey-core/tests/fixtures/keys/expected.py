"""Independent expected device bytes for each fixture: openssl -text for PEM, a minimal packet walker for OpenPGP."""
import re, struct, subprocess, sys, os, shutil, base64
OUT = '/private/tmp/claude-501/gk/out'; P = 'test-passphrase'
def run(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    if r.returncode: raise SystemExit(f"{a}: {r.stderr}")
    return r.stdout
def field(text, name):
    m = re.search(r'^' + name + r':\s*\n((?:\s+[0-9a-f:]+\n)+)', text, re.M)
    return bytes.fromhex(re.sub(r'[\s:]', '', m.group(1)))
def strip(b):
    i = 0
    while i < len(b) - 1 and b[i] == 0: i += 1
    return b[i:]
def ecc32(b):
    b = strip(b) if len(b) > 32 else b
    return b.rjust(32, b'\0')
def rsa_line(p, q):
    p, q = strip(p), strip(q); return f'{len(p)//64} {(p+q).hex()}'
def openssl_rsa(path, extra=()):
    t = run('openssl', 'rsa', '-in', path, '-text', '-noout', *extra); return rsa_line(field(t, 'prime1'), field(t, 'prime2'))
def openssl_ec(path, typ, extra=()):
    t = run('openssl', 'pkey', '-in', path, '-text', '-noout', *extra); return f'{typ} {ecc32(field(t, "priv")).hex()}'
def to_pem(name):
    tmp = f'/private/tmp/claude-501/gk/{name}.tmp'; shutil.copy(f'{OUT}/{name}', tmp); os.chmod(tmp, 0o600)
    run('ssh-keygen', '-q', '-p', '-P', P, '-N', '', '-m', 'PEM', '-f', tmp); return tmp
def openssh_ed25519(name):
    tmp = f'/private/tmp/claude-501/gk/{name}.tmp'; shutil.copy(f'{OUT}/{name}', tmp); os.chmod(tmp, 0o600)
    if name != 'ssh-ed25519-plain': run('ssh-keygen', '-q', '-p', '-P', P, '-N', '', '-f', tmp)
    body = ''.join(l for l in open(tmp).read().splitlines() if not l.startswith('-----'))
    d = base64.b64decode(body); assert d.startswith(b'openssh-key-v1\0'); o = len(b'openssh-key-v1\0')
    def s():
        nonlocal o; n = struct.unpack('>I', d[o:o+4])[0]; v = d[o+4:o+4+n]; o += 4 + n; return v
    assert s() == b'none'; s(); s(); o += 4; s()
    priv = s(); o2 = 8; 
    def s2():
        nonlocal o2; n = struct.unpack('>I', priv[o2:o2+4])[0]; v = priv[o2+4:o2+4+n]; o2 += 4 + n; return v
    assert s2() == b'ssh-ed25519'; s2(); sk = s2(); return f'1 {sk[:32].hex()}'
CURVES = {bytes.fromhex('2b06010401da470f01'): 1, bytes.fromhex('2b060104019755010501'): 1,
          bytes.fromhex('2a8648ce3d030107'): 2, bytes.fromhex('2b8104000a'): 3}
def pgp(name):
    d = open(f'{OUT}/{name}.plain.gpg', 'rb').read(); o = 0; lines = []
    while o < len(d):
        h = d[o]; o += 1; assert h & 0x80
        if h & 0x40:
            tag = h & 0x3f; l = d[o]; o += 1
            if l >= 192 and l < 224: l = ((l - 192) << 8) + d[o] + 192; o += 1
            elif l == 255: l = struct.unpack('>I', d[o:o+4])[0]; o += 4
        else:
            tag = (h >> 2) & 0xf; lt = h & 3; n = [1, 2, 4][lt]; l = int.from_bytes(d[o:o+n], 'big'); o += n
        body = d[o:o+l]; o += l
        if tag not in (5, 7): continue
        assert body[0] == 4; algo = body[5]; b = 6
        def mpi():
            nonlocal b; bits = struct.unpack('>H', body[b:b+2])[0]; n = (bits + 7) // 8; v = body[b+2:b+2+n]; b += 2 + n; return v
        if algo in (1, 2, 3): mpi(); mpi()
        else:
            ol = body[b]; oid = body[b+1:b+1+ol]; b += 1 + ol; mpi()
            if algo == 18: kl = body[b]; b += 1 + kl
        assert body[b] == 0, 'secret not plaintext'; b += 1
        if algo in (1, 2, 3): mpi(); p = mpi(); q = mpi(); lines.append(rsa_line(p, q))
        else: lines.append(f'{CURVES[oid]} {ecc32(mpi()).hex()}')
    return '\n'.join(lines)
exp = {}
for n in ['pgp-rsa2048', 'pgp-rsa4096', 'pgp-ed25519', 'pgp-p256', 'pgp-secp256k1-sign']: exp[n + '.asc'] = pgp(n)
exp['ssh-rsa2048'] = openssl_rsa(to_pem('ssh-rsa2048'))
exp['ssh-p256'] = openssl_ec(to_pem('ssh-p256'), 2)
exp['ssh-ed25519'] = openssh_ed25519('ssh-ed25519'); exp['ssh-ed25519-plain'] = openssh_ed25519('ssh-ed25519-plain')
exp['pem-pkcs1-rsa2048.pem'] = openssl_rsa(f'{OUT}/pem-pkcs1-rsa2048.pem')
exp['pem-pkcs1-enc-rsa2048.pem'] = openssl_rsa(f'{OUT}/pem-pkcs1-enc-rsa2048.pem', ('-passin', 'pass:' + P))
exp['pem-pkcs8-enc-rsa1024.pem'] = openssl_rsa(f'{OUT}/pem-pkcs8-enc-rsa1024.pem', ('-passin', 'pass:' + P))
exp['pem-sec1-p256.pem'] = openssl_ec(f'{OUT}/pem-sec1-p256.pem', 2)
exp['pem-pkcs8-enc-p256.pem'] = openssl_ec(f'{OUT}/pem-pkcs8-enc-p256.pem', 2, ('-passin', 'pass:' + P))
exp['pem-sec1-secp256k1.pem'] = openssl_ec(f'{OUT}/pem-sec1-secp256k1.pem', 3)
exp['pem-pkcs8-ed25519.pem'] = openssl_ec(f'{OUT}/pem-pkcs8-ed25519.pem', 1)
for k, v in exp.items():
    open(f'{OUT}/{k}.expected', 'w').write(v + '\n')
    print(k, [ (l.split()[0], len(l.split()[1])//2) for l in v.splitlines()])
