"""
TP13 - Ataque de extensión de longitud (Length Extension Attack)

MAC = SHA-256(secreto || mensaje)          secreto: 16 bytes desconocidos
mensaje = concat(clave+valor) de todos los pares excepto 'mac',
          ordenados alfabéticamente por clave, sin los símbolos = ni &.

Ataque:
  SHA-256 usa Merkle-Damgård. Si conocemos SHA-256(S||M) podemos
  calcular SHA-256(S||M||pad1||extensión) sin conocer S, inicializando
  SHA-256 con el MAC actual como estado interno y desplazando el contador
  de longitud a |S||M||pad1|.

Construcción de la query falsificada:
  Usamos la clave 'a' (antes alfabéticamente que 'action', 'admin', 'user')
  para que su valor absorba el resto del mensaje original + los bytes de padding.
  Luego agregamos admin=true y user=<email>.
  El mensaje resultante es exactamente original_msg || pad1 || admintrue || user || email.
"""

import hashlib, requests, struct, urllib.parse

EMAIL      = "santiagovietto5@gmail.com"
SERVER     = "https://cripto.iua.edu.ar"
SECRET_LEN = 16

# ── SHA-256 custom: permite setear IV y contador de bytes previos ─────────────

_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
_IV = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _compress(st, blk):
    w = list(struct.unpack('>16I', blk))
    for i in range(16, 64):
        s0 = _rotr(w[i-15],7)^_rotr(w[i-15],18)^(w[i-15]>>3)
        s1 = _rotr(w[i-2],17)^_rotr(w[i-2],19)^(w[i-2]>>10)
        w.append((w[i-16]+s0+w[i-7]+s1)&0xFFFFFFFF)
    a,b,c,d,e,f,g,h = st
    for i in range(64):
        S1  = _rotr(e,6)^_rotr(e,11)^_rotr(e,25)
        ch  = (e&f)^((e^0xFFFFFFFF)&g)
        t1  = (h+S1+ch+_K[i]+w[i])&0xFFFFFFFF
        S0  = _rotr(a,2)^_rotr(a,13)^_rotr(a,22)
        maj = (a&b)^(a&c)^(b&c)
        t2  = (S0+maj)&0xFFFFFFFF
        h=g; g=f; f=e; e=(d+t1)&0xFFFFFFFF
        d=c; c=b; b=a; a=(t1+t2)&0xFFFFFFFF
    return [(st[i]+x)&0xFFFFFFFF for i,x in enumerate([a,b,c,d,e,f,g,h])]


def _sha256_pad(total_len: int) -> bytes:
    """Padding SHA-256 para un mensaje de total_len bytes."""
    k = (56 - (total_len + 1) % 64) % 64
    return b'\x80' + b'\x00' * k + struct.pack('>Q', total_len * 8)


def sha256_ext(data: bytes, iv: list, prior_bytes: int) -> str:
    """
    SHA-256 inicializado con 'iv' y con 'prior_bytes' ya procesados.
    Equivale a continuar el hash como si 'data' siguiera a los prior_bytes.
    """
    state  = list(iv)
    padded = data + _sha256_pad(prior_bytes + len(data))
    for i in range(0, len(padded), 64):
        state = _compress(state, padded[i:i+64])
    return ''.join(f'{x:08x}' for x in state)


# Verificación: sha256_ext con IV estándar y prior=0 debe igualar hashlib
assert sha256_ext(b"abc", _IV, 0) == hashlib.sha256(b"abc").hexdigest(), \
    "Error en implementación SHA-256 custom"


def mac_message(pairs) -> bytes:
    """Genera el mensaje MAC: pares (excluye 'mac') ordenados por clave."""
    filtered = sorted([(k, v) for k, v in pairs if k != 'mac'], key=lambda x: x[0])
    return b''.join(k.encode() + v.encode() for k, v in filtered)


# ── Paso 1: obtener el desafío ────────────────────────────────────────────────
print("[1] Obteniendo desafío...")
resp = requests.get(f"{SERVER}/secret-prefix-mac/{EMAIL}/challenge")
challenge = resp.text.strip()
print(f"[1] Desafío: {challenge}")

pairs        = urllib.parse.parse_qsl(challenge)
original_mac = dict(pairs)['mac']
original_msg = mac_message(pairs)
print(f"[1] Mensaje original ({len(original_msg)} bytes): {original_msg.decode()}")
print(f"[1] MAC original: {original_mac}")


# ── Paso 2: calcular el padding del mensaje original ─────────────────────────
total_original = SECRET_LEN + len(original_msg)          # secreto + mensaje
padding1       = _sha256_pad(total_original)
padded_len     = total_original + len(padding1)           # múltiplo de 64
assert padded_len % 64 == 0

print(f"\n[2] Longitud (secreto+mensaje): {total_original} B")
print(f"[2] Padding1 ({len(padding1)} B): {padding1.hex()}")
print(f"[2] Longitud con padding: {padded_len} B ({padded_len//64} bloques)")


# ── Paso 3: extensión y nuevo MAC ─────────────────────────────────────────────
# En la nueva query los pares (excepto mac) ordenados son: a, admin, user
# Mensaje nuevo = 'a' + value_a + 'admin' + 'true' + 'user' + email
# Queremos que sea: original_msg || padding1 || admintrue || user || email
# => value_a = original_msg[1:] + padding1
# => extension = b'admintrue' + b'user' + email

extension = b"admintrue" + b"user" + EMAIL.encode()
print(f"\n[3] Extensión ({len(extension)} B): {extension.decode()}")

iv = list(struct.unpack('>8I', bytes.fromhex(original_mac)))
new_mac = sha256_ext(extension, iv, padded_len)
print(f"[3] Nuevo MAC: {new_mac}")


# ── Paso 4: construir la query falsificada ────────────────────────────────────
# value_a contiene bytes binarios (el padding1); hay que URL-encodearlos
value_a         = original_msg[1:] + padding1             # todo excepto la 'a' inicial
value_a_encoded = urllib.parse.quote(value_a, safe='')
user_encoded    = urllib.parse.quote(EMAIL, safe='')

forged_query = (
    "a="     + value_a_encoded +
    "&admin=true" +
    "&mac="  + new_mac +
    "&user=" + user_encoded
)
print(f"\n[4] Query falsificada (primeros 80 chars): {forged_query[:80]}...")


# ── Paso 5: enviar la respuesta ───────────────────────────────────────────────
url  = f"{SERVER}/secret-prefix-mac/{EMAIL}/answer?{forged_query}"
resp = requests.get(url)
print(f"\n[5] Código HTTP: {resp.status_code}")
print(f"[5] Respuesta:   {resp.text.strip()}")
