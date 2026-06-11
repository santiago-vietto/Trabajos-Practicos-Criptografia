"""
TP8 - Descifrado en modo ECB (ECB Byte-at-a-time)

El servidor calcula: AES-ECB( decode_b64(mensaje) || secreto )
En modo ECB cada bloque se cifra independientemente con la misma clave.

Ataque:
  Para recuperar el byte k del secreto:
    1. Enviar padding de (15 - k%16) bytes de 'A' como sonda.
       → El bloque k//16 del ciphertext termina con S[k] (desconocido).
       → Guardamos ese bloque como C_ref.
    2. Construir el prefijo de 15 bytes conocidos: A's + bytes ya descubiertos
       (o los últimos 15 bytes del secreto conocido si k >= 15).
    3. Probar los 256 posibles valores del último byte:
       → Enviar prefijo_15 + [guess] (16 bytes)
       → Block 0 del ciphertext = AES(prefijo_15 || guess)
       → Si coincide con C_ref: S[k] = guess.

Optimización:
  - Cachear los 16 ciphertexts de sonda al inicio (solo 16 requests iniciales).
  - Priorizar ASCII imprimible para reducir intentos promedio.
"""

import base64
import requests

EMAIL       = "santiagovietto5@gmail.com"
SERVER      = "https://cripto.iua.edu.ar"
URL_ENCRYPT = f"{SERVER}/ecb-decrypt/{EMAIL}/encrypt"
URL_ANSWER  = f"{SERVER}/ecb-decrypt/{EMAIL}/answer"
B           = 16

session = requests.Session()


def encrypt(data: bytes) -> bytes:
    b64  = base64.b64encode(data).decode()
    resp = session.post(URL_ENCRYPT, files={"message": (None, b64)})
    return base64.b64decode(resp.text.strip())


# ── Paso 1: determinar la longitud del secreto ────────────────────────────────
print("[1] Determinando longitud del secreto...")
ct0_len = len(encrypt(b""))
for p in range(1, B * 2 + 1):
    if len(encrypt(b"A" * p)) > ct0_len:
        secret_len = ct0_len - p
        print(f"[1] Longitud: {secret_len} bytes  (ciphertext creció en p={p})")
        break


# ── Paso 2: cachear los 16 ciphertexts de sonda ───────────────────────────────
print("[2] Cacheando ciphertexts de sonda (16 requests)...")
probe = {}
for pad_len in range(B):
    probe[pad_len] = encrypt(b"A" * pad_len)


# ── Paso 3: descifrar byte a byte ─────────────────────────────────────────────
print(f"[3] Descifrando {secret_len} bytes (puede tardar varios minutos)...")

# Priorizar ASCII imprimible, luego el resto
GUESS_ORDER = (list(range(32, 127))
             + list(range(0, 32))
             + list(range(127, 256)))

known = b""

for k in range(secret_len):
    pad_len   = 15 - (k % B)
    block_idx = k // B
    C_ref     = probe[pad_len][block_idx * B : (block_idx + 1) * B]

    # Prefijo de 15 bytes: A's + bytes ya conocidos
    prefix = (b"A" * max(0, 15 - k) + known)[-15:]

    found = False
    for guess in GUESS_ORDER:
        if encrypt(prefix + bytes([guess]))[:B] == C_ref:
            known += bytes([guess])
            found  = True
            break

    if not found:
        known += b"\x00"   # no debería ocurrir

    if (k + 1) % 16 == 0 or k == secret_len - 1:
        try:
            preview = known.decode("utf-8")
        except UnicodeDecodeError:
            preview = known.decode("latin-1")
        print(f"  [{k+1:3d}/{secret_len}] {preview!r}")


# ── Paso 4: enviar la respuesta ───────────────────────────────────────────────
try:
    secret_text = known.decode("utf-8")
except UnicodeDecodeError:
    secret_text = known.decode("latin-1")

print(f"\n[4] Secreto descifrado:\n{secret_text}")

resp = session.post(URL_ANSWER, files={"message": (None, secret_text)})
print(f"\n[5] Código HTTP : {resp.status_code}")
print(f"[5] Respuesta   : {resp.text.strip()}")
