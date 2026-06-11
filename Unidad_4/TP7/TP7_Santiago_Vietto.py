"""
TP7 - Cambio de bits en modo CBC (CBC Bit Flipping Attack)

Perfil: user=EMAIL;data=DATA;role=user  (AES-128-CBC, IV prepended)

Ataque:
  En CBC: P[i] = D(C[i]) XOR C[i-1]
  Flipear C[i-1] cambia P[i] de manera predecible, aunque P[i-1] queda garbled
  (no importa porque DATA es arbitrario y no se verifica su contenido).

  1. Elegir DATA de 12 bytes para que ";role=user" empiece exactamente en el
     bloque 4 del plaintext (offset 48):
       ct[0:16]  = IV
       ct[16:32] = C1  P1 = "user=santiagovie"
       ct[32:48] = C2  P2 = "tto5@gmail.com;d"
       ct[48:64] = C3  P3 = "ata=AAAAAAAAAAAA"  <- modifico este bloque
       ct[64:80] = C4  P4 = ";role=user\x06*6"  <- se ve afectado

  2. Máscara = P4_viejo XOR P4_nuevo:
       P4_viejo = ";role=user\x06\x06\x06\x06\x06\x06"
       P4_nuevo  = ";role=admin\x05\x05\x05\x05\x05"   (PKCS7 válido)
       Aplicar a ct[48:64] → P4 descifra a ";role=admin\x05*5"

  Plaintext tras quitar PKCS7:
    "user=santiagovietto5@gmail.com;d<16 bytes garbled>;role=admin"
  Campos:  user=EMAIL ✓   role=admin ✓
"""

import base64
import requests

EMAIL  = "santiagovietto5@gmail.com"
SERVER = "https://cripto.iua.edu.ar"
B      = 16


# ── Paso 1: calcular longitud de DATA para alinear ";role=user" al bloque 4 ───
# Prefijo: "user=EMAIL;data=" = 5 + len(EMAIL) + 6
prefix_len = 5 + len(EMAIL) + 6            # 36
role_start = ((prefix_len // B) + 1) * B   # 48
data_len   = role_start - prefix_len        # 12

raw_data = b"A" * data_len
data_b64 = base64.b64encode(raw_data).decode()

print(f"[1] DATA = {data_len} A's  (b64: {data_b64})")


# ── Paso 2: registrar y obtener IV+ciphertext ──────────────────────────────────
resp = requests.post(
    f"{SERVER}/cbc-bitflip/{EMAIL}/register",
    files={"email": (None, EMAIL), "data": (None, data_b64)}
)
ct = bytearray(base64.b64decode(resp.text.strip()))
print(f"[2] Respuesta: {len(ct)} bytes  (IV + {len(ct)-B} de ciphertext)")


# ── Paso 3: calcular y aplicar máscara ────────────────────────────────────────
profile_len = prefix_len + data_len + 10   # 58 bytes (";role=user" = 10)
pkcs7_old   = B - (profile_len % B)        # 6 bytes de \x06
pkcs7_new   = pkcs7_old - 1               # 5 bytes de \x05 ("admin" tiene 1 char más)

P4_old = b";role=user"  + bytes([pkcs7_old] * pkcs7_old)   # 16 bytes
P4_new = b";role=admin" + bytes([pkcs7_new] * pkcs7_new)   # 16 bytes
mask   = bytes(a ^ b for a, b in zip(P4_old, P4_new))

print(f"[3] P4 original : {P4_old.hex()}")
print(f"[3] P4 objetivo : {P4_new.hex()}")
print(f"[3] Máscara     : {mask.hex()}")

# Aplicar al bloque C3 = ct[role_start : role_start+B]
for j in range(B):
    ct[role_start + j] ^= mask[j]


# ── Paso 4: enviar (con reintentos) ───────────────────────────────────────────
# P3 queda garbled al flippear C3; si contiene ';' accidentalmente puede crear
# campos espurios. Cada registro usa un IV/clave distinta → diferente P3 garbled.
for intento in range(20):
    # Nueva registration → nuevo IV → nuevo P3 garbled
    if intento > 0:
        resp = requests.post(
            f"{SERVER}/cbc-bitflip/{EMAIL}/register",
            files={"email": (None, EMAIL), "data": (None, data_b64)}
        )
        ct = bytearray(base64.b64decode(resp.text.strip()))
        for j in range(B):
            ct[role_start + j] ^= mask[j]

    forjado_b64 = base64.b64encode(ct).decode()
    resp2 = requests.post(
        f"{SERVER}/cbc-bitflip/{EMAIL}/answer",
        files={"message": (None, forjado_b64)}
    )
    resultado = resp2.text.strip()
    print(f"[4] Intento {intento+1:2d}: {resultado}")
    if "Ganaste" in resultado:
        break
