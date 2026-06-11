"""
TP9 - Padding Oracle Attack (AES-128-CBC)

El servidor cifra un mensaje secreto con AES-CBC y el IV va prepended al ciphertext.
El endpoint /decrypt actúa como oráculo: responde 200 OK si el padding PKCS7 es
válido, o 400 "Bad padding bytes" si no lo es.

Ataque:
  Para cada bloque C[i] (i=1..n), recuperamos D[i] = AES_dec(C[i]) byte a byte.
  Luego P[i] = D[i] XOR C[i-1]  (con C[0] = IV).

  Para recuperar el byte j (0-indexed, de 15 a 0) de D[i]:
    pad_byte = 16 - j   (j=15 → pad=1; j=14 → pad=2; ... j=0 → pad=16)

    1. Construir C'[i-1] de 16 bytes:
         - Bytes k > j:  C'[k] = D[i,k] XOR pad_byte  (fuerzan padding conocido)
         - Byte j:       C'[j] = x  (probar 0..255)

    2. Enviar [C'[i-1] || C[i]] al oráculo.
       Si responde 200 OK → P'[i,j] = pad_byte → D[i,j] = x XOR pad_byte.

    3. Para j=15 (buscamos padding \x01): verificar falso positivo flipeando el
       byte j-1 del C' modificado. Si el oráculo deja de responder OK, era un
       falso positivo (ej. padding \x02\x02) y continuamos buscando.

  Resultado: P[i,k] = D[i,k] XOR C[i-1,k] para todo k.
"""

import base64
import requests

EMAIL         = "santiagovietto5@gmail.com"
SERVER        = "https://cripto.iua.edu.ar"
URL_CHALLENGE = f"{SERVER}/padding-oracle/{EMAIL}/challenge"
URL_DECRYPT   = f"{SERVER}/padding-oracle/{EMAIL}/decrypt"
URL_ANSWER    = f"{SERVER}/padding-oracle/{EMAIL}/answer"
B             = 16

session = requests.Session()


def oracle(ct: bytes) -> bool:
    """Devuelve True si el padding del ciphertext es válido (HTTP 200)."""
    b64  = base64.b64encode(ct).decode()
    resp = session.post(URL_DECRYPT, files={"message": (None, b64)})
    return resp.status_code == 200


# ── Paso 1: obtener el ciphertext del challenge ───────────────────────────────
print("[1] Obteniendo ciphertext del challenge...")
ct_full  = base64.b64decode(session.get(URL_CHALLENGE).text.strip())
blocks   = [ct_full[i:i+B] for i in range(0, len(ct_full), B)]
n_blocks = len(blocks)
print(f"[1] Ciphertext: {len(ct_full)} bytes  ({n_blocks} bloques, incluyendo IV)")


# ── Paso 2: ataque Padding Oracle bloque a bloque ────────────────────────────
print(f"[2] Iniciando ataque sobre {n_blocks - 1} bloques de plaintext...")

plaintext_raw = b""

for i in range(1, n_blocks):
    C_prev = blocks[i - 1]   # bloque anterior (IV cuando i=1)
    C_curr = blocks[i]        # bloque cifrado actual

    D = bytearray(B)          # D[i] = AES_dec(C[i]) — salida interna antes del XOR

    for j in range(B - 1, -1, -1):   # de byte 15 (último) al 0 (primero)
        pad_byte = B - j              # valor de padding objetivo

        # Fijar los bytes ya recuperados para producir pad_byte en esas posiciones
        C_mod = bytearray(B)
        for k in range(j + 1, B):
            C_mod[k] = D[k] ^ pad_byte

        encontrado = False
        for x in range(256):
            C_mod[j] = x
            if oracle(bytes(C_mod) + bytes(C_curr)):
                # Para el último byte del bloque verificamos falso positivo:
                # puede que el padding sea \x02\x02 u otro en vez de \x01
                if j == B - 1:
                    C_check        = bytearray(C_mod)
                    C_check[j - 1] ^= 1
                    if not oracle(bytes(C_check) + bytes(C_curr)):
                        continue   # falso positivo, seguir buscando
                D[j]      = x ^ pad_byte
                encontrado = True
                break

        if not encontrado:
            print(f"  [!] No se encontró byte {j} del bloque {i}")
            D[j] = 0

    # Recuperar el bloque de plaintext: XOR de la salida interna con el bloque anterior
    P = bytes(D[k] ^ C_prev[k] for k in range(B))
    plaintext_raw += P
    try:
        preview = P.decode("utf-8")
    except UnicodeDecodeError:
        preview = P.decode("latin-1")
    print(f"  [Bloque {i:2d}/{n_blocks - 1}] {preview!r}")


# ── Paso 3: eliminar padding PKCS7 ───────────────────────────────────────────
pad_len   = plaintext_raw[-1]
plaintext = plaintext_raw[:-pad_len]
try:
    secret = plaintext.decode("utf-8")
except UnicodeDecodeError:
    secret = plaintext.decode("latin-1")

print(f"\n[3] Mensaje descifrado:\n{secret}")


# ── Paso 4: enviar la respuesta ───────────────────────────────────────────────
resp = session.post(URL_ANSWER, files={"message": (None, secret)})
print(f"\n[4] Código HTTP : {resp.status_code}")
print(f"[4] Respuesta   : {resp.text.strip()}")
