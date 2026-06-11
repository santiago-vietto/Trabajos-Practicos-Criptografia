"""
TP12 - Prueba de trabajo en una red blockchain
Objetivo: construir un bloque válido (nonce tal que SHA-256(bloque) < target)
          y enviarlo al servidor para que lo agregue a la cadena.

Estructura del bloque (96 bytes):
  [ 0: 8] número de bloque  (uint64 big-endian)
  [ 8:16] timestamp          (uint64 big-endian, segundos UTC)
  [16:24] primeros 64 bits del target (big-endian; los 192 restantes son ceros)
  [24:32] nonce              (uint64 big-endian)
  [32:64] hash bloque anterior (SHA-256 de los 96 bytes del bloque anterior)
  [64:96] hash del email     (SHA-256(email UTF-8))
"""

import hashlib
import requests
import base64
import struct
import time
from datetime import datetime

EMAIL      = "santiagovietto5@gmail.com"
SERVER     = "https://cripto.iua.edu.ar"
URL_LATEST = f"{SERVER}/pow/{EMAIL}/blocks/latest"
URL_BLOCKS = f"{SERVER}/pow/{EMAIL}/blocks"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- Paso 1: obtener el último bloque de la cadena ---
print("[1] Obteniendo último bloque...")
resp = requests.get(URL_LATEST)
prev_block = base64.b64decode(resp.content)
assert len(prev_block) == 96, f"Longitud inesperada: {len(prev_block)}"

prev_number    = int.from_bytes(prev_block[0:8],  "big")
prev_timestamp = int.from_bytes(prev_block[8:16], "big")
msb_64_target  = int.from_bytes(prev_block[16:24],"big")
target_bytes   = prev_block[16:24]          # se copia tal cual al nuevo bloque
prev_hash      = sha256(prev_block)          # SHA-256 de los 96 bytes

print(f"[1] Número de bloque anterior : {prev_number}")
print(f"[1] Timestamp anterior        : {datetime.fromtimestamp(prev_timestamp)}")
print(f"[1] Target (MSB 64 bits)      : {msb_64_target:#018x}")
print(f"[1] Hash bloque anterior      : {prev_hash.hex()}")


# --- Paso 2: armar la plantilla del nuevo bloque ---
email_hash       = sha256(EMAIL.encode("utf-8"))
new_block_number = prev_number + 1

new_block = bytearray(96)
struct.pack_into(">Q", new_block,  0, new_block_number)
# [8:16]  timestamp  → se actualiza en el bucle
new_block[16:24] = target_bytes
# [24:32] nonce      → se actualiza en el bucle
new_block[32:64] = prev_hash
new_block[64:96] = email_hash

print(f"\n[2] Minando bloque #{new_block_number} (target MSB64 = {msb_64_target:#018x})...")


# --- Paso 3: proof of work ---
# Optimización: solo comparar los 8 bytes más significativos del hash
# (hash < target ⟺ top-64-bits-del-hash < msb_64_target)
inicio = time.time()
nonce  = 0

while True:
    # Actualizar timestamp cada 200 000 iteraciones (~1 s de margen)
    if nonce % 200_000 == 0:
        struct.pack_into(">Q", new_block, 8, int(time.time()))

    struct.pack_into(">Q", new_block, 24, nonce)

    h = hashlib.sha256(new_block).digest()
    if int.from_bytes(h[:8], "big") < msb_64_target:
        break

    nonce += 1

elapsed = time.time() - inicio
print(f"[3] Nonce encontrado : {nonce}  ({nonce:,} intentos en {elapsed:.2f}s)")
print(f"[3] Hash del bloque  : {hashlib.sha256(new_block).hexdigest()}")
print(f"[3] Timestamp usado  : {datetime.fromtimestamp(int.from_bytes(new_block[8:16], 'big'))}")


# --- Paso 4: enviar el bloque ---
print("\n[4] Enviando bloque al servidor...")
encoded_block = base64.b64encode(bytes(new_block))
resp = requests.post(URL_BLOCKS, files={"block": encoded_block})
print(f"[4] Código HTTP : {resp.status_code}")
print(f"[4] Respuesta   : {resp.text.strip()}")
