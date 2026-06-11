"""
TP11 - Colisiones en una función de hash
Función SHA-256-48: SHA-256 truncado a los primeros 48 bits (12 caracteres hex).
Objetivo: encontrar dos mensajes distintos (que incluyan el email) con el mismo hash.
Técnica: ataque de cumpleaños — esfuerzo esperado ~2^(48/2) = 2^24 ≈ 16M hashes.
"""

import hashlib
import requests
import time

EMAIL  = "santiagovietto5@gmail.com"
URL    = f"https://cripto.iua.edu.ar/collision/{EMAIL}/answer"
BITS   = 48
N_HEX  = BITS // 4  # 12


def sha256_n(msg: bytes, n: int) -> str:
    return hashlib.sha256(msg).hexdigest()[:n]


# --- Paso 1: ataque de cumpleaños ---
print(f"[1] Buscando colisión SHA-256-{BITS} (esperado ~2^{BITS//2} = {2**(BITS//2):,} intentos)...")

tabla: dict[str, bytes] = {}
inicio = time.time()
msg1 = msg2 = None

for i in range(1, 2**30):
    # cada mensaje incluye el email
    candidato = f"{EMAIL};{i}".encode()
    h = sha256_n(candidato, N_HEX)

    if h in tabla:
        msg1 = tabla[h]
        msg2 = candidato
        break
    tabla[h] = candidato

elapsed = time.time() - inicio
print(f"[1] Colisión encontrada en {i:,} intentos ({elapsed:.2f}s)")
print(f"[1] msg1: {msg1.decode()}")
print(f"[1] msg2: {msg2.decode()}")
print(f"[1] SHA-256-48(msg1) = {sha256_n(msg1, N_HEX)}")
print(f"[1] SHA-256-48(msg2) = {sha256_n(msg2, N_HEX)}")


# --- Paso 2: enviar la respuesta al servidor ---
print(f"\n[2] Enviando respuesta al servidor...")
resp = requests.post(URL, files={"message1": (None, msg1), "message2": (None, msg2)})
print(f"[2] Código HTTP: {resp.status_code}")
print(f"[2] Respuesta:   {resp.text.strip()}")
