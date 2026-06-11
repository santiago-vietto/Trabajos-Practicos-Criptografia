"""
TP10 - Segunda preimagen de una función de hash
Función SHA-256-24: SHA-256 truncado a los primeros 24 bits (6 caracteres hex).
Objetivo: encontrar un mensaje distinto al email que produzca el mismo hash.
"""

import hashlib
import requests
import time

EMAIL = "santiagovietto5@gmail.com"
URL_CHALLENGE = f"https://cripto.iua.edu.ar/second-preimage/{EMAIL}/challenge"
URL_ANSWER    = f"https://cripto.iua.edu.ar/second-preimage/{EMAIL}/answer"
BITS          = 24
HEX_CHARS     = BITS // 4  # 6


# --- Paso 1: obtener el hash objetivo ---
def sha256_n(mensaje: str, n_hex: int) -> str:
    return hashlib.sha256(mensaje.encode()).hexdigest()[:n_hex]

hash_objetivo = sha256_n(EMAIL, HEX_CHARS)
print(f"[1] Email:         {EMAIL}")
print(f"[1] SHA-256-24:    {hash_objetivo}")


# --- Paso 2: buscar segunda preimagen por fuerza bruta ---
print(f"\n[2] Buscando segunda preimagen (esperado ~2^24 = {2**24:,} intentos)...")

inicio = time.time()
candidato = None

for i in range(1, 2**28):  # margen amplio por las dudas
    # generamos mensajes del estilo "msg0", "msg1", ...
    intento = f"preimage_{i}"
    if sha256_n(intento, HEX_CHARS) == hash_objetivo:
        candidato = intento
        break

elapsed = time.time() - inicio
print(f"[2] Segunda preimagen encontrada en {i:,} intentos ({elapsed:.2f}s): {candidato!r}")
print(f"[2] SHA-256-24({candidato!r}) = {sha256_n(candidato, HEX_CHARS)}")


# --- Paso 3: enviar la respuesta al servidor ---
print(f"\n[3] Enviando respuesta al servidor...")
# curl -F usa multipart/form-data; requests.post con files= replica ese comportamiento
resp = requests.post(URL_ANSWER, files={"message": (None, candidato)})
print(f"[3] Código HTTP: {resp.status_code}")
print(f"[3] Respuesta:   {resp.text.strip()}")
