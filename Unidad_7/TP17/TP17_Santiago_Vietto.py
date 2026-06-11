"""
TP17 - DSA con reutilización de k

Cuando dos mensajes se firman con el mismo k, se obtiene el mismo r.
Con dos pares (m1, s1) y (m2, s2) que comparten r, se recupera k y luego x:

  k = (H(m1) - H(m2)) * (s1 - s2)^(-1)  mod q
  x = r^(-1) * (k*s1 - H(m1))            mod q

Estrategia: firmar mensajes distintos hasta encontrar una colisión en r.
"""

import base64
import hashlib
import requests

EMAIL      = "santiagovietto5@gmail.com"
SERVER     = "https://cripto.iua.edu.ar"
URL_PUBKEY = f"{SERVER}/dsa/{EMAIL}/public-key"
URL_SIGN   = f"{SERVER}/dsa/{EMAIL}/sign"
URL_ANSWER = f"{SERVER}/dsa/{EMAIL}/answer"


# ── Paso 1: obtener la clave pública ──────────────────────────────────────────
print("[1] Obteniendo clave pública...")
pk = requests.get(URL_PUBKEY).json()
P = int(pk["P"])
Q = int(pk["Q"])
G = int(pk["G"])
Y = int(pk["Y"])
print(f"[1] Q = {str(Q)[:40]}...")


# ── Paso 2: firmar mensajes distintos hasta encontrar r repetido ──────────────
print("\n[2] Buscando colisión en r (k reutilizado)...")

# seen: r -> (raw_bytes_del_mensaje, s)
seen: dict[int, tuple[bytes, int]] = {}
msg1 = msg2 = s1 = s2 = r_col = None

for i in range(1000):
    # El servidor recibe el mensaje en base64, lo decodifica y firma los bytes crudos
    raw = f"msg_{i}".encode()
    b64 = base64.b64encode(raw).decode()
    resp = requests.post(URL_SIGN, files={"message": (None, b64)}).json()
    r = int(resp["r"])
    s = int(resp["s"])

    if r in seen:
        msg2, s2 = raw, s
        msg1, s1 = seen[r]
        r_col = r
        print(f"[2] ¡Colisión en r! tras {i+1} firmas  (i={i})")
        break

    seen[r] = (raw, s)

assert r_col is not None, "No se encontró colisión en r"


# ── Paso 3: recuperar k ───────────────────────────────────────────────────────
h1 = int(hashlib.sha256(msg1).hexdigest(), 16) % Q
h2 = int(hashlib.sha256(msg2).hexdigest(), 16) % Q

# k = (H(m1) - H(m2)) * (s1 - s2)^(-1) mod q
k = (h1 - h2) * pow(s1 - s2, -1, Q) % Q
print(f"\n[3] k recuperado = {str(k)[:40]}...")


# ── Paso 4: recuperar la clave privada x ──────────────────────────────────────
# x = r^(-1) * (k*s1 - H(m1)) mod q
x = pow(r_col, -1, Q) * (k * s1 - h1) % Q
print(f"[4] x recuperado = {str(x)[:40]}...")

# Verificación: g^x mod p debe ser igual a Y
assert pow(G, x, P) == Y, "¡Verificación fallida! x incorrecto."
print("[4] Verificación OK: g^x mod p == Y ✓")


# ── Paso 5: enviar la clave privada ───────────────────────────────────────────
print("\n[5] Enviando clave privada...")
resp = requests.post(URL_ANSWER, files={"private-key": (None, str(x))})
print(f"[5] Código HTTP: {resp.status_code}")
print(f"[5] Respuesta:   {resp.text.strip()}")
