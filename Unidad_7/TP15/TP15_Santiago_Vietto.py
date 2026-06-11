"""
TP15 - Ataque de broadcast sobre RSA (Håstad's Broadcast Attack)

El servidor cifra el mismo mensaje M con RSA textbook (sin padding) usando e=3
y tres claves públicas distintas (n1, n2, n3):
  c1 = M^3 mod n1
  c2 = M^3 mod n2
  c3 = M^3 mod n3

Como M < ni para todo i, se cumple que M^3 < n1*n2*n3.
El Teorema Chino del Resto permite recuperar x = M^3 mod (n1*n2*n3) = M^3 exacto.
Luego se extrae la raíz cúbica entera para obtener M.
"""

import base64, requests
from math import gcd

EMAIL  = "santiagovietto5@gmail.com"
SERVER = "https://cripto.iua.edu.ar"
URL_CHALLENGE = f"{SERVER}/rsa-broadcast/{EMAIL}/challenge"
URL_ANSWER    = f"{SERVER}/rsa-broadcast/{EMAIL}/answer"


def icbrt(n: int) -> int:
    """Raíz cúbica entera exacta usando Newton en aritmética entera (sin float)."""
    if n == 0:
        return 0
    # Estimación inicial: 2^ceil(bits/3)  — siempre ≥ cbrt(n)
    x = 1 << ((n.bit_length() + 2) // 3)
    # Newton: x ← (2x + n//x²) / 3 — converge a floor(cbrt(n))
    while True:
        x1 = (2 * x + n // (x * x)) // 3
        if x1 >= x:
            break
        x = x1
    # Corrección fina por truncamiento de división entera
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def crt(residues, moduli):
    """
    Teorema Chino del Resto.
    Dado [a1, a2, ..., ak] y [n1, n2, ..., nk] coprimos dos a dos,
    devuelve x tal que x ≡ ai (mod ni) para todo i.
    """
    N = 1
    for ni in moduli:
        N *= ni
    x = 0
    for ai, ni in zip(residues, moduli):
        Ni  = N // ni
        inv = pow(Ni, -1, ni)   # inverso modular (Python 3.8+)
        x  += ai * Ni * inv
    return x % N


# ── Paso 1: obtener 3 pares (ciphertext, n) ───────────────────────────────────
print("[1] Obteniendo 3 desafíos (mismo mensaje, distintas claves)...")
cs, ns = [], []
for i in range(3):
    resp = requests.get(URL_CHALLENGE).json()
    c_bytes = base64.b64decode(resp["ciphertext"])
    c = int.from_bytes(c_bytes, "big")
    n = int(resp["publicKey"]["n"])
    e = int(resp["publicKey"]["e"])
    cs.append(c)
    ns.append(n)
    print(f"  [{i+1}] n = {str(n)[:30]}...,  e = {e}")
    print(f"       c = {str(c)[:30]}...")

assert all(e == 3 for _ in [None]), "El ataque asume e=3"
print()


# ── Paso 2: CRT para recuperar x = M^3 ───────────────────────────────────────
print("[2] Aplicando Teorema Chino del Resto...")
x = crt(cs, ns)
print(f"[2] x = M³ = {str(x)[:40]}... ({x.bit_length()} bits)")


# ── Paso 3: raíz cúbica entera ───────────────────────────────────────────────
print("[3] Calculando raíz cúbica entera...")
M = icbrt(x)
assert M ** 3 == x, f"¡La raíz cúbica no es exacta! M^3 ≠ x"
print(f"[3] M = {str(M)[:40]}...")


# ── Paso 4: convertir M a texto ───────────────────────────────────────────────
m_bytes   = M.to_bytes((M.bit_length() + 7) // 8, "big")
plaintext = m_bytes.decode("ascii")
print(f"\n[4] Texto claro recuperado: {plaintext!r}")


# ── Paso 5: enviar la respuesta ───────────────────────────────────────────────
print("[5] Enviando respuesta...")
resp = requests.post(URL_ANSWER, files={"message": (None, plaintext)})
print(f"[5] Código HTTP: {resp.status_code}")
print(f"[5] Respuesta:   {resp.text.strip()}")
