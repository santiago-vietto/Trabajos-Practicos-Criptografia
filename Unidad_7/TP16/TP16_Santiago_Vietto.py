"""
TP16 - RSA con clave pequeña (256 bits) + PKCS#1 v1.5

Ataque:
  1. Factorizar n de 256 bits. Se prueba en orden:
       a) API de factordb (instantáneo si ya está)
       b) Pollard p-1 con B=2^20 (rápido si p-1 es B-smooth)
       c) Brent-Pollard ρ con gmpy2 (rápido con aritmética de precisión arbitraria nativa)
  2. Con p y q: φ(n) = (p-1)(q-1) y d = e⁻¹ mod φ(n).
  3. Descifrar: M = C^d mod n.
  4. Quitar padding PKCS#1 v1.5: 0x00 || 0x02 || PS || 0x00 || mensaje
"""

import base64
import random
import requests
from math import gcd
import gmpy2

EMAIL  = "santiagovietto5@gmail.com"
SERVER = "https://cripto.iua.edu.ar"
URL_CHALLENGE = f"{SERVER}/rsa-small/{EMAIL}/challenge"
URL_ANSWER    = f"{SERVER}/rsa-small/{EMAIL}/answer"


# ── Algoritmos de factorización ───────────────────────────────────────────────

def factordb(n: int):
    """Intenta factorizar consultando factordb.com."""
    r = requests.get(f"http://factordb.com/api?query={n}", timeout=15).json()
    status = r.get("status", "")
    print(f"  → factordb status: {status}")
    if status == "FF":
        primes = [int(f[0]) for f in r["factors"] if int(f[1]) == 1]
        product = 1
        for p in primes:
            product *= p
        if product == n and len(primes) == 2:
            return primes[0], primes[1]
    return None


def pollard_pm1(n: int, B: int = 1 << 20):
    """Pollard p-1: rápido si p-1 es B-smooth."""
    a = gmpy2.mpz(2)
    # Calcular a = 2^(product of prime powers ≤ B) mod n
    p = 2
    while p <= B:
        if gmpy2.is_prime(p):
            pk = p
            while pk * p <= B:
                pk *= p
            a = gmpy2.powmod(a, pk, n)
        p += 1
    d = gcd(int(a) - 1, n)
    if 1 < d < n:
        return d
    return None


def brent_rho(n: int):
    """Brent's improvement of Pollard's ρ, usando gmpy2 para velocidad."""
    n = gmpy2.mpz(n)
    if n % 2 == 0:
        return 2

    while True:
        x = gmpy2.mpz(random.randint(2, int(n) - 1))
        c = gmpy2.mpz(random.randint(1, int(n) - 1))
        y, r, q, g = x, 1, gmpy2.mpz(1), gmpy2.mpz(1)
        m = gmpy2.mpz(128)

        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = gmpy2.mpz(0)
            while k < r and g == 1:
                ys = y
                for _ in range(int(min(m, r - k))):
                    y = (y * y + c) % n
                    diff = x - y if x >= y else y - x
                    q = q * (diff % n) % n
                g = gmpy2.mpz(gcd(int(q), int(n)))
                k += m
            r *= 2

        if g == n:
            while True:
                ys = (ys * ys + c) % n
                diff = x - ys if x >= ys else ys - x
                g = gmpy2.mpz(gcd(int(diff % n), int(n)))
                if g > 1:
                    break

        if g != n:
            return int(g)


def factorize(n: int):
    """Factoriza n = p*q usando los métodos disponibles."""
    # 1. factordb
    print("  → Consultando factordb...")
    res = factordb(n)
    if res:
        print("  → ¡Encontrado en factordb!")
        return res

    # 2. Pollard p-1
    print("  → Probando Pollard p-1 (B=2^20)...")
    d = pollard_pm1(n)
    if d:
        print(f"  → ¡Factor encontrado con p-1!")
        return d, n // d

    # 3. Brent-Pollard ρ con gmpy2
    print("  → Usando Brent-Pollard ρ con gmpy2 (puede tardar 1-5 min)...")
    while True:
        d = brent_rho(n)
        if 1 < d < n:
            print(f"  → ¡Factor encontrado con Brent-ρ!")
            return d, n // d


# ── Paso 1: obtener el desafío ─────────────────────────────────────────────────
print("[1] Obteniendo desafío...")
data = requests.get(URL_CHALLENGE).json()

C = int.from_bytes(base64.b64decode(data["ciphertext"]), "big")
n = int(data["publicKey"]["n"])
e = int(data["publicKey"]["e"])
k = (n.bit_length() + 7) // 8

print(f"[1] n ({n.bit_length()} bits) = {str(n)[:50]}...")
print(f"[1] e = {e}")


# ── Paso 2: factorizar n ───────────────────────────────────────────────────────
print("\n[2] Factorizando n...")
p, q = factorize(n)
assert p * q == n and p > 1 and q > 1
print(f"[2] p = {p}")
print(f"[2] q = {q}")


# ── Paso 3: clave privada ──────────────────────────────────────────────────────
phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)


# ── Paso 4: descifrar ──────────────────────────────────────────────────────────
M  = pow(C, d, n)
em = M.to_bytes(k, "big")


# ── Paso 5: quitar padding PKCS#1 v1.5 ────────────────────────────────────────
assert em[0] == 0x00 and em[1] == 0x02, f"Padding inesperado: {em[:4].hex()}"
sep       = em.index(0x00, 2)
plaintext = em[sep + 1:].decode("ascii")
print(f"\n[4] Texto claro: {plaintext!r}")


# ── Paso 6: enviar respuesta ───────────────────────────────────────────────────
resp = requests.post(URL_ANSWER, files={"message": (None, plaintext)})
print(f"\n[5] Código HTTP: {resp.status_code}")
print(f"[5] Respuesta:   {resp.text.strip()}")
