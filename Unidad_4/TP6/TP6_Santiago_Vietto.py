"""
TP6 - Falsificación en modo ECB (Cut-and-Paste Attack)

El servidor crea perfiles: user=EMAIL&id=N&role=user  (AES-128-ECB si encrypted=true)
El email es validado, por lo que no se pueden inyectar bytes de control directamente.

Ataque:
  Email_admin = "AAAAAAAAAA@admin" → perfil = "user=AAAAAAAAAA@admin&id=N_a&role=user"
    Block 2: E("admin&id=N_a&rol")   ← contiene "admin" como inicio del valor de role
    Block 3: E("e=user\x0a*10")      ← padding PKCS7 válido (10 bytes de \x0a)

  Email_align = email de longitud L tal que "user=EMAIL&id=N_b&role=" = k*16 bytes
    prefix_blocks = primeros k bloques del ciphertext

  Forjado = prefix_blocks + block2 + block3
  Descifrado = "user=EMAIL&id=N_b&role=" + "admin&id=N_a&rol" + "e=user\x0a*10"
             = "user=EMAIL&id=N_b&role=admin&id=N_a&role=user"  (PKCS7 válido)

  La query tiene role=admin como primer campo role → ¡Ganaste!
"""

import base64
import requests

EMAIL  = "santiagovietto5@gmail.com"
SERVER = "https://cripto.iua.edu.ar"
B      = 16

def reg(email_to_register: str, encrypted: bool = False) -> str:
    params = {"email": email_to_register}
    if encrypted:
        params["encrypted"] = "true"
    return requests.get(
        f"{SERVER}/ecb-forge/{EMAIL}/register", params=params
    ).text.strip()


# ── Paso 1: obtener bloque "admin..." + bloque de cierre con PKCS7 válido ──────
# Email "AAAAAAAAAA@admin" produce:
#   Block 0: E("user=AAAAAAAAAA@")    (5 + 10 + 1 = 16)
#   Block 1: E("admin&id=N_a&rol")    ← "admin block"
#   Block 2: E("e=user\x0a*10")       ← cierre con PKCS7 válido (10×\x0a)

email_admin = "AAAAAAAAAA@admin" + "\t" * 11  # tabs son ignorados por el servidor
ct_admin    = base64.b64decode(reg(email_admin, encrypted=True))

# Verificar estructura del plain profile
plain_admin = reg(email_admin)
print(f"[1] Perfil admin: {plain_admin!r}")
print(f"[1] Bloques: {len(ct_admin) // B}")

block_admin   = ct_admin[B   : 2*B]  # bloque 1: "admin&id=N_a&rol"
block_closure = ct_admin[2*B : 3*B]  # bloque 2: "e=user\x0a*10"
print(f"[1] Bloque admin  : {block_admin.hex()}")
print(f"[1] Bloque cierre : {block_closure.hex()}")


# ── Paso 2: buscar email cuyo prefix "user=EMAIL&id=N&role=" sea múltiplo de 16 ──
email_align   = None
n_prefix_blks = None

for L in range(8, 48):
    local      = "B" * (L - 4)
    test_email = local + "@B.B"
    if len(test_email) != L:
        continue

    plain = reg(test_email)
    try:
        N = plain.split("&id=")[1].split("&")[0]
    except IndexError:
        continue

    prefix_len = 5 + L + 4 + len(N) + 6
    if prefix_len % B == 0:
        email_align   = test_email
        n_prefix_blks = prefix_len // B
        print(f"\n[2] Email alineado: {email_align!r}  N={N}  "
              f"prefix={prefix_len}B ({n_prefix_blks} bloques)")
        break

assert email_align, "No se encontró email alineado"


# ── Paso 3: obtener bloques del prefix cifrado ────────────────────────────────
ct_align       = base64.b64decode(reg(email_align, encrypted=True))
bloques_prefix = ct_align[: n_prefix_blks * B]
print(f"[3] Bloques prefix: {len(bloques_prefix)}B")


# ── Paso 4: forjar el ciphertext ──────────────────────────────────────────────
# Descifrado resultante:
#   user=EMAIL_align&id=N_align&role=admin&id=N_admin&role=user
# PKCS7: últimos 10 bytes = \x0a × 10 → válido
forjado     = bloques_prefix + block_admin + block_closure
forjado_b64 = base64.b64encode(forjado).decode()
print(f"[4] Ciphertext forjado ({len(forjado)}B): {forjado_b64[:60]}...")


# ── Paso 5: enviar la respuesta ───────────────────────────────────────────────
resp = requests.post(
    f"{SERVER}/ecb-forge/{EMAIL}/answer",
    files={"message": (None, forjado_b64)}
)
print(f"\n[5] Código HTTP: {resp.status_code}")
print(f"[5] Respuesta:   {resp.text.strip()}")
