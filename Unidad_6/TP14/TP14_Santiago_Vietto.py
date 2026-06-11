import re
import requests
import urllib.parse

#####################################################################################################

# Datos de conexion con el servidor
server     = "https://cripto.iua.edu.ar"
email      = "santiagovietto5@gmail.com"
BLOCK_SIZE = 16

#####################################################################################################

# Declaracion de funciones:

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def url_encode_forged(data: bytes) -> str:
    # Mantener &, = y chars alfanumericos seguros; encodear todo lo demas (incluye <, >, #, espacio)
    safe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~&=@'
    return urllib.parse.quote(data, safe=safe)

#####################################################################################################

# Paso 1: Obtener el desafio del servidor.
#
# El servidor devuelve una query string de la forma:
#   from=...&email=monto&comment=...&mac=<hex>
# El MAC se calcula como CBC-MAC del mensaje sin el campo &mac=...

print("=" * 80)
print("Paso 1: Obteniendo el desafio del servidor...")

r = requests.get(f"{server}/cbc-mac/{email}/challenge")
challenge_qs = r.text.strip()
print(f"  Desafio recibido: {challenge_qs}")

#####################################################################################################

# Paso 2: Parsear el desafio — separar el mensaje M y el tag T.

print("\nPaso 2: Parseando el desafio...")

mac_match = re.search(r'&mac=([0-9a-fA-F]+)', challenge_qs)
mac_hex   = mac_match.group(1)
T         = bytes.fromhex(mac_hex)
M_str     = challenge_qs[: mac_match.start()]   # query string sin &mac=...
M         = M_str.encode('utf-8')

print(f"  Mensaje M ({len(M)} bytes): {M}")
print(f"  Tag T: {mac_hex}")

#####################################################################################################

# Paso 3: Aplicar padding PKCS7 a M y dividirlo en bloques.
#
# CBC-MAC requiere que el mensaje sea multiplo de 16 bytes.
# Con PKCS7, si faltan k bytes para completar el bloque, se agregan k bytes de valor k.

print("\nPaso 3: Aplicando padding PKCS7 a M...")

M_padded = pkcs7_pad(M, BLOCK_SIZE)
bloques  = [M_padded[i:i+BLOCK_SIZE] for i in range(0, len(M_padded), BLOCK_SIZE)]

print(f"  Longitud M padded: {len(M_padded)} bytes ({len(bloques)} bloques)")
for i, b in enumerate(bloques):
    print(f"  Bloque {i+1}: {b}")

#####################################################################################################

# Paso 4: Construir la extension para el ataque de longitud CBC-MAC.
#
# Dado M con tag T = CBC-MAC(M), podemos forjar:
#   M'' = M_padded || (M_1 XOR T) || M_2 || ... || M_n
#
# Al procesar M_padded el estado CBC es T. Luego:
#   AES_K(T XOR (M_1 XOR T)) = AES_K(M_1)  ← mismo inicio que CBC-MAC de M
#   ...hasta M_n → estado = T nuevamente
#
# Por lo tanto CBC-MAC(M'') = T (mismo tag que M).

print("\nPaso 4: Construyendo la extension del ataque CBC-MAC...")

M1_xor_T = xor_bytes(bloques[0], T)
extension = M1_xor_T + b''.join(bloques[1:])   # 80 bytes = igual longitud que M_padded

print(f"  M_1 XOR T: {M1_xor_T.hex()}")
print(f"  Longitud extension: {len(extension)} bytes")

#####################################################################################################

# Paso 5: Determinar cuantas extensiones se necesitan para superar $10.000.
#
# El mensaje original transfiere $1000 a {email}.
# Cada extension agrega otra copia de M_2..M_n que incluye el campo email=1000.
# Con N_ext extensiones el total sera (1 + N_ext) * 1000.
# Para superar $10.000 necesitamos al menos 10 extensiones (total = $11.000).

print("\nPaso 5: Calculando el numero de extensiones necesarias...")

monto_unitario  = 1000
objetivo        = 10_000
num_extensiones = (objetivo // monto_unitario)   # 10 extensiones → $11.000 total
total_previsto  = (1 + num_extensiones) * monto_unitario

print(f"  Monto unitario por copia:  ${monto_unitario}")
print(f"  Extensiones a agregar:     {num_extensiones}")
print(f"  Monto total previsto:      ${total_previsto}")

#####################################################################################################

# Paso 6: Construir el mensaje falsificado M'' y su query string URL-encodeada.
#
# M_completo = M_padded || extension × num_extensiones  (880 bytes, multiplo de 16)
# CBC-MAC(M_completo) = T.
#
# El servidor aplica PKCS7 a los bytes que recibe antes de calcular el MAC.
# Si enviamos los 880 bytes tal cual, el servidor los paddearia a 896 bytes (\x10×16)
# y obtendria un MAC diferente.
#
# Solucion: enviar M_completo SIN los ultimos pad_len bytes del padding de M_padded.
# El servidor los restituye con PKCS7, reconstruyendo exactamente M_completo.
#
# (M_padded || ext × k)[:-pad_len] tiene 875 bytes (no multiplo de 16).
# PKCS7 agrega \x05×5 → 880 bytes = M_padded || ext × k → CBC-MAC = T ✓

print("\nPaso 6: Construyendo la query string falsificada...")

pad_len      = BLOCK_SIZE - (len(M) % BLOCK_SIZE)   # 5 bytes para M de 75 bytes
M_forjado    = (M_padded + extension * num_extensiones)[:-pad_len]
qs_encodeada = url_encode_forged(M_forjado)
qs_con_mac   = qs_encodeada + f"&mac={mac_hex}"

print(f"  pad_len original de M:     {pad_len} bytes")
print(f"  Longitud M_forjado:        {len(M_forjado)} bytes (se envian sin los ultimos {pad_len} bytes de padding)")
print(f"  Longitud con padding PKCS7 que vera el servidor: {len(M_forjado) + pad_len} bytes")
print(f"  Query string (primeros 120 chars): {qs_con_mac[:120]}...")

#####################################################################################################

# Paso 7: Enviar la respuesta al servidor.

print("\nPaso 7: Enviando query string falsificada al servidor...")

url_respuesta = f"{server}/cbc-mac/{email}/answer?{qs_con_mac}"
resp = requests.get(url_respuesta)

print(f"  Status code: {resp.status_code}")
print(f"  Respuesta:   {resp.text.strip()}")
print("=" * 80)
