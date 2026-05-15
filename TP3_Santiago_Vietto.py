import base64
import hashlib
import requests
from email.utils import parsedate_to_datetime
from datetime import timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

#####################################################################################################

# Datos de conexion con el servidor: URL de servidor y usuario

server = "https://cripto.iua.edu.ar"
email = "santiagovietto5@gmail.com"

#####################################################################################################

# Declaracion de funciones:

def get_challenge():
    response = requests.get(f"{server}/timerand/{email}/challenge")
    response.raise_for_status()
    return response.text


def separate_challenge(challenge):

    lines = challenge.splitlines()

    date = None
    body_base64 = []
    reading_body = False

    for line in lines:
        if line.startswith("Date:"):
            date = line.replace("Date:", "").strip()

        if line.strip() == "":
            reading_body = True
            continue

        if reading_body:
            body_base64.append(line.strip())

    if date is None:
        raise Exception("No se encontró la fecha en el challenge")

    if not body_base64:
        raise Exception("No se encontró el cuerpo base64 del challenge")

    return date, "".join(body_base64)


def generate_key(timestamp_microseconds):

    seed = timestamp_microseconds.to_bytes(8, byteorder="big")
    key = hashlib.md5(seed).digest()

    return key


def decipher(key, iv, ciphertext):

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)

    text_without_padding = unpad(decrypted_text, AES.block_size)

    return text_without_padding


#####################################################################################################

# Paso 1: Conexion con servidor, solicitud de desafio y extraccion de fecha y Base64.

challenge = get_challenge()

date, body_base64 = separate_challenge(challenge)
    
print("\nRespuesta servidor:")
print(challenge)

######################################################################################################

# Paso 2: Conversión de la fecha del encabezado a timestamp Unix.

formated_date = parsedate_to_datetime(date)

if formated_date.tzinfo is None:
    formated_date = formated_date.replace(tzinfo=timezone.utc)

timestamp_seconds = int(formated_date.timestamp())
timestamp_microseconds_base = timestamp_seconds * 1000000

print("Fecha del encabezado:", date)
print("Timestamp segundos:", timestamp_seconds)
print("Timestamp microsegundos inicial:", timestamp_microseconds_base)


#####################################################################################################

# Paso 3: Decodificación del cuerpo Base64 y separación de sus partes.

data = base64.b64decode(body_base64)

encrypted_symmetric_key = data[:128]
iv = data[128:144]
ciphertext = data[144:]

print("\nTamaño total del cuerpo Base64:", len(data), "bytes")
print("Tamaño de clave simétrica cifrada:", len(encrypted_symmetric_key), "bytes")
print("Tamaño de IV:", len(iv), "bytes")
print("Tamaño del texto cifrado:", len(ciphertext), "bytes")

#####################################################################################################

# Paso 4: Fuerza bruta sobre los microsegundos posibles, generacion de claves y decifrado.

plaintext = None

for microsecond in range(1000000):
    timestamp_microseconds = timestamp_microseconds_base + microsecond
    key = generate_key(timestamp_microseconds)

    try:
        plaintext_bytes = decipher(key, iv, ciphertext)
    except ValueError:
        continue

    try:
        plaintext = plaintext_bytes.decode("ascii")
    except UnicodeDecodeError:
        continue

    print("\nClave encontrada:", key)
    print("Microsegundo:", microsecond)
    print("Timestamp en microsegundos:", timestamp_microseconds)
    
    print("\nMensaje claro:")
    print(plaintext)

    break

if plaintext is None:
    raise Exception("No se encontro la clave correcta")

message = plaintext

#####################################################################################################

# Paso : Envio de la respuesta al servidor.

response_answer = requests.post(
    f"{server}/timerand/{email}/answer",
    files={
        "message": (None, message)
    }
)

print("\nRespuesta del servidor:")
print(f"Status code: {response_answer.status_code}")
print(response_answer.text)

