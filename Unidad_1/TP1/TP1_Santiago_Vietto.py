import base64
import requests

##################################################################################

# Paso 1: Conexion con servidor, solicitud de desafio y decodificacion Base64.

email = "santiagovietto5@gmail.com"
known_plaintext = email.encode("ascii")

server = "https://cripto.iua.edu.ar"
url_challenge = f'{server}/md5crypt/{email}/challenge'

response = requests.get(url_challenge)
    
challenge = response.content

print("\nRespuesta servidor:")
print(challenge.decode('ascii'))

ciphertext = base64.b64decode(challenge)

#####################################################################################################

# Paso 2: Eliminacion de clave auxiliar interna y reduccion del texto cirfado.

reduced_ciphertext = b""

for i in range(0, len(ciphertext), 2):
    byte_par = ciphertext[i]
    byte_impar = ciphertext[i + 1]

    resultado = byte_par ^ byte_impar

    reduced_ciphertext += bytes([resultado])

print("\nCantidad de bytes del texto cifrado original:", len(ciphertext))
print("Cantidad de bytes del texto cifrado reducido:", len(reduced_ciphertext))

#####################################################################################################

# Paso 3: Obtencion de los posibles bytes validos de la clave reducida.

hex_digits = b"0123456789abcdef"
valid_key_bytes = set()

for a in hex_digits:
    for b in hex_digits:
        valid_key_bytes.add(a ^ b)
        
print("\nValores de bytes validos: ", valid_key_bytes)

#####################################################################################################

# Paso 4: Obtencion de la clave reducida y decifrado del texto claro.

key_len = 16
mensaje = None

for offset in range(0, len(reduced_ciphertext) - len(known_plaintext)):
    
    posible_clave = {}

    for i in range(len(known_plaintext)):
        
        posicion_clave = (offset + i) % key_len
        valor_clave = reduced_ciphertext[offset + i] ^ known_plaintext[i]

        if valor_clave not in valid_key_bytes:
            break

        if posicion_clave in posible_clave and posible_clave[posicion_clave] != valor_clave:
            break

        posible_clave[posicion_clave] = valor_clave

    if len(posible_clave) == key_len:
        
        key = bytearray(b"\x00" * key_len)

        for posicion, valor in posible_clave.items():
            key[posicion] = valor

        key = bytes(key)

        plaintext = b""

        for j in range(len(reduced_ciphertext)):
            plaintext += bytes([reduced_ciphertext[j] ^ key[j % key_len]])

        mensaje = plaintext.decode("ascii", errors="replace")

        print("\nOffset encontrado:", offset)
        print("Clave encontrada:", key)

        print("\nMensaje descifrado:")
        print(mensaje)

        break


if mensaje is None:
    print("\nNo se pudo descifrar el mensaje.")
    exit()

#####################################################################################################

# Paso 5: Envio de la respuesta al servidor.

answer_url = f"{server}/md5crypt/{email}/answer"

response_answer = requests.post(
    answer_url,
    files={
        "message": ("message.txt", mensaje, "text/plain")
    }
)

print("\nRespuesta del servidor:")
print("Código:", response_answer.status_code)
print(response_answer.text)


