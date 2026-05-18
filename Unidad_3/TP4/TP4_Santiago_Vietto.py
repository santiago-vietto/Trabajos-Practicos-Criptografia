import base64
import requests

#####################################################################################################

# Datos de conexion con el servidor: URL de servidor y usuario

server = "https://cripto.iua.edu.ar"
email = "santiagovietto5@gmail.com"

#####################################################################################################

# Declaración de funciones:

def get_challenge():
    response = requests.get(f"{server}/stream/{email}/challenge")
    response.raise_for_status()
    return response.text


def separate_challenge(challenge):
    lines = challenge.strip().splitlines()
    ciphertexts = [base64.b64decode(line) for line in lines]
    return ciphertexts


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def is_printable_ascii(data):
    return all(33 <= byte <= 126 for byte in data)


def is_repeated_character(data):
    return len(set(data)) == 1 and is_printable_ascii(data)


def is_even_decimal_number(data):
    if not data:
        return False

    if not all(48 <= byte <= 57 for byte in data):
        return False

    return data[-1] in [
        ord("0"),
        ord("2"),
        ord("4"),
        ord("6"),
        ord("8")
    ]

#####################################################################################################

# Paso 1: Conexion con servidor, solicitud de desafio y extraccion de textos cifrados.

challenge = get_challenge()

ciphertexts = separate_challenge(challenge)

print("\nRespuesta del servidor:")
print(challenge)

print("Textos cifrados recibidos:", len(ciphertexts))
print("Longitud:", len(ciphertexts[0]))

#####################################################################################################

# Paso 2: Buscar la secuencia cifrante repetida.

keystream_found = None

for base_index, base_ciphertext in enumerate(ciphertexts):

    for character in range(33, 127):

        repeated_plaintext = bytes([character]) * len(base_ciphertext)

        candidate_keystream = xor_bytes(base_ciphertext, repeated_plaintext)

        decrypted_candidates = []

        for i, ciphertext in enumerate(ciphertexts):
            plaintext = xor_bytes(ciphertext, candidate_keystream)

            if is_printable_ascii(plaintext):
                decrypted_candidates.append((i, plaintext))

        repeated_plaintexts = []
        even_decimal_plaintexts = []

        for i, plaintext in decrypted_candidates:
            if is_repeated_character(plaintext):
                repeated_plaintexts.append((i, plaintext))

            if is_even_decimal_number(plaintext):
                even_decimal_plaintexts.append((i, plaintext))

        if len(repeated_plaintexts) >= 2 and len(even_decimal_plaintexts) >= 1:

            repeated_indexes = {i for i, _ in repeated_plaintexts}
            decimal_indexes = {i for i, _ in even_decimal_plaintexts}

            if len(repeated_indexes | decimal_indexes) >= 3:

                keystream_found = candidate_keystream

                print("\nKeystream encontrada:", keystream_found)
                
                print("\nTexto base:", base_index)
                print("Carácter supuesto:", chr(character))
                
                print("\nTextos descifrados candidatos:")
                for i, plaintext in decrypted_candidates:
                    print(f"{i}: {plaintext.decode()}")

                break

    if keystream_found is not None:
        break


if keystream_found is None:
    print("No se encontró la keystream.")
else:
    keystream_base64 = base64.b64encode(keystream_found).decode()

    print("\nKeystream en base64:", keystream_base64)
    
#####################################################################################################

# Paso 5: Envio de la respuesta al servidor.   
    
response_answer = requests.post(
    f"{server}/stream/{email}/answer", 
    files={
        "keystream": (None, keystream_base64)
    }
)

print("\nRespuesta del servidor:")
print(f"Status code: {response_answer.status_code}")
print(response_answer.text)