import requests

#####################################################################################################

# Datos de conexion con el servidor: URL de servidor y usuario

server = "https://cripto.iua.edu.ar"
email = "santiagovietto5@gmail.com"

# Constantes del generador Java: Multiplicador de Java, Incremento, y mascara.

MULTIPLIER = 0x5DEECE66D
ADDEND = 0xB
MASK = (1 << 48) - 1

#####################################################################################################

# Declaracion de funciones:

def get_challenge():
    response = requests.get(f"{server}/javarand/{email}/challenge")
    response.raise_for_status()
    return int(response.text)


def to_unsigned_32(value):
    return value & 0xffffffff


def next_seed(seed):
    return (seed * MULTIPLIER + ADDEND) & MASK


def to_signed_32(value):
    if value >= 2**31:
        return value - 2**32
    return value


#####################################################################################################

# Paso 1: Conexion con servidor y solicitud de dos valores aleatorios consecutivos.

value_1 = get_challenge()
value_2 = get_challenge()

print("\nPrimer valor entregado por Java:", value_1)
print("Segundo valor entregado por Java:", value_2)

#####################################################################################################

# Paso 2: Conversion de valores obtenidos a unsigned. 

value_1_unsigned = to_unsigned_32(value_1)
value_2_unsigned = to_unsigned_32(value_2)

print("\nPrimer valor sin signo:", value_1_unsigned)
print("Segundo valor sin signo:", value_2_unsigned)

#####################################################################################################

# Paso 3: Obtencion del estado del segundo valor.

state_after_first = None

for low_bits in range(1 << 16):
    candidate_seed = (value_1_unsigned << 16) | low_bits

    next_candidate_seed = next_seed(candidate_seed)
    candidate_output = next_candidate_seed >> 16

    if candidate_output == value_2_unsigned:
        state_after_first = next_candidate_seed
        break

if state_after_first is None:
    raise Exception("No se pudo recuperar el estado interno.")

print("\nEstado/semilla recuperada del segundo valor:", state_after_first)

#####################################################################################################

# PAso 4: Prediccion del proximo numero.

next_state = next_seed(state_after_first)
predicted_value_unsigned = next_state >> 16
predicted_value_signed = to_signed_32(predicted_value_unsigned)

print("\nPredicción:", predicted_value_signed)

#####################################################################################################

# Paso 5: Envio de la respuesta al servidor.

response_answer = requests.post(
    f"{server}/javarand/{email}/answer",
    files={
        "number": str(predicted_value_signed).encode("ascii")
    }
)

print("\nRespuesta del servidor:")
print(f"Status code: {response_answer.status_code}")
print(response_answer.text)

