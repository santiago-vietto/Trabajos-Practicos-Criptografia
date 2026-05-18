import base64
import requests

#####################################################################################################

# Datos de conexion con el servidor: URL de servidor y usuario

server = "https://cripto.iua.edu.ar"
email = "santiagovietto5@gmail.com"

#####################################################################################################

# Declaración de funciones:

def get_challenge(email_register, data_base64):
    response = requests.post(
        f"{server}/stream-bitflip/{email}/register",
        files={
            "email": (None, email_register),
            "data": (None, data_base64)
        }
    )

    response.raise_for_status()
    return response.text.strip()

#####################################################################################################

# Paso 1: Conexión con servidor, registro del perfil y obtención del texto cifrado.

email_register = "usuario@example.com"
data = "A" * 15

data_base64 = base64.b64encode(data.encode()).decode()

challenge = get_challenge(email_register, data_base64)

print("\nRespuesta del servidor:")
print(challenge)

#####################################################################################################

# Paso 2: Decodificación del mensaje recibido, y separación del nonce y texto cifrado.

decoded = base64.b64decode(challenge)

nonce = decoded[:16]
ciphertext = bytearray(decoded[16:])

#####################################################################################################

# Paso 3: Construcción del texto claro original y del texto claro objetivo.

plain_original = f"user={email_register};data={data};role=user".encode()
plain_target = f"user={email_register};role=admin;data={data[:-1]}".encode()

print("\nTexto claro original:", plain_original)
print("Longitud:", len(plain_original))

print("\nTexto claro objetivo:", plain_target)
print("Longitud:", len(plain_target))

print("\nLongitud texto cifrado:", len(ciphertext))

assert len(plain_original) == len(plain_target)
assert len(ciphertext) == len(plain_original)

#####################################################################################################

# Paso 4: Aplicación del bit flipping para modificar el texto cifrado.   

for i in range(len(ciphertext)):
    ciphertext[i] = ciphertext[i] ^ plain_original[i] ^ plain_target[i]
    
#####################################################################################################

# Paso 5: Reconstrucción del mensaje modificado con nonce y ciphertext alterado.

new_message = base64.b64encode(nonce + bytes(ciphertext)).decode()

print("\nMensaje modificado:")
print(new_message)

#####################################################################################################

# Paso 6: Envio de la respuesta al servidor.   

response_answer = requests.post(
    f"{server}/stream-bitflip/{email}/answer",
    files={
        "message": (None, new_message)
    }
)

print("\nRespuesta del servidor:")
print(f"Status code: {response_answer.status_code}")
print(response_answer.text)




'''
Procedimiento implementado:

1. El punto de partida es que el servidor usa un cifrado de flujo. En este tipo de cifrado, el texto 
claro se combina con una secuencia cifrante mediante XOR C = P ⊕ K, y para descifrar P = C ⊕ K.
Si se modifica un byte del texto cifrado, se modifica el byte correspondiente del texto claro al 
descifrar. Esto es bit flipping, es decir, una modificación en el texto cifrado produce una modificación 
predecible en el texto claro.

2. Registrar un perfil controlado: Primero nos conectamos al servidor y registramos un perfil usando 
datos elegidos por nosotros. Con esos datos, el servidor construye internamente un perfil de esta forma:

    user=usuario@example.com;data=AAAAAAAAAAAAAAA;role=user

La elección de data = "A" * 15 no es casual, porque nos permite conocer exactamente una parte importante 
del texto claro y además mantener una longitud controlada para luego modificar el mensaje.

3. Obtener el mensaje cifrado del servidor: Se envía el email_register y el data_base64 al endpoint y el
servidor devuelve un mensaje en base64 que contiene nonce || ciphertext. Es decir, primero viene el nonce 
de 16 bytes y después el texto cifrado.

4. Decodificar el mensaje y separar sus partes: Luego el código decodifica la respuesta base64, y despues
separa el resto del mensaje.

    nonce: primeros 16 bytes
    ciphertext: resto del mensaje

El nonce no se modifica. Lo que se modifica es solamente el ciphertext.

5. Reconstruir el texto claro original esperado: Como conocemos los datos que enviamos, podemos reconstruir 
el texto claro que el servidor probablemente cifró. Eso genera:

    user=usuario@example.com;data=AAAAAAAAAAAAAAA;role=user

Este es el perfil original, donde el rol todavía es role=user.

6. Construir el texto claro objetivo: Después el código arma el texto que queremos que aparezca al descifrar,
lo cual genera:

    user=usuario@example.com;role=admin;data=AAAAAAAAAAAAAA

El objetivo es que el mensaje descifrado contenga role=admin. Y para lograrlo, se cambia el orden de los 
campos y se reduce una A. Esto se hace porque el texto original y el texto objetivo deben tener la misma 
longitud. No se puede agrandar el mensaje cifrado; solo se pueden modificar bytes ya existentes.

7. Verificar que las longitudes coincidan: Esto es fundamental. El ataque se hace byte por byte, por lo tanto
el texto original, texto objetivo y texto cifrado deben medir exactamente lo mismo. Si las longitudes no 
coinciden, el bit flipping no puede aplicarse correctamente.

8. Aplicar el bit flipping: Esta es la parte central, donde la logica es:

    ciphertext_modificado = ciphertext_original ⊕ plain_original ⊕ plain_target

Esto funciona porque:

    ciphertext_original = plain_original ⊕ keystream

Entonces:

    ciphertext_modificado = ciphertext_original ⊕ plain_original ⊕ plain_target

Al reemplazar:

    ciphertext_modificado = plain_original ⊕ keystream ⊕ plain_original ⊕ plain_target

Como:

    plain_original ⊕ plain_original = 0

queda:

    ciphertext_modificado = keystream ⊕ plain_target

Por lo tanto, cuando el servidor descifre:

    ciphertext_modificado ⊕ keystream = plain_target

verá un perfil que contiene role=admin.

9. Reconstruir el mensaje modificado: Una vez alterado el ciphertext, el código vuelve a unirlo con el 
mismo nonce. El nuevo mensaje tiene la misma estructura que esperaba el servidor:

    nonce || ciphertext_modificado

Luego se codifica en base64 porque el endpoint del servidor espera recibir el mensaje en ese formato.


'''
