#!/usr/bin/env python
# coding: utf-8
import io
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os

#########################################################
#                     DESCIFRADO                        #
#########################################################

#Directorio keys
keys_folder = os.path.abspath('keys')

#path de archivo encriptado
msj_path = os.path.abspath('msj.crp')

# Emulamos un fichero con nuestra cadena porque el método read facilita
with open(msj_path, "rb") as f:
    enc_data = f.read()
# la división de cada parte de la cadena (datos y clave AES encriptada).
# Podríamos también obtenerlos simplemente mediante slicing de la cadena
data_file = io.BytesIO(enc_data)

# Leemos el archivo con la clave privada

with open(keys_folder+"/private.pem", "rb") as f:
    recipient_key = f.read()

# Cargamos la clave pública (instancia de clase RSA)
key = RSA.importKey(recipient_key,  passphrase="12345")

# Instancia del cifrador asimétrico
cipher_rsa = PKCS1_OAEP.new(key)

# Separamos las distintas partes de la cadena cifrada
enc_aes_key, nonce, tag, ciphertext =    (data_file.read(c) for c in (key.size_in_bytes(), 16, 16, -1))

# Desencriptamos la clave AES mediante la clave privada RSA
aes_key = cipher_rsa.decrypt(enc_aes_key)

# Desencriptamos los datos en si con la clave AES
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Decodificamos la cadena
cadena = data.decode("utf-8")
# Mostrar mensaje descifrado
print(cadena)

