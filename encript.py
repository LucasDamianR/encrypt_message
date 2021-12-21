#!/usr/bin/env python
# coding: utf-8

import io
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os

#########################################################
#                        CIFRADO                        #
#########################################################

# Cadena UTF-8 a encriptar
cadena = input('Mensaje a encriptar: ')

# Trabajamos con bytes, codifcamos la cadena.
bin_data = cadena.encode("utf-8")

#Generar directorio keys
keys_folder = os.path.abspath('keys')

# Leemos el archivo con la clave publica
with open(keys_folder+"/public.pem", "rb") as f:
    recipient_key = f.read()

# Cargamos la clave pública (instancia de clase RSA)
key = RSA.importKey(recipient_key)

# Instancia del cifrador asimétrico
cipher_rsa = PKCS1_OAEP.new(key)

# Generamos una clave para el cifrado simétrico
aes_key = get_random_bytes(16)

# Encriptamos la clave del cifrado simétrico con la clave pública RSA
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Encriptamos los datos mediante cifrado simétrico (AES en este caso)
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(bin_data)

# Concatenamos la clave simétrica cifrada a los datoscifrados con ella
enc_data = b"".join((enc_aes_key, cipher_aes.nonce, tag, ciphertext))

msj_path = os.path.abspath('msj.crp')
with open(msj_path, "wb") as f:
    f.write(enc_data)
    
print(enc_data)