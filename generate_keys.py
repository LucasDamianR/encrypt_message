#!/usr/bin/env python
# coding: utf-8

from Crypto.PublicKey import RSA
import os
import shutil

#########################################################
#                GENERACIÓN DE LA CLAVE                 #
#########################################################

#Generar directorio keys
keys_folder = os.path.abspath('keys')

if os.path.isdir(keys_folder):
# sí existe, borrar el contenido
    shutil.rmtree(keys_folder)
    print('The keys have been cleaned')
    
os.mkdir(keys_folder)

    
# Generar pareja de claves RSA de 2048 bits de longitud
key = RSA.generate(2048)

# Passphrase para encriptar la clave privada
secret_code = "12345"

# Exportamos la clave privada
private_key = key.export_key(passphrase=secret_code)

# Guardamos la clave privada en un fichero
with open(keys_folder+"\\private.pem", "wb") as f:
    f.write(private_key)

# Obtenemos la clave pública
public_key = key.publickey().export_key()

# Guardamos la clave pública en otro fichero
with open(keys_folder+"\\public.pem", "wb") as f:
    f.write(public_key)

