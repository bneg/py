#!/usr/bin/python
# Requires Crypto
# Author: @beyondnegative / bneg
#
# About:
# Encrypt / Decrypt using the Blowfish Algorithm
# Possibly a way to do this with openssl on the CLI
# openssl enc -base64 -e -bf-bc -in <infile> -out <outfile> -kfile <passphrase file>
#
# Assumptions:
#   Padding " " whitespace
#   MODE: MODE_ECB

import binascii
from Crypto.Cipher import Blowfish

INPUT_SIZE = 8
key = 'somekey' # Secret key for decryption

# Padding to ensure 8 byte blocks
def pad_string(str):
    new_str = str
    pad_chars = INPUT_SIZE - (len(str) % INPUT_SIZE)

    if pad_chars != 0 and pad_chars != 8:
        for x in range(pad_chars):
            new_str += " "

    return new_str

plaintext = "p@ssw0rd"

crypt_obj = Blowfish.new(key, Blowfish.MODE_ECB)
ciphertext = crypt_obj.encrypt(pad_string(plaintext))

print "\tPlaintext password: " + plaintext
print "\tBlowfish cyphertext: " + binascii.b2a_hex(ciphertext).upper()
print "\tDecrypted back to plaintext: " + crypt_obj.decrypt(ciphertext)

