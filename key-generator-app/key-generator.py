#an application that allows you to generate a pair of keys 
#the private key is encrypted with the AES algorithm using the user's password

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

aes_key = input("pin: ").encode()
hashed_pin = hashlib.sha3_256()
hashed_pin.update(aes_key)
hashed_pin = hashed_pin.digest()

cipher = AES.new(hashed_pin, AES.MODE_CBC)
ciphertext = cipher.encrypt(pad(private_key, AES.block_size))

with open("encrypted_private_key.bin", "wb") as f:
    f.write(ciphertext)

with open("public_key.bin", "wb") as f:
    f.write(public_key)