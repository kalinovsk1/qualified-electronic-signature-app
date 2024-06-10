#an application that allows you to generate a pair of keys 
#the private key is encrypted with the AES algorithm using the user's password

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import os
import psutil

def find_usb_drive():
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            return partition.mountpoint
    return None

rsa_key = RSA.generate(4096)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

aes_key = input("pin: ").encode()
hashed_pin = hashlib.sha3_256()
hashed_pin.update(aes_key)
hashed_pin = hashed_pin.digest()

cipher = AES.new(hashed_pin, AES.MODE_CBC)
#ciphertext = cipher.encrypt(pad(private_key, AES.block_size))
iv = cipher.iv
ciphertext = iv + cipher.encrypt(pad(private_key, AES.block_size))

dir_path = os.getcwd()
public_key_path = os.path.join(dir_path, "public_key")

if not os.path.exists(public_key_path):
    os.mkdir(public_key_path)

with open(f"{public_key_path}/public_key.bin", "wb") as f:
    f.write(public_key)

usb_path = find_usb_drive()
private_key_path = os.path.join(usb_path, "private_key")

if not os.path.exists(private_key_path):
    os.mkdir(private_key_path)

with open(f"{private_key_path}/encrypted_private_key.bin", "wb") as f:
    f.write(ciphertext)