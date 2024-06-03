import os
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import psutil

def find_usb_drive():
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            return partition.mountpoint
    return None


def public_key_path():
    try:
        file = os.path.join("..", "key-generator-app", "public_key", "public_key.bin")
        with open(file, "rb") as f:
            public_key = RSA.import_key(f.read())
        return public_key
    
    except Exception as e:
        messagebox.showerror("Error", "Failure to read public key")
        return None


def pin_window(section, file):
    def verify_pin(pin):
        # load key from pendrive
        usb_path = find_usb_drive()
        key_path = os.path.join(usb_path, "private_key", "encrypted_private_key.bin")
        with open(key_path, "rb") as f:
            key = f.read()
        #check PIN
        try:
            x = pin.encode()
            decrypted_private_key = decrypt_private_key(key, x)
            messagebox.showinfo("Success", "Valid PIN")
            # TODO: decryption
            if section == 1:
                decryption(file ,decrypted_private_key)
            # TODO: sign
            if section == 2:
                sign_file()
        except ValueError:
            messagebox.showerror("Error", "Invalid PIN")
        pin_window.destroy()

    #window
    pin_window = Tk()
    pin_window.title("PIN")
    pin_window.configure(background="lavender")
    pin_window.minsize(180, 100)
    pin_window.maxsize(180, 100)
    pin_window.geometry("180x100+300+300")
    label_pin = Label(pin_window, text="Enter a PIN to your private key:")
    label_pin.grid(row=0, sticky="ew", pady=5, padx=10)
    pin_entry = Entry(pin_window, show="*")
    pin_entry.grid(row=1, sticky="ew", pady=5, padx=10)
    pin_button = Button(pin_window, text="Submit", command=lambda: verify_pin(pin_entry.get()))
    pin_button.grid(row=2, sticky="ew", pady=5, padx=10)
    pin_window.mainloop()


def decrypt_private_key(key, PIN):
    iv = key[:AES.block_size]
    encrypted_key = key[AES.block_size:]
    hashed_pin = hashlib.sha3_256()
    hashed_pin.update(PIN)
    hashed_pin = hashed_pin.digest()
    cipher = AES.new(hashed_pin, AES.MODE_CBC, iv)
    decrypted_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
    return decrypted_key


def sign_file():
    # TODO: implement file signing
    x=1


def verify_file():
    # TODO: implement signature verification
    x=1


def encryption_file(file):
    try:
        file = file.replace('/', '//')
        file_name, file_extension = os.path.splitext(file)
        encrypted_file_path = f"{file_name}_encrypted{file_extension}"
        key = public_key_path()
        cipher = PKCS1_OAEP.new(key)
        # smaller block encryption 
        with open(file, 'rb') as f:
            while True:
                block = f.read(128)
                if not block:
                    break    
                cipherfile = cipher.encrypt(block)
                # save encrypted file
                with open(encrypted_file_path, 'ab') as ff:
                    ff.write(cipherfile)
        messagebox.showinfo("Success", "File successfully encrypted")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")


def decryption(file, key):
    try:
        file = file.replace('/', '//')
        file_name, file_extension = os.path.splitext(file)
        decrypted_file_path = f"{file_name}_decrypted{file_extension}"
        private_key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(private_key)
        
        with open(file, 'rb') as f:
            with open(decrypted_file_path, 'wb') as df:
                while True:
                    block = f.read(256)
                    if not block:
                        break
                    decrypted_block = cipher.decrypt(block)
                    df.write(decrypted_block)
        
        messagebox.showinfo("Success", "File successfully decrypted")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")