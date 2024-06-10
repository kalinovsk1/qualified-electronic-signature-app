#an application that allows you encrypt/decrypt documents, sign documents and verify them
#keys are from key-generator-app

import os
from tkinter import *
from tkinter import filedialog
from functions import *

def open_file_browser(section):
    filepath = filedialog.askopenfilename(initialdir="/", title="Select a File",
                                          filetypes=(("All files", "*.*"),))
    if filepath:
        filename = os.path.basename(filepath)
        name = f"Selected File: {filename}"
        match section:
            case 1:
                file_label.config(text=filepath)
            case 2:
                file_label2.config(text=filepath)
            case 3:
                file_label3.config(text=filepath)
            case 4:
                file_label4.config(text=filepath)


def disk_connected():
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            usb_verification_title.config(text="usb connected")
            return
    usb_verification_title.config(text="usb disconnected")
    

# main, app
root = Tk()
root.title("User app")
root.configure(background="lavender")
root.geometry("730x450")
root.resizable(0, 0)


# usb drive verification section
usb_verification = Frame(root, width = 730, height=40, bg='lavender')
usb_verification.pack(side="top")
usb_verification_title = Label(usb_verification, width=20, height=1, text="usb disconnected",font=("Terminal", 12, "bold"), bg='white smoke', padx=5, pady=5)
usb_verification_title.grid(row=0, column=0, padx=10, pady=10)
usb_verification_button = Button(usb_verification, text="detect", width=10, height=1, font=("Terminal", 11, "bold"), padx=5, pady=5, command=lambda: disk_connected())
usb_verification_button.grid(row=0, column=1)

# functions section
functions_frame = Frame(root, width=730, height=440, bg="lavender")
functions_frame.pack(side="top")

# signature section
signature = Frame(functions_frame, width=325, height=200, bg='white smoke')
signature.grid(row=0, column=0, padx=10, pady=10)
signature_title = Label(signature, text="Sign a file", font=("Terminal", 16, "bold"), bg='white smoke', width=30)
signature_title.pack(side="top", pady=10)
open_file_button = Button(signature, text="Select a file", command=lambda: open_file_browser(1))
open_file_button.pack(side="top", pady=10)
file_label = Label(signature, text="No File Selected", bg='white smoke', wraplength=300)
file_label.pack(side="top")
sign_button = Button(signature, text="SIGN", bg='thistle', command=lambda: pin_window(2, file_label.cget("text")))
sign_button.pack(side="top", pady=10)

# verification section
verification = Frame(functions_frame, width=325, height=200, bg='white smoke')
verification.grid(row=0, column=1, padx=10, pady=10) 
verification_title = Label(verification, text="Verify signature", font=("Terminal", 16, "bold"), bg='white smoke', width=30)
verification_title.pack(side="top", pady=10)
open_file_button2 = Button(verification, text="Select a file", command=lambda: open_file_browser(2))
open_file_button2.pack(side="top", pady=10)
file_label2 = Label(verification, text="No File Selected", bg='white smoke', wraplength=300)
file_label2.pack(side="top")
verify_button = Button(verification, text="VERIFY", command=lambda: verify_file(file_label2.cget("text")), bg='thistle')
verify_button.pack(side="top", pady=10)

# message decryption section - user A
decryption = Frame(functions_frame, width=325, height=200, bg='white smoke')
decryption.grid(row=1, column=0, padx=10, pady=10)
decryption_title = Label(decryption, text="Decryption", font=("Terminal", 16, "bold"),  bg='white smoke', width=30)
decryption_title.pack(side="top", pady=10)
open_file_button4 = Button(decryption, text="Select a file to decrypt", command=lambda: open_file_browser(4))
open_file_button4.pack(side="top", pady=10)
file_label4 = Label(decryption, text="No File Selected", bg='white smoke', wraplength=300)
file_label4.pack(side="top")
decryption_button = Button(decryption, text="DECRYPT", bg='thistle', command=lambda: pin_window(1, file_label4.cget("text")))
decryption_button.pack(side="top", pady=10)

# message encryption section - user B
encryption = Frame(functions_frame, width=325, height=200, bg='white smoke')
encryption.grid(row=1, column=1, padx=10, pady=10)
encryption_title = Label(encryption, text="Encryption", font=("Terminal", 16, "bold"),  bg='white smoke', width=30)
encryption_title.pack(side="top", pady=10)
open_file_button3 = Button(encryption, text="Select a file to encrypt", command=lambda: open_file_browser(3))
open_file_button3.pack(side="top", pady=10)
file_label3 = Label(encryption, text="No File Selected", bg='white smoke', wraplength=300)
file_label3.pack(side="top")
encryption_button = Button(encryption, text="ENCRYPT", bg='thistle', command=lambda: encryption_file(file_label3.cget("text")))
encryption_button.pack(side="top", pady=10)
root.mainloop()