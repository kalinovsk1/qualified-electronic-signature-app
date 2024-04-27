from tkinter import *
from tkinter import filedialog
# TODO: add functions that creating sections in GUI

def open_file_browser():
    filepath = filedialog.askopenfilename(initialdir="/", title="Select a File",
                                          filetypes=(("All files", "*.*"),))
    if filepath:
        file_label.config(text=f"Selected File: {filepath}")

def sign_file():
    # TODO: implement file signing
    x=1

def verify_file():
    # TODO: implement signature verification
    x=1

root = Tk()
root.title("User app")
root.configure(background="lavender")
root.minsize(730, 480)
root.maxsize(730, 480)
root.geometry("730x480+100+100")

# signature section
signature = Frame(root, width=385, height=285, bg='white smoke')
signature.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
signature_title = Label(signature, text="Sign a file", font=("Terminal", 16, "bold"), bg='white smoke')
signature_title.grid(row=0, sticky="ew", padx=100, pady=10)
open_file_button = Button(signature, text="Select a file", command=open_file_browser)
open_file_button.grid(row=2, sticky="ew", padx=100, pady=10)
file_label = Label(signature, text="No File Selected", bg='white smoke')
file_label.grid(row=3, sticky="ew", padx=20)
sign_button = Button(signature, text="SIGN", command=sign_file, bg='thistle')
sign_button.grid(row=4, sticky="ew", padx=100, pady=10)
# TODO: window to enter a PIN

# verification section
verification = Frame(root, width=385, height=285, bg='white smoke')
verification.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
verification_title = Label(verification, text="Verify signature", font=("Terminal", 16, "bold"),  bg='white smoke')
verification_title.grid(row=0, column=0, sticky="ew", padx=70, pady=10)
open_file_button2 = Button(verification, text="Select a file", command=open_file_browser)
open_file_button2.grid(row=1, column=0, sticky="ew", padx=100, pady=10)
file_label2 = Label(verification, text="No File Selected", bg='white smoke')
file_label2.grid(row=2, column=0, sticky="ew", padx=20)
verify_button = Button(verification, text="VERIFY", command=verify_file, bg='thistle')
verify_button.grid(row=3, column=0, sticky="ew", padx=100, pady=10)
# TODO: window to select public key

# message encryption section - user A
encryption = Frame(root, width=385, height=285, bg='white smoke')
encryption.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
encryption_title = Label(encryption, text="Encryption", font=("Terminal", 16, "bold"),  bg='white smoke')
encryption_title.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
T1 = Text(encryption, width=30, height=10)
T1.grid(row=1, column=0, sticky="ew", padx=50, pady=10)
encryption_button = Button(encryption, text="ENCRYPT", bg='thistle')
encryption_button.grid(row=2, column=0, sticky="ew", padx=100, pady=10)

# message decryption section - user B
decryption = Frame(root, width=385, height=285, bg='white smoke')
decryption.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
decryption_title = Label(decryption, text="Decryption", font=("Terminal", 16, "bold"),  bg='white smoke')
decryption_title.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
T2 = Text(decryption, width=30, height=10)
T2.grid(row=1, column=0, sticky="ew", padx=50, pady=10)
decryption_button = Button(decryption, text="DECRYPT", bg='thistle')
decryption_button.grid(row=2, column=0, sticky="ew", padx=100, pady=10)

root.mainloop()
