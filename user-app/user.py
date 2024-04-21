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
root.minsize(800, 560)
root.maxsize(800, 560)
root.geometry("800x560+100+100")

# signature section
signature = Frame(root, width=380, height=350, bg='white smoke')
signature.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
signature_title = Label(signature, text="Sign a file", font=("Arial", 16))
signature_title.grid(row=0, column=1, sticky="ew", padx=120)
open_file_button = Button(signature, text="Select a file", command=open_file_browser)
open_file_button.grid(row=1, column=1, sticky="ew", padx=20, pady=10)
file_label = Label(signature, text="No File Selected", bg='white smoke')
file_label.grid(row=2, column=1, sticky="ew", padx=20)
sign_button = Button(signature, text="Sign", command=sign_file)
sign_button.grid(row=3, column=1, sticky="ew", padx=20, pady=30)
# TODO: window to enter a PIN

# verification section
verification = Frame(root, width=380, height=350, bg='white smoke')
verification.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
verification_title = Label(verification, text="Verify signature", font=("Arial", 16))
verification_title.grid(row=0, column=0, sticky="ew", padx=120)
open_file_button2 = Button(verification, text="Select a file", command=open_file_browser)
open_file_button2.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
file_label2 = Label(verification, text="No File Selected", bg='white smoke')
file_label2.grid(row=2, column=0, sticky="ew", padx=20)
verify_button = Button(verification, text="Sign", command=verify_file)
verify_button.grid(row=3, column=0, sticky="ew", padx=20, pady=30)
# TODO: window to select public key

# message encryption/decryption section
message = Frame(root, width=780, height=350, bg='white smoke')
message.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
message_title = Label(message, text="Encryption / Decryption", font=("Arial", 16))
message_title.grid(row=0, column=0, sticky="ew", padx=120)
T = Text(message, width=90, height=10)
T.grid(row=1, column=0, sticky="ew", padx=20, pady=30)
encryption_button = Button(message, text="encrypt")
encryption_button.grid(row=2, column=0, sticky="ew", padx=20,  pady=5)
decryption_button = Button(message, text="decrypt")
decryption_button.grid(row=3, column=0, sticky="ew", padx=20, pady=10)

root.mainloop()
