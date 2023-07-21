from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa
import tkinter as tk
import bank.bank as bank
import json as js

def create_user_key():
    priv = ECC.generate(curve='ed25519')
    with open('private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))

def check_publ_key(signed_key, bank_path, usr_path):
    with open(bank_path, 'r') as f:
        bank_key = ECC.import_key(f.read())
    with open(usr_path, 'r') as f:
        usr_key = ECC.import_key(f.read())
    usr_hash = SHA512.new(bytes(usr_key.export_key(format='PEM'), 'utf-8'))
    verifier = eddsa.new(bank_key, 'rfc8032')
    try:
        verifier.verify(usr_hash, signed_key)
        print("The key is authentic")
    except ValueError:
        print("The key is not authentic")

def main():
    user_id = bank.get_user_id()


    root = tk.Tk()
    root.title("Offline-Banking")
    root.geometry("350x600")

    label = tk.Label(root, text=user_id)
    label.pack()

    root.mainloop()

main()