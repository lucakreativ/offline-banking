from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa
import tkinter as tk
import bank.bank as bank
import json as js
import qrcode
import cv2
from qreader import QReader

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

def new_transaction():
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=2,
        border=4,
    )
    qr.add_data(f"OFFLINEBANK||20|7|Nudeln")
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save("qr.png")

def scan():
    qreader = QReader()
    image = cv2.cvtColor(cv2.imread('qr.png'), cv2.COLOR_BGR2RGB)
    code = qreader.detect_and_decode(image=image)[0]
    if code[:13] == "OFFLINEBANK||":
        val, t_id, prod = code[13:].split('|')
        choice_win = tk.Tk()
        tk.font = ("TkDefaultFont", 20)
        label = tk.Label(choice_win, text=f"Do you accept the following transaction?")
        label.pack()
        label = tk.Label(choice_win, text=f"Value: {val}€")
        label.pack()
        label = tk.Label(choice_win, text=f"Product: {prod}")
        label.pack()
        button = tk.Button(choice_win, text=f"Allow", command=lambda: (accept(), choice_win.destroy()))
        button.pack()
        button = tk.Button(choice_win, text=f"Deny", command=lambda: choice_win.destroy())
        button.pack()
        choice_win.mainloop()

def accept():
    with open(data)

def new():
    data = {}

    data["signed"] = bank.sign_user_key(f"../user/open.pem")

    with open('data.json', 'w') as f:
        js.dump(data, f)

def main(new=False):
    if new: new()
    with open('data.json', 'r') as f:
        data = js.load(f)

    root = tk.Tk()
    root.title("Offline-Banking")
    root.geometry("350x600")

    label = tk.Label(root, text=f"Aktueller Kontostand: {data['balance']}€")
    label.pack()
    new_transaction_button = tk.Button(root, text=f"Neue Transaktion", command=new_transaction)
    new_transaction_button.pack()
    scan_button = tk.Button(root, text=f"Scan", command=scan)
    scan_button.pack()

    root.mainloop()


main()