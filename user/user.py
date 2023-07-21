from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa

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

check_publ_key(b"mF\x9a\xe3\x1a\xab3/K\xa3\xf1\xe0\xc9y\x9c\x8c!\xddFB\xeb`\x00)\xd9BJ\xb7\x18\xc8o\xa7\x15\x83(\x85\x92^\x84\\\x883k\x10\x18f\xca\xea\xe8\xe6~\x1d\x16\x88\x83'\xcd\xbb!\xcf\xfc\xb4\x15\t", '../bank/bank-open.pem', "open.pem")