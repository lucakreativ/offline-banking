from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa

def create_keys():
    priv = ECC.generate(curve='ed25519')
    with open('bank-private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('bank-open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))

def load_public_key():
    with open('bank-open.pem', 'r') as f:
        return ECC.import_key(f.read())

def load_private_key():
    with open('bank-private.pem', 'r') as f:
        return ECC.import_key(f.read())

def load_user_key(dir):
    with open(dir, 'r') as f:
        return ECC.import_key(f.read())

def sign_user_key(dir):
    priv = load_private_key()
    publ = load_public_key()
    usr = load_user_key(dir)
    usr_hash = SHA512.new(bytes(usr.export_key(format='PEM'), 'utf-8'))
    signer = eddsa.new(priv, 'rfc8032')
    signed = signer.sign(usr_hash)
    return signed



print(sign_user_key('../user/open.pem'))