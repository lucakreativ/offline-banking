import qr_working_example.bank.bank as bank
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA512
from Crypto.Signature import eddsa

bank.create_keys()

def create_user_key():
    priv = ECC.generate(curve='ed25519')
    with open('private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))


create_user_key()
with open("signedMessage.txt", "wb") as f:
    f.write(bank.sign_user_key("open.pem", 546))
