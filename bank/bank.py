from Crypto.PublicKey import ECC


def create_keys():
    priv = ECC.generate(curve='ed25519')
    with open('bank-private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('bank-open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))


def load_public_key():
    with open('bank-open.pem', 'r') as f:
        ECC.import_key(f.read())


def load_private_key():
    with open('bank-private.pem', 'r') as f:
        ECC.import_key(f.read())
