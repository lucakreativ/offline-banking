from Crypto.PublicKey import ECC

def create_bank_key():
    priv = ECC.generate(curve='ed25519')
    with open('bank-key/bank-private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('bank-key/bank-open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))

def create_user_key():
    priv = ECC.generate(curve='ed25519')
    with open('usr-key/private.pem', 'wt') as f:
        f.write(priv.export_key(format='PEM'))

    opn = priv.public_key()
    with open('usr-key/open.pem', 'wt') as f:
        f.write(opn.export_key(format='PEM'))