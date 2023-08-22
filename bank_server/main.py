from fastapi import FastAPI, Depends, HTTPException, Header
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

from base64 import b64encode, b64decode
import base64
import time

app = FastAPI()

# Directory where keys are stored
KEYS_DIR = ""

# Read PEM formatted keys from disk
def load_keys(username):
    with open(KEYS_DIR + "private.pem", "rb") as private_key_file:
        private_key = ECC.import_key(private_key_file.read())
    
    with open(KEYS_DIR + "public.pem", "rb") as public_key_file:
        public_key = ECC.import_key(public_key_file.read())
    
    return private_key, public_key


#Load bank keys and sign RSA key
bank_sign_key=ECC.import_key(open("bank_private.pem", "rb").read())
rsa_key=RSA.import_key(open("bank_rsa_private.pem").read())
rsa_key_export=rsa_key.export_key(format="PEM")

key_hash = SHA512.new(rsa_key_export)

signer = eddsa.new(bank_sign_key, 'rfc8032')
signed_bank_rsa = signer.sign(key_hash)
base64_signed_bank_rsa=b64encode(signed_bank_rsa).decode('utf-8')



@app.get("/get-public-key")
def getPublicKey():
    return {"bank_key" : rsa_key_export, "signature_bank_key":base64_signed_bank_rsa}
    

# Main application entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)