import requests
import json
import base64
import time

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

from base64 import b64encode, b64decode

#tests if signature of RSA public key is authentic
def test_get_public_key():
    url = "http://127.0.0.1:8000/get-public-key"


    response=requests.get(url)
    data=json.loads(response.text)

    bank_key=data["bank_key"]
    signature_bank_key=b64decode(data["signature_bank_key"])
    print(bank_key)
    print(signature_bank_key)
    bank_key=RSA.import_key(bank_key).export_key(format="PEM")

    key_hash = SHA512.new(bank_key)


    public_key = ECC.import_key(open("bank_open.pem", "rb").read())

    verifier = eddsa.new(public_key, 'rfc8032')
    try:
        verifier.verify(key_hash, signature_bank_key)
        
        print("The key is authentic")
    except ValueError:
        print("The key is not authentic")

