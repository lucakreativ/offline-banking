import requests
import json
import base64
import time

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


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



def sendSymmetricKey(ID):

    session_key=get_random_bytes(16)
    IV=get_random_bytes(16)


    url="http://127.0.0.1:8000/send-symmetric-key"
    recipien_key = RSA.import_key(open("bank_rsa_public.pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipien_key)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv=IV)

    #encrypt + encode session key
    encryptedKey = cipher_rsa.encrypt(session_key)
    b64EncryptedKey = b64encode(encryptedKey).decode("utf-8")

    #encrypt + encode IV
    encryptedIV = cipher_rsa.encrypt(IV)
    b64EncryptedIV = b64encode(encryptedIV).decode("utf-8")


    bytesID=str(ID).encode()
    aesEncryptedID = cipher_aes.encrypt(pad(bytesID, AES.block_size))
    encryptedID = cipher_rsa.encrypt(aesEncryptedID)
    b64EncryptedID = b64encode(encryptedID).decode("utf-8")

    client_sign_key=ECC.import_key(open("client_private.pem", "rb").read())
    signer = eddsa.new(client_sign_key, 'rfc8032')

    unixTime = str(int(time.time()))

    data_hash = SHA512.new(session_key+IV+bytesID+unixTime.encode())

    signed_data = signer.sign(data_hash)
    encrypted_signed_data = cipher_rsa.encrypt(signed_data)
    b64SignedData=b64encode(encrypted_signed_data).decode('utf-8')
    
    response = requests.post(url, json={"encryptedKey" : b64EncryptedKey, "encryptedID" : b64EncryptedID, "encryptedIV": b64EncryptedIV, "encryptedSignedHash" : b64SignedData, "unixTime" : unixTime})



sendSymmetricKey(340985324)