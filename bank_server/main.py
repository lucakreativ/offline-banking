from fastapi import FastAPI, Depends, HTTPException, Header
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from pydantic import BaseModel

from base64 import b64encode, b64decode
import base64
import sqlite3
import os
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


#Load bank keys
bank_sign_key=ECC.import_key(open("bank-private.pem", "rb").read())

rsa_private_key = RSA.import_key(open("bank_rsa_private.pem").read())
cipher_rsa = PKCS1_OAEP.new(rsa_private_key)


#sign process
rsa_key_export=rsa_private_key.export_key(format="PEM")

key_hash = SHA512.new(rsa_key_export)

signer = eddsa.new(bank_sign_key, 'rfc8032')
signed_bank_rsa = signer.sign(key_hash)
base64_signed_bank_rsa=b64encode(signed_bank_rsa).decode('utf-8')



def encryptSymmetricData(data, key, IV=None):
    if IV==None:
        IV=get_random_bytes(16)
    cipher_aes = AES.new(key, AES.MODE_CBC, iv=IV)
    encryptedData = cipher_aes.encrypt(pad(data, AES.block_size))
    b64encData = b64encode(encryptedData).decode("utf-8")
    b64encIV = b64encode(IV).decode("utf-8")
    return (b64encData, b64encIV, IV)
    
def signData(data):
    dataHashed = SHA512.new(data)
    signedHashed = signer.sign(dataHashed)
    signedHashB64 = b64encode(signedHashed).decode("utf-8")
    return signedHashB64

def b64PackageDecoder(dataBlock):
    dataDictionary = {}
    for i in dataBlock:
        try:
            dataDictionary[i[0]] = base64.b64decode(i[1])
        except:
            dataDictionary[i[0]] = i[1]

    return dataDictionary

session_ID_data = {}


@app.get("/get-public-key")
def getPublicKey():
    return {"bank_key" : rsa_key_export, "signature_bank_key":base64_signed_bank_rsa}
    

@app.get("/get-challenge")
def get_random_data():
    length=64
    random_bytes = os.urandom(length)

    connection = sqlite3.connect('database.sqlite3')
    cursor = connection.cursor()
    cursor.execute('''
        INSERT INTO usersChallenges (unix_time, random_data)
        VALUES (?, ?)
    ''', (int(time.time()), random_bytes))

    row_id = cursor.lastrowid


    connection.commit()
    connection.close()

    length=64
    random_bytes = os.urandom(length)
    b64_encoded = base64.b64encode(random_bytes).decode('utf-8')
    return {"random_data": b64_encoded, "id": row_id}



@app.post("/get-challenge-response")
def get_challenge_response(data: dict):
    connection = sqlite3.connect('database.sqlite3')
    cursor = connection.cursor()
    cursor.execute('''
        SELECT publicKey, publicKeyRSA FROM account WHERE customerID=? AND deviceID=?
    ''', (data["customerID"], data["deviceID"]))

    public_key, public_keyRSA = cursor.fetchone()


    connection.commit()


    cursor.execute('''
        SELECT random_data FROM usersChallenges WHERE id=?
    ''', (data["id"],))

    randomData = cursor.fetchone()[0]
    connection.commit()
    connection.close()

    # verify signature
    public_key = ECC.import_key(public_key)
    verifier = eddsa.new(public_key, 'rfc8032')
    
    data_hash = SHA512.new(randomData)
    try:
        verifier.verify(data_hash, b64decode(data["signature"]))
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid signature")
    

    random_key = get_random_bytes(16)
    
    rsa_public_key = RSA.import_key(public_keyRSA)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_random_key = cipher_rsa.encrypt(random_key)
    encrypted_random_key_b64 = b64encode(encrypted_random_key).decode("utf-8")
    signed_random_key = signData(encrypted_random_key)
    return {"random_key": encrypted_random_key_b64, "signed_random_key": signed_random_key}
    


# Main application entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)