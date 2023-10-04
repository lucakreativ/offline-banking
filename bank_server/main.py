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
bank_sign_key=ECC.import_key(open("bank_private.pem", "rb").read())
rsa_key=RSA.import_key(open("bank_rsa_private.pem").read())

rsa_private_key = RSA.import_key(open("bank_rsa_private.pem").read())
cipher_rsa = PKCS1_OAEP.new(rsa_private_key)


#sign process
rsa_key_export=rsa_key.export_key(format="PEM")

key_hash = SHA512.new(rsa_key_export)

signer = eddsa.new(bank_sign_key, 'rfc8032')
signed_bank_rsa = signer.sign(key_hash)
base64_signed_bank_rsa=b64encode(signed_bank_rsa).decode('utf-8')


class encryptedSendSymmetricKey(BaseModel):
    encryptedKey: str
    encryptedID: str
    encryptedIV: str
    unixTime: str
    encryptedSignedHash: str

def encryptSymmetricData(data, key, IV=None):
    if IV==None:
        IV=get_random_bytes(16)
    cipher_aes = AES.new(key, AES.MODE_CBC, iv=IV)
    encryptedData = cipher_aes.encrypt(pad(data, AES.block_size))
    b64encData = b64encode(encryptedData).decode("utf-8")
    b64encIV = b64encode(IV).decode("utf-8")
    return (b64encData, b64encIV)
    

session_ID_data = {}


@app.get("/get-public-key")
def getPublicKey():
    return {"bank_key" : rsa_key_export, "signature_bank_key":base64_signed_bank_rsa}
    

@app.post("/send-symmetric-key")
def sendSymmetricKey(encryptedData: encryptedSendSymmetricKey):
    bytesKey = b64decode(encryptedData.encryptedKey)
    bytesIV = b64decode(encryptedData.encryptedIV)
    bytesID = b64decode(encryptedData.encryptedID)
    bytesSignedHash = b64decode(encryptedData.encryptedSignedHash)
    unixTimeSend = encryptedData.unixTime

    decryptedKey = cipher_rsa.decrypt(bytesKey)
    decryptedIV = cipher_rsa.decrypt(bytesIV)
    RSADecryptedID = cipher_rsa.decrypt(bytesID)
    decryptedSignedHash = cipher_rsa.decrypt(bytesSignedHash)

    cipher_aes = AES.new(decryptedKey, AES.MODE_CBC, iv=decryptedIV)
    decryptedID = unpad(cipher_aes.decrypt(RSADecryptedID), AES.block_size)

    public_key = ECC.import_key(open("client_open.pem", "rb").read())

    data_hash = SHA512.new(decryptedKey+decryptedIV+decryptedID+unixTimeSend.encode())

    verifier = eddsa.new(public_key, 'rfc8032')
    try:
        verifier.verify(data_hash, decryptedSignedHash)
        
        current_time = int(time.time())
        print("The data is authentic and signed by the right person")

        if current_time-60<encryptedData.unixTime:
            print("Request within allowed timeframe")
            foundID=False

            while foundID==False:
                sessionID = get_random_bytes(64)
                if session_ID_data.get(sessionID) is None:
                    foundID=True

            session_ID_data[sessionID] = [time.time(), decryptedID, decryptedKey]

            finishID = "0"
            finishReason = "OK"

        else:
            print("The request is to old")

            finishID = "2"
            finishReason = "Request to old"
            sessionID = ""

    except ValueError:
        print("The data is not authentic or not signed by the right person")

        finishID = "1"
        finishReason = "Signature not authentic"
        sessionID = ""

    if sessionID == "":
        sessionID = get_random_bytes(64)

    IV=get_random_bytes(16)
    cipher_aes = AES.new(decryptedKey, AES.MODE_CBC, iv=IV)
    encryptedSessionKey = cipher_aes.encrypt(pad(sessionID, AES.block_size))
    b64encSessionKey = b64encode(encryptedSessionKey).decode("utf-8")
    dataHashed = SHA512.new(finishID.encode()+finishReason.encode()+sessionID+IV)
    signedHash = b64encode(signer.sign(dataHashed)).decode("utf-8")
    return {"finishID":finishID, "finishReason":finishReason, "sessionID":b64encSessionKey, "signedHash":signedHash}
    


# Main application entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)