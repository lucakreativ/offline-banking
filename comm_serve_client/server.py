from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


private_key = RSA.import_key(open("zrsa_private.pem").read())

enc_sessionkey=open("encrypted_sessionkey.bin", "rb").read()


cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_sessionkey)
