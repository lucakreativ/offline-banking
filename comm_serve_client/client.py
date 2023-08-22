from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

data = "I met aliens in UFO. Here is the map.".encode("utf-8")
file_out = open("encrypted_sessionkey.bin", "wb")

recipient_key = RSA.import_key(open("zrsa_public.pem").read())
session_key = b'Test'

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

file_out.write(enc_session_key)
file_out.close()
