import base64
from Crypto.Cipher import AES

key = b"YELLOW SUBMARINE"

with open("./challenge7.enc") as f:
    ciphertext = base64.b64decode(f.read())
    suite = AES.new(key, AES.MODE_ECB)
    print(suite.decrypt(ciphertext).decode())
