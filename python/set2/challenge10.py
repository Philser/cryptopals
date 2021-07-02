from Crypto.Cipher import AES
import base64
import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)

with open("./challenge10.enc") as f:
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * AES.block_size

    text = base64.b64decode(f.read())
    print(cipher_lib.decrypt_aes_cbc(text, iv, key).decode())
