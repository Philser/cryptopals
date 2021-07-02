import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)

print(cipher_lib.pad_pkcs7("YELLOW SUBMARINE", 20).encode())
