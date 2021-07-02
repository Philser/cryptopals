import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)

to_encrypt = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

expected_cipher = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a\
26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831652\
86326302e27282f"

encrypted = cipher_lib.encrypt_repeating_key_xor(
    to_encrypt.encode(), "ICE".encode())

if encrypted.hex() == expected_cipher:
    print("The algorithm works!")
else:
    print("Uh oh! Got unexpected result: " + encrypted)
