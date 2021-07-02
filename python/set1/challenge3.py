
import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)


def challenge3():
    raw_bytes = bytes.fromhex("1b37373331363f78151b7f2b783431333d7839782"
                              "8372d363c78373e783a393b3736")
    scores = []
    for character in range(65, 91):  # ASCII codes for A..Z
        output = cipher_lib.decipher_single_byte_xor(raw_bytes, character)
        scores.append((cipher_lib.score_plaintext(output.upper()),
                       chr(character), output))

    scores.sort()

    print("Most likely solutions:")
    print(scores[0])
    print(scores[1])
    print(scores[2])


challenge3()
