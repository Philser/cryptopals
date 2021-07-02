import importlib.util
spec = importlib.util.spec_from_file_location(
    "cipher_lib", "../lib/cipher_lib.py")
cipher_lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher_lib)


with open("./challenge4.enc") as f:
    scores_global = []
    for string in f.readlines():
        raw_bytes = bytes.fromhex(string.strip('\n'))
        scores_local = []
        try:
            # Try every character for string
            for character in range(32, 123):  # ASCII codes for A..Z
                output = cipher_lib.decipher_single_byte_xor(
                    raw_bytes, character)
                score = cipher_lib.score_plaintext(output.upper())
                scores_local.append((score, chr(character), output))

            scores_local.sort()
            # Only look at the most likely solution for every string
            scores_global.append(scores_local[0])
        except UnicodeDecodeError:
            # could not decode string, continue with next
            continue

scores_global.sort()
print("Most likely solutions:")
print(scores_global[0])
print(scores_global[1])
print(scores_global[2])
