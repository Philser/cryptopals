from Crypto.Cipher import AES
import secrets
import random


def __get_frequency_distribution__(str):
    character_frequency = {}

    for character in str:
        upperCase = character.upper()
        if character in character_frequency:
            character_frequency[upperCase] += 1
        else:
            character_frequency[upperCase] = 1

    return character_frequency


def decipher_single_byte_xor(cipher, key):
    output = ""
    for byte_index in range(0, len(cipher)):
        deciphered = cipher[byte_index] ^ key
        try:
            text = deciphered.to_bytes(
                1, byteorder='big').decode('ascii')
        except UnicodeDecodeError as e:
            raise e
        output += text
    return output

# Sources:
# https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
# https://en.wikipedia.org/wiki/Chi-squared_test
# https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html


def score_plaintext(str):
    english_frequency_percent = {
        'E': 11.1607, 'A': 8.4966, 'R': 7.5809,
        'I': 7.5448, 'O': 7.1635, 'T': 6.9509,
        'N': 6.6544, 'S': 5.7351, 'L': 5.4893,
        'C': 4.5388, 'U': 3.6308, 'P': 3.1671,
        'M': 3.0129, 'H': 3.0034, 'G': 2.4705,
        'B': 2.0720, 'F': 1.8121, 'Y': 1.7779,
        'W': 1.2899, 'K': 1.1016, 'V': 1.0074,
        'X': 0.2902, 'Z': 0.2722, 'J': 0.1965,
        'Q': 0.1962, 'D': 3.3844
    }

    distr = __get_frequency_distribution__(str)

    non_printable_characters = 0
    special_characters = 0
    chi_squared = 0.0
    for character in distr:
        observed = distr[character]
        if character in english_frequency_percent:
            expected = english_frequency_percent[character] / 100.0 * len(str)
        else:
            if (ord(character) < 32 or ord(character) > 126):
                # Character is not printable
                # The more of those we find, the more unlikely it is to be
                # English
                # (0.1 is just a heuristic I found by playing around)
                non_printable_characters += 1
                expected = 0.1 / non_printable_characters
            else:
                if (ord(character) == 32):
                    # Ignore spaces to not punish actual english sentences
                    # with lots of short words separated by spaces
                    continue
                # Character is printable but not a letter or number
                # Do not treat it as harshly as unprintable characters
                # but still punish a high frequency of special characters
                # (1 is just a heuristic I found by playing around)
                special_characters += 1
                expected = 1 / special_characters
        s = observed - expected
        chi_squared += s ** 2 / expected

    return chi_squared


def encrypt_repeating_key_xor(plaintext: bytes, key: bytes):
    cipher = b""
    for pos in range(0, len(plaintext)):
        xord = plaintext[pos] ^ key[pos % len(key)]
        cipher += xord.to_bytes(
            1, byteorder='big')

    return cipher


def get_hamming_distance(bytes1, bytes2):
    if len(bytes1) != len(bytes2):
        raise ValueError("Byte arrays are not the same length!")

    distance = 0
    for pos in range(0, len(bytes1)):
        for bit in range(0, 32):
            b1 = bytes1[pos] >> bit & 1
            b2 = bytes2[pos] >> bit & 1
            distance += b1 ^ b2

    return distance


def guess_keysize(cipher: bytes) -> int:
    distances = []
    for keysize_guess in range(2, 41):
        distance = 0
        # Average it for better results
        offset = 0
        i = 0
        while offset < len(cipher):
            bytes1 = cipher[offset: offset + keysize_guess]
            bytes2 = cipher[offset + keysize_guess: offset + keysize_guess * 2]
            if (len(bytes1) != len(bytes2)):
                # reached end, ignore last dangling bytes for now
                break
            dist = get_hamming_distance(
                bytes1,
                bytes2
            )
            distance += dist / keysize_guess  # normalize
            i += 1
            offset = keysize_guess * i * 2

        average = distance / i
        distances.append((keysize_guess, average))

    distances.sort(key=lambda distance: distance[1])

    # We only care for the keysize with the lowest distance
    return distances[0][0]


def slice_by_keysize(cipher: bytes, key_size: int) -> list:
    cipher_blocks = []
    offset = 0
    i = 0
    while offset < len(cipher):
        cipher_blocks.append(cipher[offset: offset + key_size])
        i += 1
        offset = key_size * i
    return cipher_blocks


def transpose_blocks(cipher_blocks: list, key_size: int):
    transposed = []
    for i in range(0, key_size):
        transposed.append(b"")
        for j in range(0, len(cipher_blocks) - 1):
            transposed[i] += cipher_blocks[j][i].to_bytes(
                1, byteorder='big')

    # We handle the last block seperately, because it might not be
    # of length key_size
    last_block = cipher_blocks[len(cipher_blocks) - 1]
    for i in range(0, len(last_block)):
        transposed[i] += last_block[i].to_bytes(1, byteorder='big')

    return transposed


def decrypt_repeating_key_xor(cipher: bytes, key: bytes):
    spread_key = b""
    for i in range(0, len(cipher)):
        spread_key += key[i % len(key)].to_bytes(1, byteorder='big')

    cleartext = b""
    for index in range(0, len(cipher)):
        deciphered = cipher[index] ^ spread_key[index]
        cleartext += deciphered.to_bytes(
            1, byteorder='big')

    return cleartext


def bruteforce_repeating_key_xor(cipher: bytes) -> (str, str):
    key_size = guess_keysize(cipher)

    cipher_blocks = slice_by_keysize(cipher, key_size)

    transposed = transpose_blocks(cipher_blocks, key_size)

    key = b""

    for block in transposed:
        block_scores = []
        for character in range(32, 123):
            output = decipher_single_byte_xor(block, character)
            score = score_plaintext(output.upper())
            block_scores.append((score, chr(character), output))
        block_scores.sort()
        key += block_scores[0][1].encode()

    return (key, decrypt_repeating_key_xor(cipher, key))


def pad_pkcs7(input: bytes, block_size: int) -> bytes:
    if len(input) % block_size == 0:
        return input

    padding = block_size - (len(input) % block_size)

    return input + chr(padding).encode() * padding


def decrypt_aes_cbc(cipher: bytes, iv: bytes, key: bytes):
    suite = AES.new(key, AES.MODE_ECB)

    if len(cipher) % AES.block_size != 0:
        raise ValueError("Cipher length needs to be a multiple of 16")

    offset = 0
    plain = b""
    previous_block = iv
    for i in range(0, len(cipher) // AES.block_size):
        offset = i * AES.block_size
        curr_block = cipher[offset: offset + AES.block_size]
        intermediate = suite.decrypt(curr_block)
        plain += decrypt_repeating_key_xor(intermediate, previous_block)

        previous_block = curr_block

    return plain


def encrypt_aes_cbc(plaintext: bytes, iv: bytes, key: bytes):
    suite = AES.new(key, AES.MODE_ECB)

    padded = pad_pkcs7(plaintext, AES.block_size)

    offset = 0
    cipher = b""
    previous_block = iv
    for i in range(0, len(padded) // AES.block_size):
        offset = i * AES.block_size
        curr_block = padded[offset: offset + AES.block_size]
        intermediate = encrypt_repeating_key_xor(curr_block, previous_block)
        cipher += suite.encrypt(intermediate)

        previous_block = curr_block

    return cipher


def encrypt_aes_ebc(plaintext: bytes, key: bytes):
    suite = AES.new(key, AES.MODE_ECB)

    padded = pad_pkcs7(plaintext, AES.block_size)

    return suite.encrypt(padded)


def encryption_oracle(input: str):
    key = secrets.token_bytes(16)

    byte_count = random.randint(5, 10)
    plaintext = secrets.token_bytes(
        byte_count) + input.encode() + secrets.token_bytes(byte_count)

    random.seed()
    mode = random.randint(1, 2)

    cipher = b""
    if mode == 1:
        cipher = encrypt_aes_ebc(plaintext, key)
    else:
        iv = secrets.token_bytes(AES.block_size)
        cipher = encrypt_aes_cbc(plaintext, iv, key)

    return cipher
