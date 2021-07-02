from Crypto.Cipher import AES
with open("./challenge8.enc") as f:
    # AES ECB is deterministic
    # Thus, we need to find a ciphertext that has reoccuring strings
    for line in f.readlines():
        blocks = {}

        for i in range(0, len(line) // AES.block_size - 1):
            offset = i * AES.block_size

            if blocks.get(line[offset:offset + AES.block_size]):
                print("AES detected in string: ")
                print(line)
                break
            else:
                blocks[line[offset:offset + AES.block_size]] = 1
