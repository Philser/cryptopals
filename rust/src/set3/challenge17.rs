use crate::oracle::utils::generate_random_byte_vec;
use std::error::Error;

use rand::{thread_rng, Rng};
use rust::utils::crypto::{decrypt_aes_cbc, encrypt_aes_cbc, pad_pkcs7, unpad_pkcs7};

fn pick_random_string() -> &'static str {
    let strings = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    let mut rng = thread_rng();
    let index = rng.gen_range(0..strings.len());

    &strings[index]
}

struct EncryptedResult {
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
}

fn encrypt_plaintext(key: &[u8], block_size: usize) -> Result<EncryptedResult, Box<dyn Error>> {
    let iv = generate_random_byte_vec(block_size);

    let cipher = encrypt_aes_cbc(&pick_random_string().as_bytes(), &iv, &key)?;

    Ok(EncryptedResult {
        ciphertext: cipher,
        iv,
    })
}

fn has_valid_padding(
    cipher: &[u8],
    key: &[u8],
    iv: &[u8],
    block_size: usize,
) -> Result<bool, Box<dyn Error>> {
    let plaintext = decrypt_aes_cbc(cipher, iv, key, false)?;

    match unpad_pkcs7(&plaintext, block_size) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn run() -> Result<(), Box<dyn Error>> {
    const BLOCK_SIZE: usize = 16;
    let key = generate_random_byte_vec(BLOCK_SIZE);

    let result = encrypt_plaintext(&key, BLOCK_SIZE)?;

    let mut cracked_plaintext: Vec<u8> = Vec::with_capacity(result.ciphertext.len());
    for block in 1..result.ciphertext.len() / BLOCK_SIZE {
        let mut cipher = result.ciphertext.clone();
        let cipher_len = cipher.len();

        let mut intermediate: Vec<u8> = (0..BLOCK_SIZE).map(|_| 0).collect();
        for padding in 1..BLOCK_SIZE {
            // It is important to randomize the rest of the cipher block to remove any previously valid padding
            // so that only 0x01 produces a valid padding, and not additionally the char that would produce the
            // actual padding of the plaintext
            let random = generate_random_byte_vec(BLOCK_SIZE - 1);
            for i in 0..BLOCK_SIZE - padding {
                cipher[cipher_len - BLOCK_SIZE * (block + 1) + i] = random[i];
            }

            // Prepare padding
            for pos in 0..padding - 1 {
                // Going backwards through all positions we already cracked the plaintext for
                cipher[cipher_len - BLOCK_SIZE * block - pos - 1] =
                    padding as u8 ^ intermediate[intermediate.len() - pos - 1];
            }

            // Set next unknown byte to a value until we match padding
            for byte in 0..255 {
                cipher[cipher_len - BLOCK_SIZE * block - padding] = byte;

                if has_valid_padding(&cipher, &key, &result.iv, BLOCK_SIZE)? {
                    println!("Intermediate value: {}", byte ^ padding as u8);
                    intermediate[BLOCK_SIZE - padding] = byte ^ padding as u8;
                }
            }
        }

        println!("Intermediate block: {:?}", intermediate);

        // TODO: Imperformant
        for pos in (0..intermediate.len()).rev() {
            cracked_plaintext.insert(
                0,
                intermediate[pos] ^ result.ciphertext[cipher_len - BLOCK_SIZE * (block + 1) + pos],
            );
        }
    }
    // TODO: Plaintext needs to be unpadded
    println!("Plain: {:?}", cracked_plaintext);

    Ok(())
}
