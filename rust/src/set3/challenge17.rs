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
    let plaintext = pad_pkcs7(pick_random_string().as_bytes(), block_size)?;

    let iv = generate_random_byte_vec(block_size);

    let cipher = encrypt_aes_cbc(&plaintext, &iv, &key)?;

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
    let block_size = 16;
    let key = generate_random_byte_vec(block_size);

    let cipher = encrypt_plaintext(&key, block_size);

    

    Ok(())
}
