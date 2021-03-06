use crate::oracle::utils::generate_random_byte_vec;
use std::error::Error;

use rand::{thread_rng, Rng};
use rust::utils::crypto::{decrypt_aes_cbc, encrypt_aes_cbc, unpad_pkcs7};

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

    let cipher = encrypt_aes_cbc(pick_random_string().as_bytes(), &iv, &key)?;

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

    let mut cracked_plaintext: Vec<u8> = Vec::new();

    let block_count = result.ciphertext.len() / BLOCK_SIZE;
    // Iterate through cipher blocks from second-to-last to first
    for block in (1..block_count).rev() {
        let curr_block_start_idx = get_start_of_block(BLOCK_SIZE, block);
        let curr_block_end_idx = get_end_of_block(BLOCK_SIZE, block);

        // Throw away the blocks we have already processed
        let mut cipher = result.ciphertext
            [0..result.ciphertext.len() - (block_count - block - 1) * BLOCK_SIZE]
            .to_vec();

        // For each block, crack padding byte by byte
        let mut intermediate: Vec<u8> = (0..BLOCK_SIZE).map(|_| 0).collect();
        for cipher_idx in 0..BLOCK_SIZE {
            let padding_byte = cipher_idx as u8 + 1;

            // It is important to zero the rest of the cipher block to remove any previously valid padding
            // so that only 0x01 produces a valid padding, and not additionally the char that would produce the
            // actual padding of the plaintext
            overwrite_with_zero(
                &mut cipher,
                BLOCK_SIZE,
                curr_block_start_idx,
                curr_block_end_idx,
            );

            // Prepare padding
            for pos in 0..cipher_idx {
                // Going through all positions we already cracked the plaintext for
                cipher[curr_block_end_idx - pos] =
                    padding_byte ^ intermediate[intermediate.len() - pos - 1];
            }

            // Set next unknown byte to a value until we match padding
            for byte in 0..=255 {
                cipher[curr_block_end_idx - cipher_idx] = byte;

                if has_valid_padding(&cipher, &key, &result.iv, BLOCK_SIZE)? {
                    if cipher_idx == 0 {
                        // Check if penultimate byte is not 0x02, because then the rest of the attack will fail
                        cipher[curr_block_end_idx - 1] = 0;
                        if !has_valid_padding(&cipher, &key, &result.iv, BLOCK_SIZE)? {
                            // We changed the penultimate byte of the attack cipher block and now the padding is not valid anymore,
                            // meaning that the current byte resolves to 0x02, instead of 0x01. Thus, we continue our search.

                            continue;
                        }
                    }
                    intermediate[BLOCK_SIZE - cipher_idx - 1] = byte ^ padding_byte;
                    cracked_plaintext.insert(
                        0,
                        byte ^ padding_byte ^ result.ciphertext[curr_block_end_idx - cipher_idx],
                    );
                    break;
                }
            }
        }
    }

    let base64_encoded = String::from_utf8(unpad_pkcs7(&cracked_plaintext, BLOCK_SIZE)?)?;
    println!(
        "Cleartext: {}",
        String::from_utf8(base64::decode(base64_encoded)?)?
    );

    Ok(())
}

/// Gets the start index of a block, where block 1 starts at index 0
fn get_start_of_block(block_size: usize, block: usize) -> usize {
    block_size * (block - 1)
}

/// Gets the end index of a block, where block 1 ends at index block_size - 1
fn get_end_of_block(block_size: usize, block: usize) -> usize {
    block_size * (block - 1) + block_size - 1
}

fn overwrite_with_zero(
    cipher: &mut [u8],
    block_size: usize,
    block_start_idx: usize,
    block_end_idx: usize,
) {
    let zeroes: Vec<u8> = (0..block_size).map(|_| 0).collect();
    cipher[block_start_idx..=block_end_idx].clone_from_slice(&zeroes[..block_size]);
}

#[test]
fn can_get_start_of_block() {
    assert_eq!(get_start_of_block(2, 1), 0);
    assert_eq!(get_start_of_block(2, 2), 2);
    assert_eq!(get_start_of_block(2, 3), 4);
}

#[test]
fn can_get_end_of_block() {
    assert_eq!(get_end_of_block(2, 1), 1);
    assert_eq!(get_end_of_block(2, 2), 3);
    assert_eq!(get_end_of_block(2, 3), 5);
}

#[test]
fn can_overwrite_with_random() {
    let original = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cipher = original;

    let block_size = 2;

    let start = 0;
    let end = block_size - 1;

    overwrite_with_zero(&mut cipher, block_size, start, end);

    assert!(original[0..=1] != cipher[0..=1]);
    assert!(original[2..] == cipher[2..]);

    let block_size = 10;
    cipher = original;

    let start = 0;
    let end = block_size - 1;

    overwrite_with_zero(&mut cipher, block_size, start, end);

    assert!(original != cipher);
}
