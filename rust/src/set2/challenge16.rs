use std::error::Error;

use crate::{
    oracle::{ecb_oracle::ECBOracle, utils::generate_random_byte_vec},
    utils::crypto::{decrypt_aes_cbc, encrypt_aes_cbc},
};

pub fn run() -> Result<(), Box<dyn Error>> {
    let key = generate_random_byte_vec(16);
    let iv = generate_random_byte_vec(16);
    Ok(())
}

fn encrypt(input: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let sanitized = input.replace(";", "").replace("=", "");
    let mut plaintext = b"comment1=cooking%20MCs;userdata=".to_vec();
    plaintext.extend(sanitized.as_bytes());
    plaintext.extend(b";comment2=%20like%20a%20pound%20of%20bacon");

    let cipher = encrypt_aes_cbc(&plaintext, iv.to_vec(), key)?;

    Ok(cipher)
}

fn is_admin(cipher: &[u8], key: &[u8], iv: &[u8]) -> Result<bool, Box<dyn Error>> {
    let plaintext = String::from_utf8(decrypt_aes_cbc(cipher, iv.to_vec(), key, true)?)?;

    Ok(plaintext.contains(";admin=true;"))
}
