use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
use std::error::Error;

pub fn unpad_pkcs7(plaintext: &[u8], block_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if plaintext.len() % block_size != 0 {
        return Err(Box::from(format!(
            "Plaintext not padded to multiple of block size {}",
            block_size
        )));
    }

    let padding = plaintext[plaintext.len() - 1] as u8;

    if (padding as usize) > block_size {
        // Is not padded
        return Ok(plaintext.to_vec());
    }

    let mut new = plaintext.to_vec();
    new.truncate(plaintext.len() - padding as usize);

    Ok(new)
}

pub fn pad_pkcs7(plaintext: &[u8], block_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if block_size > 128 {
        return Err(Box::from("block sizes > 128 not supported"));
    }

    let rest = plaintext.len() % block_size;
    if rest == 0 {
        return Ok(plaintext.to_vec());
    }

    let padding = block_size - rest;
    let mut new = plaintext.to_vec();
    for _ in 0..padding {
        new.push(padding as u8);
    }

    Ok(new)
}

pub fn encrypt_repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cipher = vec![];
    for pos in 0..plaintext.len() {
        let xord: u8 = plaintext[pos] ^ key[pos % key.len()];
        cipher.push(xord);
    }

    Ok(cipher)
}

pub fn decrypt_repeating_key_xor(cipher: &[u8], key: &[u8]) -> Vec<u8> {
    let mut spread_key = b"".to_vec();
    for i in 0..cipher.len() {
        spread_key.push(key[i % key.len()]);
    }

    let mut cleartext = b"".to_vec();
    for index in 0..cipher.len() {
        let deciphered = cipher[index] ^ spread_key[index];
        cleartext.push(deciphered);
    }

    cleartext
}

fn encrypt_aes_ebc_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    block_aes_ecb(block, key, Mode::Encrypt)
}

fn decrypt_aes_ebc_block(block: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    block_aes_ecb(block, key, Mode::Decrypt)
}

fn block_aes_ecb(block: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();

    if block.len() != suite.block_size() {
        return Err(Box::from(format!(
            "Invalid block size, expected {} but was {}",
            suite.block_size(),
            block.len()
        )));
    }

    let mut crypter = Crypter::new(suite, mode, key, None)?;
    crypter.pad(false);

    let mut result = vec![0; suite.block_size() * 2];

    crypter.update(&block, &mut result)?;
    crypter.finalize(&mut result)?;

    // Throw away padding
    result.truncate(suite.block_size());

    Ok(result)
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();
    let padded = pad_pkcs7(&plaintext, suite.block_size())?;
    let mut offset;
    let mut cipher = vec![];
    for i in 0..(padded.len() / suite.block_size()) {
        offset = i * suite.block_size();
        let block = padded[offset..offset + suite.block_size()].to_vec();
        cipher.extend(encrypt_aes_ebc_block(&block, &key)?);
    }

    Ok(cipher)
}

pub fn encrypt_aes_cbc(
    plaintext: &[u8],
    iv: Vec<u8>,
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();

    let padded = pad_pkcs7(plaintext, suite.block_size())?;
    let mut offset;
    let mut cipher = b"".to_vec();
    let mut previous_block = iv;
    let mut curr_block: Vec<u8>;
    for i in 0..(padded.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = padded[offset..offset + suite.block_size()].to_vec();
        let intermediate = encrypt_repeating_key_xor(&curr_block, &previous_block)?;
        let mut encrypted_block = encrypt_aes_ebc_block(&intermediate, &key)?;

        previous_block = encrypted_block.clone();
        cipher.append(&mut encrypted_block);
    }
    Ok(cipher)
}

pub fn decrypt_aes_ebc(cipher: &[u8], key: &[u8], unpad: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();
    if cipher.len() % suite.block_size() != 0 {
        return Err(Box::from(format!(
            "Invalid cipher. Length is not a multiple of {}",
            suite.block_size()
        )));
    }

    let mut curr_block;
    let mut offset;
    let mut plaintext = b"".to_vec();
    for i in 0..(cipher.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = cipher[offset..offset + suite.block_size()].to_vec();
        plaintext.extend(decrypt_aes_ebc_block(&curr_block, &key)?);
    }

    if unpad {
        plaintext = unpad_pkcs7(&plaintext, suite.block_size())?;
    }

    Ok(plaintext)
}

pub fn decrypt_aes_cbc(
    cipher: &[u8],
    iv: Vec<u8>,
    key: &[u8],
    unpad: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();
    if cipher.len() % suite.block_size() != 0 {
        return Err(Box::from(format!(
            "Invalid cipher. Length is not a multiple of {}",
            suite.block_size()
        )));
    }

    let mut offset;
    let mut plaintext = b"".to_vec();
    let mut previous_block = iv;
    let mut curr_block;
    for i in 0..(cipher.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = cipher[offset..offset + suite.block_size()].to_vec();
        let intermediate = decrypt_aes_ebc_block(&curr_block, &key)?;
        let mut decrypted = decrypt_repeating_key_xor(&intermediate, &previous_block);
        plaintext.append(&mut decrypted);

        previous_block = curr_block.clone();
    }

    if unpad {
        plaintext = unpad_pkcs7(&plaintext, suite.block_size())?;
    }

    Ok(plaintext)
}

#[test]
fn can_pad() {
    let mut expected = b"YELLOW SUBMARINE".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 16) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => panic!("Test should not have failed"),
    }
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 20) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => panic!("Test should not have failed"),
    }

    expected = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\
    \x10\x10\x10\x10\x10\x10\x10"
        .to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 32) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => panic!("Test should not have failed"),
    }

    expected = b"YELLOW SUBMARINE\x05\x05\x05\x05\x05".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 7) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => panic!("Test should not have failed"),
    }
}

#[test]
fn can_unpad() {
    let mut expected = b"YELLOW SUBMARINE".to_vec();

    match unpad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 16) {
        Ok(unpadded) => assert_eq!(expected, unpadded),
        Err(_) => panic!("Test should not have failed"),
    }

    expected = b"YELLOW SUBMARIN".to_vec();

    match unpad_pkcs7(&b"YELLOW SUBMARIN\x01".to_vec(), 16) {
        Ok(unpadded) => assert_eq!(expected, unpadded),
        Err(_) => panic!("Test should not have failed"),
    }

    expected = b"YELLOW SUBMARINE".to_vec();

    match unpad_pkcs7(
        &b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
            .to_vec(),
        16,
    ) {
        Ok(unpadded) => assert_eq!(expected, unpadded),
        Err(_) => panic!("Test should not have failed"),
    }
}

#[test]
fn can_encrypt_repeating_key_xor() {
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2\
    6226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let input = b"Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal"
        .to_vec();

    match encrypt_repeating_key_xor(&input, &b"ICE".to_vec()) {
        Ok(result) => {
            let expected = hex::decode(expected_hex)
                .map_err(|_| panic!("Error decoding expected hex string"))
                .unwrap();
            assert_eq!(expected, result)
        }
        Err(e) => panic!("Function threw an error: {}", e),
    }
}

#[test]
fn can_decrypt_repeating_key_xor() {
    let expected = b"YELLOW SUBMARINE".to_vec();
    let key = b"KEY".to_vec();

    let encrypted = encrypt_repeating_key_xor(&expected, &key)
        .map_err(|_| panic!("Error encrypting plaintext"))
        .unwrap();

    let decrypted = decrypt_repeating_key_xor(&encrypted, &key);
    assert_eq!(expected, decrypted);
}

#[test]
fn can_encrypt_aes_ebc_block() {
    let key = b"YELLOW SUBMARINE".to_vec();

    let mut bytes = b"YELLOW SUBMARINE".to_vec();
    let mut expected = b"\xd1\xaaOex\x92eB\xfb\xb6\xdd\x87l\xd2\x05\x08".to_vec();
    match encrypt_aes_ebc_block(&bytes, &key) {
        Ok(encrypted) => assert_eq!(expected, encrypted),
        Err(e) => panic!("Unexpected error: {}", e),
    }

    bytes = pad_pkcs7(&b"test".to_vec(), 16)
        .map_err(|e| panic!("Unexpected error while padding: {}", e))
        .unwrap();
    expected = b"jx`\x035\x85a\xab\x9b\xb5M\xd4\xcf\x80\xb8\xab".to_vec();
    match encrypt_aes_ebc_block(&bytes, &key) {
        Ok(encrypted) => assert_eq!(expected, encrypted),
        Err(e) => panic!("Unexpected error: {}", e),
    }

    if encrypt_aes_ebc_block(&b"unpadded".to_vec(), &key).is_ok() {
        panic!("Method should have thrown but didn't")
    }
}

#[test]
fn can_decrypt_aes_ebc_block() {
    let key = b"YELLOW SUBMARINE".to_vec();

    let mut bytes = b"\xd1\xaaOex\x92eB\xfb\xb6\xdd\x87l\xd2\x05\x08".to_vec();
    let mut expected = b"YELLOW SUBMARINE".to_vec();
    match decrypt_aes_ebc_block(&bytes, &key) {
        Ok(decrypted) => assert_eq!(expected, decrypted),
        Err(e) => panic!("Unexpected error: {}", e),
    }

    bytes = b"jx`\x035\x85a\xab\x9b\xb5M\xd4\xcf\x80\xb8\xab".to_vec();
    expected = b"test\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c".to_vec();
    match decrypt_aes_ebc_block(&bytes, &key) {
        Ok(decrypted) => assert_eq!(expected, decrypted),
        Err(e) => panic!("Unexpected error: {}", e),
    }
}

#[test]
fn can_decrypt_aes_cbc() {
    let suite = Cipher::aes_128_cbc();
    let key = b"YELLOW SUBMARINE".to_vec();
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }

    let mut plaintext = b"test".to_vec();
    let mut encrypted = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();
    let mut expected = decrypt(suite, &key, Some(&iv), &encrypted).unwrap();

    match decrypt_aes_cbc(&encrypted, iv.clone(), &key, true) {
        Ok(decrypted) => assert_eq!(expected, decrypted),
        Err(e) => panic!("Test failed with: {}", e),
    }

    plaintext = b"YELLOW SUBMARINE".to_vec();
    encrypted = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();
    expected = decrypt(suite, &key, Some(&iv), &encrypted).unwrap();
    match decrypt_aes_cbc(&encrypted, iv.clone(), &key, true) {
        Ok(decrypted) => assert_eq!(expected, decrypted,),
        Err(e) => panic!("Test failed with: {}", e),
    }
}

#[test]
fn can_encrypt_aes_cbc() {
    let suite = Cipher::aes_128_cbc();
    let key = b"YELLOW SUBMARINE".to_vec();
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }

    let mut plaintext = b"test".to_vec();

    let mut expected = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();

    match encrypt_aes_cbc(&plaintext, iv.clone(), &key) {
        Ok(encrypted) => {
            assert_eq!(expected, encrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }

    plaintext = b"Longer than 16 bytes".to_vec();

    expected = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();

    match encrypt_aes_cbc(&plaintext, iv.clone(), &key) {
        Ok(encrypted) => {
            assert_eq!(expected, encrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }
}

#[test]
fn can_encrypt_aes_ebc() {
    let suite = Cipher::aes_128_ecb();
    let key = b"YELLOW SUBMARINE".to_vec();

    let mut plaintext = b"test".to_vec();

    let mut expected = encrypt(suite, &key, None, &plaintext).unwrap();

    match encrypt_aes_ecb(&plaintext, &key) {
        Ok(encrypted) => {
            assert_eq!(expected, encrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }

    plaintext = b"Longer than 16 bytes".to_vec();

    expected = encrypt(suite, &key, None, &plaintext).unwrap();

    match encrypt_aes_ecb(&plaintext, &key) {
        Ok(encrypted) => {
            assert_eq!(expected, encrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }
}

#[test]
fn can_decrypt_aes_ebc() {
    let suite = Cipher::aes_128_ecb();
    let key = b"YELLOW SUBMARINE".to_vec();

    let mut plaintext = b"test".to_vec();
    let mut encrypted = encrypt(suite, &key, None, &plaintext).unwrap();

    match decrypt_aes_ebc(&encrypted, &key, true) {
        Ok(decrypted) => {
            assert_eq!(plaintext, decrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }

    plaintext = b"testtesttesttesttesttesttesttest".to_vec(); // two blocks
    encrypted = encrypt(suite, &key, None, &plaintext).unwrap();

    match decrypt_aes_ebc(&encrypted, &key, true) {
        Ok(decrypted) => {
            assert_eq!(plaintext, decrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }

    plaintext = b"testtesttesttesttesttest".to_vec(); // one and a half blocks
    encrypted = encrypt(suite, &key, None, &plaintext).unwrap();

    match decrypt_aes_ebc(&encrypted, &key, true) {
        Ok(decrypted) => {
            assert_eq!(plaintext, decrypted)
        }
        Err(_) => panic!("Function threw error unexpectedly"),
    }
}
