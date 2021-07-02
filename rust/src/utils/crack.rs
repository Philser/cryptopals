use std::error::Error;

use crate::oracle::{ecb_oracle::ECBOracle, oracle_trait::Oracle};

pub enum AesMode {
    Ecb,
    Cbc 
}

// TODO: This function is a mess
pub fn decipher_ecb_oracle_secret(oracle: &ECBOracle) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1. Discover block size
    let block_size = discover_block_size(oracle)?;

    // 2. Detect cipher mode
    match detect_cipher_mode(oracle, block_size)? {
        AesMode::Ecb => {/*let's continue*/},
        _ => return Err(Box::from("Error: Cipher is not in ECB mode"))
    }

    // Bonus: Detect and evade prefix
    // B.1: Set a "prefix length" value to 0
    // B.2: Insert recurring pattern and look for repeating blocks at start of array
    // B.3.1: If recurring pattern was found BUT not of original length, increase "prefix length"
    // B.3.2: If recurring pattern of right length was found, "prefix length" is the right value
    //        and we memorize at which position the recurring pattern was found
    // B.4: For attacking the cipher, we now always insert "prefix length" and drop the first
    //      blocks that we know only hold the random prefix
    let (prefix_length, cipher_start_block) = get_ecb_prefix_counter_measures(oracle, block_size)?;

    // 3. - 6.
    let prefix: Vec<u8> = (0..prefix_length).map(|_| 0).collect();
    let mut char_sequence: Vec<u8> = (0..block_size).map(|_| 65/*"A"*/).collect();
    let pure_cipher = oracle.get_encrypted(&prefix)?;
    let mut plaintext = b"".to_vec();
    for curr_block in cipher_start_block..(pure_cipher.len() / block_size) {    
        let offset = curr_block * block_size;
        let mut secret = b"".to_vec();
        
        for _ in 0..block_size  {
            // 3. Craft input block that is one byte short
            
            if !char_sequence.is_empty() {
                char_sequence.remove(0); // Left shift by one at a time
            }

            let mut input = prefix.clone();
            input.extend(&char_sequence);
            let cipher = oracle.get_encrypted(&input)?;

            let mut guess = input.clone();
            guess.extend(&secret);

            // 4.-5. Brute force next byte by trying every possible byte and look for match
            match bruteforce_aes_ebc_byte(
                &guess, 
                &cipher[offset..offset + block_size], 
                cipher_start_block,
                oracle,
                
            ) {
                Ok(character) => secret.push(character),
                Err(_) => {
                    // Let's just assume that if he cannot brute force the next char it
                    // is because he reached the end of the string.
                    // TODO: We could also check if it is a padding char and only then stop, else
                    // throw an error
                    break;
                }
            }
        }

        plaintext.extend(&secret);
        char_sequence = secret;
    }
    
    Ok(plaintext)
}

fn discover_block_size(oracle: &dyn Oracle) -> Result<usize, Box<dyn Error>> {
    let mut plaintext = b"A".to_vec();
    let mut cipher = oracle.get_encrypted(&plaintext)?;
    let mut last_cipher_len = cipher.len();
    let mut init_run = true;
    let mut padding_until_next_block = 0;
    let block_size;

    // We first add more characters until a new block is added to the cipher.
    // From there, we can start fresh without having to take into account any additional
    // characters being added to the cipher.
    loop {
        plaintext.extend(b"A".to_vec());
        cipher = oracle.get_encrypted(&plaintext)?;
        if cipher.len() > last_cipher_len {
            if init_run {
                init_run = false;
                padding_until_next_block = plaintext.len();
                last_cipher_len = cipher.len();
                continue;
            }
            block_size = plaintext.len() - padding_until_next_block;
            break;
        }
    }

    Ok(block_size)
}

pub fn detect_cipher_mode(
    oracle: &dyn Oracle,
    block_size: usize, 
    ) -> Result<AesMode, Box<dyn Error>> {
    if get_ecb_prefix_counter_measures(oracle, block_size).is_ok() {
        return Ok(AesMode::Ecb);
    }

    Ok(AesMode::Cbc)
}

fn bruteforce_aes_ebc_byte(
    plaintext: &[u8], 
    cipher_block: &[u8], 
    cipher_start_block: usize,
    oracle: &dyn Oracle, 
) -> Result<u8, Box<dyn Error>> {
    let mut printable_chars = 
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!$%&/()=?*',.-;:_ +\n\t~#<>|\\".to_vec();  
    
    let paddings: Vec<u8> = (1..cipher_block.len()).map(|i| i as u8).collect();
    printable_chars.extend(paddings);

    let offset = cipher_start_block * cipher_block.len();
       
    for letter in printable_chars.iter() {
        let mut guess = plaintext.to_vec();
        guess.push(*letter);
    
        
        if &oracle.get_encrypted(&guess)?[offset..offset + cipher_block.len()] == cipher_block {
            return Ok(*letter);
        }
    }
    
    Err(
        Box::from(
            format!("Could not bruteforce character. Plaintext: {}", String::from_utf8(plaintext.to_vec())?)
        ))
}

fn get_ecb_prefix_counter_measures(
    oracle: &dyn Oracle, 
    block_size: usize
) -> Result<(usize, usize), Box<dyn Error>> {
    let pattern_count = 4;
    
    let mut prefix_length = 0;
    let pattern: Vec<u8> = (0..block_size * pattern_count).map(|_| 41).collect();

    // Find prefix_length by inserting recurring pattern
    while prefix_length < block_size  {
        let mut input = (0..prefix_length).map(|_| 0).collect::<Vec<u8>>();
        input.extend(&pattern);

        let cipher = oracle.get_encrypted(&input)?;
        
        // Check if blocks at pos..pos + pattern_count are all equal
        let blocks = cipher.len() / block_size;
        for pos in 0..=blocks - pattern_count {
            let mut blocks_are_equal = true;
            let curr_slice = &cipher[pos * block_size .. pos * block_size + block_size];
            
            for i in pos + 1..pos + pattern_count {
                let next_slice = &cipher[i * block_size .. i * block_size + block_size];
                
                blocks_are_equal = *curr_slice == *next_slice;
            }

            if blocks_are_equal {
                return Ok((prefix_length, pos));
            }
        }

        prefix_length += 1;
    }

    Err(Box::from("Cipher is not encrypted in AES ECB Mode"))
}

#[test]
fn can_get_prefix_counter_measures() -> Result<(), Box<dyn Error>> {
    struct DummyOracle {}
    impl Oracle for DummyOracle {
        fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            // One and a half block sizes of prefix
            let mut cipher: Vec<u8> = (0..24).map(|_| 50).collect(); 
            cipher.extend(plaintext.to_vec());

            Ok(cipher)
        }
    }

    let dummy = DummyOracle{};
    let (prefix_len, pos) = get_ecb_prefix_counter_measures(
        &dummy, 
        16
    )?;
    assert_eq!(8, prefix_len);
    assert_eq!(2, pos);
    
    Ok(())
}

#[test]
fn can_get_prefix_counter_measures_no_prefix() -> Result<(), Box<dyn Error>> {
    struct DummyOracle {}
    impl Oracle for DummyOracle {
        fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            // One and a half block sizes of prefix
            let mut cipher: Vec<u8> = Vec::new();
            cipher.extend(plaintext.to_vec());

            Ok(cipher)
        }
    }

    let dummy = DummyOracle{};
    
    let (prefix_len, pos) = get_ecb_prefix_counter_measures(&dummy, 16)?;
    assert_eq!(0, prefix_len);
    assert_eq!(0, pos);

    Ok(())
}


// TODO: Tests