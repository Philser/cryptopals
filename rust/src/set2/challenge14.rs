use std::error::Error;

use crate::{
    oracle::ecb_oracle::ECBOracle,
    utils::crack::decipher_ecb_oracle_secret,
};

pub fn run() -> Result<(), Box<dyn Error>> {
    let oracle = ECBOracle::new(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
    YnkK"
            .to_owned(),
        true,
    )?;
    println!(
        "Secret: {}",
        String::from_utf8(decipher_ecb_oracle_secret(&oracle)?)?
    );
    Ok(())
}
