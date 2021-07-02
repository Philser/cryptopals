use crate::oracle::utils::aes_encryption_oracle;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    // The idea is that since we control the plaintext, we can insert a reoccurring pattern
    // that will reveal ECB because ECB ciphertexts keep patterns from the plain texts intact
    let crafted_plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE\
        YELLOW SUBMARINEYELLOW SUBMARINE"
        .to_vec();
    let (cipher, mode) = aes_encryption_oracle(&crafted_plaintext)?;
    println!("Cipher:\n{:?}\n", cipher);

    // For now, let's use a very simple algorithm that takes a sequence from the beginning of the
    // second block (to avoid the random bytes in the beginning) of the cipher and looks for it on
    // the third and fourth blocks. This assumes that the crafted plaintext is at least four blocks
    // long.
    let detected;
    let pattern = cipher[16..20].to_vec();
    if pattern == cipher[32..36] && pattern == cipher[48..52] {
        detected = "ECB";
    } else {
        detected = "CBC";
    }

    if detected == mode {
        println!("Correctly identified mode {}", mode);
    } else {
        println!("Oracle identified {}, but was {}", detected, mode);
    }

    Ok(())
}
