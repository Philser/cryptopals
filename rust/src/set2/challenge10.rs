use crate::utils::crypto::decrypt_aes_cbc;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::str;

pub fn run() -> Result<(), Box<dyn Error>> {
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }

    let path = env::current_dir()?.join("src/set2/challenge10.enc");
    println!("Reading from file {}", path.display());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut contents = "".to_owned();
    for line in reader.lines() {
        contents.push_str(&line?);
    }
    let decoded = base64::decode(contents)?;

    let decrypted = decrypt_aes_cbc(&decoded, iv, &b"YELLOW SUBMARINE".to_vec(), false)?;

    unsafe {
        println!("Decrypted:\n{}", str::from_utf8_unchecked(&decrypted));
    }

    Ok(())
}
