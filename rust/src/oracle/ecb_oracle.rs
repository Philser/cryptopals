use crate::oracle::oracle_trait::Oracle;
use crate::oracle::utils::{generate_random_byte_vec, generate_random_byte_vec_arbitrary_length};
use crate::utils::crypto;
use std::error::Error;

pub struct ECBOracle {
    key: Vec<u8>,
    blackbox_plaintext: Vec<u8>,
    random_prefix: Option<Vec<u8>>,
}

impl Oracle for ECBOracle {
    fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut to_encrypt = match &self.random_prefix {
            Some(prefix) => prefix.clone(),
            None => Vec::new(),
        };

        to_encrypt.extend(plaintext.to_vec());
        to_encrypt.extend(&self.blackbox_plaintext);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }
}

impl ECBOracle {
    pub fn new(
        blackbox_b64string: String,
        with_random_prefix: bool,
    ) -> Result<ECBOracle, Box<dyn Error>> {
        let blackbox_string = base64::decode(blackbox_b64string)?;

        let mut random_prefix = None;
        if with_random_prefix {
            random_prefix = Some(generate_random_byte_vec_arbitrary_length());
        }

        Ok(ECBOracle {
            key: generate_random_byte_vec(16),
            blackbox_plaintext: blackbox_string,
            random_prefix,
        })
    }

    pub fn decrypt_aes_ecb(&self, cipher: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        crypto::decrypt_aes_ebc(cipher, &self.key, true)
    }
}
