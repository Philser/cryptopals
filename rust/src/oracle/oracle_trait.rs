use std::error::Error;

pub trait Oracle {
    fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}
