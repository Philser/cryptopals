use std::error::Error;

use crate::oracle::{ecb_oracle::ECBOracle, oracle_trait::Oracle};
pub struct ProfileFactory {
    oracle: ECBOracle,
    uid_counter: usize,
}

impl ProfileFactory {
    pub fn new() -> Result<ProfileFactory, Box<dyn Error>> {
        let oracle = ECBOracle::new("".to_owned(), false)?;

        Ok(ProfileFactory {
            oracle,
            uid_counter: 0,
        })
    }

    pub fn profile_for(&mut self, email: &str) -> Result<String, Box<dyn Error>> {
        let mut sanitized_email = email.to_owned();
        sanitized_email = sanitized_email.replace("&", "");
        sanitized_email = sanitized_email.replace("=", "");

        let profile = format!(
            "email={}&uid={}&role=user",
            sanitized_email, self.uid_counter
        );
        self.uid_counter += 1;

        let encrypted = &self.oracle.get_encrypted(profile.as_bytes())?;

        Ok(hex::encode(encrypted))
    }

    #[cfg(test)]
    fn profile_for_admin(&mut self, email: &str) -> Result<String, Box<dyn Error>> {
        let mut sanitized_email = email.to_owned();
        sanitized_email = sanitized_email.replace("&", "");
        sanitized_email = sanitized_email.replace("=", "");

        let profile = format!(
            "email={}&uid={}&role=admin",
            sanitized_email, self.uid_counter
        );

        self.uid_counter += 1;

        let encrypted = &self.oracle.get_encrypted(profile.as_bytes())?;

        Ok(hex::encode(encrypted))
    }

    pub fn fetch_role(&self, encrypted_profile: &str) -> Result<String, Box<dyn Error>> {
        let error_box = Box::from("Invalid profile provided");
        let raw = hex::decode(encrypted_profile)?;
        match &self.oracle.decrypt_aes_ecb(&raw) {
            Ok(plaintext) => {
                let string = String::from_utf8(plaintext.to_owned())?;
                for kv_string in string.split('&') {
                    let kv_pair: Vec<&str> = kv_string.split('=').collect();
                    if kv_pair[0] == "role" {
                        return Ok(kv_pair[1].to_owned());
                    }
                }
                Err(error_box)
            }
            Err(_) => Err(error_box),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_fetch_role() -> Result<(), Box<dyn Error>> {
        let mut profile = ProfileFactory::new()?;
        let admin_profile = profile.profile_for_admin("test@test.com")?;

        let recovered_role = profile.fetch_role(&admin_profile)?;

        assert_eq!("admin", recovered_role);

        Ok(())
    }
}
