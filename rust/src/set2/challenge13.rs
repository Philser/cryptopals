use crate::utils::profile::ProfileFactory;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    // Idea:
    // 1. Find out what the encrypted version of admin[padding] & user[padding] are
    //    by providing this as email
    // 2. Create profiles of increasing email name length until we have a block resembling
    //    user[padding] at the end
    // 3. Replace last block with the admin[padding] block we found in step 1
    //
    // TODO: This doesn't handle growing UID sizes (e.g. when UID switches from 99 to 100,
    //       the whole padding is scrambled)

    let block_size = 16;

    let mut profile_factory = ProfileFactory::new()?;

    // Prepend with 10 because the string starts with "email="
    let user_block_cookie = profile_factory
        .profile_for("AAAAAAAAAAuser\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c")?;

    let user_block = &user_block_cookie[block_size * 2..block_size * 4];
    println!("User block: {:?}", user_block);

    let admin_block_cookie = profile_factory
        .profile_for("AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")?;

    // hex representation, i.e. one byte is two chars
    let admin_block = &admin_block_cookie[block_size * 2..block_size * 4];

    let mut email = "".to_string();
    let mut dummy_profile: String = "".to_string();
    for i in 0..block_size {
        dummy_profile = profile_factory.profile_for(&email)?;

        if dummy_profile.ends_with(&user_block) {
            break; // Found input fitting our needs
        }
        email.extend(['a'].iter());

        if i == block_size - 1 {
            // TODO: Better error message here please
            return Err(Box::from("Could not crack profile"));
        }
    }

    if email.len() > "@test.com".len() {
        email.truncate(email.len() - "@test.com".len());
        email.extend("@test.com".chars().into_iter());
    } else {
        email = (0..block_size - "@test.com".len() + email.len())
            .map(|_| "A".to_string())
            .collect::<String>();
        email.extend("@test.com".chars().into_iter());
    }

    dummy_profile = profile_factory.profile_for(&email)?;
    dummy_profile = dummy_profile.replace(&user_block, &admin_block);

    assert_eq!(
        "admin".to_string(),
        profile_factory.fetch_role(&dummy_profile)?,
        "Could not crack profile"
    );

    println!("Got admin with email: {}", email);
    println!("Admin cookie: {}", dummy_profile);

    Ok(())
}
