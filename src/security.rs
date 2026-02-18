use argon2::{
    Argon2,
    password_hash::{
        Error, PasswordHasher, PasswordVerifier, phc::PasswordHash,
    },
};

pub fn hash_password(password: &str) -> Result<String, Error> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())?
        .to_string())
}

pub fn verify_password(
    password_hash: &str,
    password: &str,
) -> Result<bool, Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
