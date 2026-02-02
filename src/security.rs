use sha2::{Digest, Sha256};

pub fn generate_salt() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn hash_password(salt: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}
