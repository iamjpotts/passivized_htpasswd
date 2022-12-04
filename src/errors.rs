use bcrypt;
use bcrypt::BcryptError;
use thiserror;

#[derive(Debug, thiserror::Error)]
pub enum HtpasswdError {

    #[error("Bcrypt error: {0}")]
    BCrypt(#[from] BcryptError),

    #[error("Password hashing error: {0}")]
    PwHash(#[from] pwhash::error::Error),

}
