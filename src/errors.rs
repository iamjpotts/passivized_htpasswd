use bcrypt;
use bcrypt::BcryptError;
use thiserror;

#[derive(Debug, thiserror::Error)]
pub enum HtpasswdError {

    #[error("Bcrypt error: {0}")]
    BCrypt(BcryptError)

}

impl From<BcryptError> for HtpasswdError {
    fn from(other: BcryptError) -> Self {
        Self::BCrypt(other)
    }
}