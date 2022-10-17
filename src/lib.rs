//!
//! Generate Apache .htpasswd files using bcrypt.
//!
//! # Example
//!
//! ```rust
//! use std::error::Error;
//! use passivized_htpasswd::errors::HtpasswdError;
//! use passivized_htpasswd::Htpasswd;
//!
//! fn setup_credentials() -> Result<(), Box<dyn Error>> {
//!     let mut credentials = Htpasswd::new();
//!
//!     credentials.set("John Doe", "Don't hardcode")?;
//!     credentials.write_to_path("www/.htpasswd")?;
//!
//!     Ok(())
//! }
//!
//! ```

pub mod errors;

use std::borrow::Borrow;
use std::io;
use std::path::Path;
use bcrypt::{DEFAULT_COST, Version};
use indexmap::IndexMap;
use indexmap::map::Iter;

use crate::errors::HtpasswdError;

// Minimum cost that bcrypt library will accept.
const MIN_COST: u32 = 4;

pub enum Algo {
    /// Use a specific cost. Must be within a range acceptable to the bcrypt library.
    Bcrypt {
        cost: u32
    },

    /// Fastest, cheapest, and least secure. Useful for automated tests.
    BcryptMinCost,

    /// Use default cost
    BCryptDefault
}

#[derive(Clone, Debug, Default)]
pub struct Htpasswd {
    // Username and encrypted password
    entries: IndexMap<String, String>
}

impl Htpasswd {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set<U, P>(&mut self, username: U, password: P) -> Result<(), HtpasswdError>
    where
        U: Borrow<str>,
        P: Borrow<str> + AsRef<[u8]>
    {
        self.set_with(Algo::BCryptDefault, username, password)
    }

    pub fn set_with<U, P>(&mut self, algo: Algo, username: U, password: P) -> Result<(), HtpasswdError>
    where
        U: Borrow<str>,
        P: Borrow<str> + AsRef<[u8]>
    {
        let encrypted = match algo {
            Algo::Bcrypt { cost} => {
                bcrypt::hash_with_result(password, cost)?
                    .format_for_version(Version::TwoA)
            },
            Algo::BCryptDefault => {
                return self.set_with(Algo::Bcrypt { cost: DEFAULT_COST }, username, password)
            }
            Algo::BcryptMinCost => {
                return self.set_with(Algo::Bcrypt { cost: MIN_COST }, username, password)
            }
        };

        self.entries.insert(username.borrow().to_string(), encrypted);

        Ok(())
    }

    pub fn write_to_path<P>(&self, path: P) -> Result<(), io::Error>
    where
        P: AsRef<Path>
    {
        std::fs::write(path, self.to_string())
    }
}

impl ToString for Htpasswd {
    fn to_string(&self) -> String {
        let entries : Iter<String, String> = self.entries.iter();

        entries
            .map(|(u, p)| format!("{}:{}\n", u, p))
            .collect()
    }
}

#[cfg(test)]
mod test_verifies_against_apache_cli {
    use std::process::Command;
    use tempfile::tempdir;
    use crate::Algo::BcryptMinCost;
    use crate::Htpasswd;

    fn check(file: &str, username: &str, password: &str) {
        let mut cmd = Command::new("htpasswd");
        cmd.args(["-bv", file, username, password]);

        assert_eq!(0, cmd.status().unwrap().code().unwrap());
    }

    #[test]
    fn verifies_bcrypt_min() {
        let mut htpasswd = Htpasswd::new();

        htpasswd.set_with(BcryptMinCost, "a", "b")
            .unwrap();

        let tmp = tempdir()
            .unwrap();

        let htpasswd_file = tmp
            .path()
            .join("passwords")
            .to_str()
            .unwrap()
            .to_string();

        htpasswd.write_to_path(&htpasswd_file)
            .unwrap();

        check(&htpasswd_file, "a", "b");
    }

    #[test]
    fn verifies_multiple() {
        let mut htpasswd = Htpasswd::new();

        htpasswd.set("foo", "bar")
            .unwrap();

        htpasswd.set("qux", "baz")
            .unwrap();

        let tmp = tempdir()
            .unwrap();

        let htpasswd_file = tmp
            .path()
            .join("passwords")
            .to_str()
            .unwrap()
            .to_string();

        htpasswd.write_to_path(&htpasswd_file)
            .unwrap();

        check(&htpasswd_file, "foo", "bar");
        check(&htpasswd_file, "qux", "baz");
    }
}