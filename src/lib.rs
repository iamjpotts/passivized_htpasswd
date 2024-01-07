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

use crate::errors::HtpasswdError;

/// Hashing algorithms understood by this library. Does not yet
/// include all algorithms that may present in an htpasswd file
/// or understood by tools that use its file format.
///
/// Examples:
///   * Bcrypt
///       - supported by Docker registry
///       - supported by Nginx
///       - supported by htpasswd
///   * Sha-512
///       - supported by Nginx
///       - unsupported by htpasswd
pub enum Algo {
    /// Use a specific cost. Must be within a range acceptable to bcrypt.
    Bcrypt {
        cost: u32
    },

    /// Fastest, cheapest, and least secure. Useful for automated tests.
    BcryptMinCost,

    /// Use default cost
    BCryptDefault,

    /// Use a specific number of rounds. Must be within a range acceptable to sha-512.
    Sha512 {
        rounds: u32
    },

    /// Use default number of rounds
    Sha512Default,

    /// Fastest, cheapest, and least secure. Useful for automated tests.
    Sha512MinRounds,
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
                // Use bcrypt crate directly, as bcrypt passwords generated by pwhash
                // don't validate by the htpasswd command line tool on Mac's.
                bcrypt::hash_with_result(password, cost)?
                    .format_for_version(Version::TwoA)
            },
            Algo::BCryptDefault => {
                return self.set_with(Algo::Bcrypt { cost: DEFAULT_COST }, username, password)
            }
            Algo::BcryptMinCost => {
                return self.set_with(Algo::Bcrypt { cost: pwhash::bcrypt::MIN_COST }, username, password)
            },
            Algo::Sha512 { rounds } => {
                let setup = pwhash::HashSetup {
                    rounds: Some(rounds),
                    salt: None,  // Results in a random, max-length salt being used.
                };

                pwhash::sha512_crypt::hash_with(setup, password)?
            },
            Algo::Sha512Default => {
                pwhash::sha512_crypt::hash(password)?
            },
            Algo::Sha512MinRounds => {
                return self.set_with(Algo::Sha512 { rounds: pwhash::sha512_crypt::MIN_ROUNDS }, username, password)
            },
        };

        self.entries.insert(username.borrow().to_string(), encrypted);

        Ok(())
    }

    // Private, because not all hash algorithms are implemented yet.
    #[allow(dead_code)]  // Only used by tests
    fn verify<U, P>(&self, username: U, password: P) -> bool
    where
        U: Borrow<str>,
        P: Borrow<str> + AsRef<[u8]>
    {
        if let Some(hashed) = self.entries.get(username.borrow()) {
            pwhash::sha512_crypt::verify(password, hashed)
        }
        else {
            // User not found
            false
        }
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
        let capacity = self.entries
            .iter()
            .map(|(u, p)| 2 + u.len() + p.len())
            .sum();

        let mut result = String::with_capacity(capacity);

        for (u, p) in &self.entries {
            result.push_str(u);
            result.push(':');
            result.push_str(p);
            result.push('\n');
        }

        result
    }
}

#[cfg(test)]
mod test_verifies_against_apache_cli {
    use std::process::Command;
    use tempfile::tempdir;
    use crate::Algo::{BcryptMinCost, Sha512Default, Sha512MinRounds};
    use crate::Htpasswd;

    fn check(file: &str, username: &str, password: &str) {
        let mut cmd = Command::new("htpasswd");
        cmd.args(["-bv", file, username, password]);

        assert_eq!(0, cmd.status().unwrap().code().unwrap());
    }

    #[test]
    fn verifies_bcrypt_min_against_cli() {
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
    fn verifies_multiple_against_cli() {
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

    #[test]
    fn verifies_sha512_default_against_self() {
        let mut htpasswd = Htpasswd::new();

        htpasswd.set_with(Sha512Default, "a", "b")
            .unwrap();

        // Correct password is verified
        assert!(htpasswd.verify("a", "b"));

        // Incorrect password is rejected
        assert!(!htpasswd.verify("a", "c"));
    }

    #[test]
    fn verifies_sha512_min_rounds_against_self() {
        let mut htpasswd = Htpasswd::new();

        htpasswd.set_with(Sha512MinRounds, "a", "b")
            .unwrap();

        // Correct password is verified
        assert!(htpasswd.verify("a", "b"));

        // Incorrect password is rejected
        assert!(!htpasswd.verify("a", "c"));
    }
}