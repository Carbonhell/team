//! This module implements the encryption scheme used to safely include private email addresses in
//! the team repository. It generates encrypted content that looks like this:
//!
//! ```text
//! encrypted+bfab2fae1acf74ed9f0df0d3f296f45a620f33ac249e35595dcdfe57ad96d01e54ff770a95111e6cc4d4c2c7f8b34feb42397e67b11d3136e380f1ca878c9a8e924de216d1253252363bbc8fa858cd3ce02bcc9c8f5142@rust-lang.invalid
//! ```
//!
//! The hex-encoded part of the email address is a concatenation of a 32-byte ephemeral x25519 public key,
//! a 24-byte random nonce and the XChaCha20Poly1305-encrypted email address. Utilities are provided
//! to both encrypt and decrypt.

use age::{DecryptError, EncryptError};
use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};

const PREFIX: &str = "encrypted+";
const SUFFIX: &str = "@rust-lang.invalid";

// TODO ask an infra admin to generate one
const PUBLIC_KEY: &str = "age1zgpgqyg4v855k2h6lelcpp8z9nq3pk28c4s2mgw6gr39mvznqvjse6rgs4";


/// Encrypt an email address with x25519-dalek, with blake3 for KDF and ChaCha20Poly1305 for AEAD.
/// The encryption process follows this flow:
/// 1. an ephemeral x25519 key is generated;
/// 2. a shared secret is computed against the public key defined by an infra admin as a constant above;
/// 3. the shared secret is used with a key derivation function (blake3) to generate an uniform symmetric key;
/// 4. the symmetric key is finally used to encrypt the email;
/// 5. the hex-encoded information required for decryption (public key, nonce, encrypted email) is returned as part of a fake email address.
pub fn encrypt_with_public_key(email: &str, public_key: &str) -> Result<String, Error> {
    let pubkey = public_key.parse::<Recipient>().unwrap();
    let encrypted = age::encrypt(&pubkey, email.as_bytes()).map_err(Error::EncryptionFailed)?;

    Ok(format!("{}{}{}", PREFIX, hex::encode(encrypted), SUFFIX))
}

pub fn encrypt(email: &str) -> Result<String, Error> {
    encrypt_with_public_key(email, PUBLIC_KEY)
}

/// Try decrypting an email address encrypted by this module with the provided x25519 private key.
///
/// If the email address was not encrypted by this module it will returned as-is. Because of that
/// you can pass all the email addresses you have through this function.
pub fn try_decrypt(private_key: &str, email: &str) -> Result<String, Error> {
    let encrypted = match email
        .strip_prefix(PREFIX)
        .and_then(|e| e.strip_suffix(SUFFIX))
    {
        Some(encrypted) => hex::decode(encrypted).map_err(Error::Hex)?,
        None => return Ok(email.to_string()),
    };
    
    let key = private_key.parse::<Identity>().map_err(|_| Error::WrongKeyLength)?;
    let decrypted = age::decrypt(&key, &encrypted).map_err(Error::DecryptionFailed)?;
    String::from_utf8(decrypted).map_err(|_| Error::InvalidUtf8)
}

pub fn generate_x25519_keypair() -> (String, String) {
    let key = Identity::generate();
    let pubkey = key.to_public();
    (
        key.to_string().expose_secret().to_owned(),
        pubkey.to_string(),
    )
}

#[derive(Debug)]
pub enum Error {
    Hex(hex::FromHexError),
    EncryptionFailed(EncryptError),
    DecryptionFailed(DecryptError),
    WrongKeyLength,
    InvalidUtf8,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Hex(e) => write!(f, "{e}"),
            Error::EncryptionFailed(e) => write!(f, "{e}"),
            Error::DecryptionFailed(e) => write!(f, "{e}"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8"),
            Error::WrongKeyLength => write!(f, "expected 32-bytes key"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Error> {
        const PRIVATE_KEY: &str =
            "AGE-SECRET-KEY-1LGM6NASLZZR4VAURT5VZPG2PGYEMF6FSD0SJAWLR2MTXKUJYY97Q47KJH3";
        const PUBLIC_KEY: &str = "age1zgpgqyg4v855k2h6lelcpp8z9nq3pk28c4s2mgw6gr39mvznqvjse6rgs4";
        const ADDRESS: &str = "foo@example.com";

        let encrypted = encrypt_with_public_key(ADDRESS, PUBLIC_KEY)?;
        assert!(
            !encrypted.contains(ADDRESS),
            "the encrypted version did contain the plaintext!"
        );

        assert_eq!(ADDRESS, try_decrypt(PRIVATE_KEY, &encrypted)?);

        Ok(())
    }
}
