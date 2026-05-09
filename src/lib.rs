pub mod error;

use std::error::Error;
use base64::{
    engine::general_purpose::STANDARD_NO_PAD,
    Engine,
};
use crate::error::KeyGenError;

pub struct OCA {
    key: Key,
    original_key_fingerprint: u8,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Key {
    pub key: String,
}

impl OCA {
    pub fn new(key: Key) -> Self {
        let original_key_fingerprint = key.key.as_bytes().iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        Self { key, original_key_fingerprint }
    }

    pub fn crypt(&self, msg: &str) -> String {
        let key_len = self.key.key.len() as u8;
        
        let encoded = STANDARD_NO_PAD.encode(msg.as_bytes());
        let encrypted_bytes = self.xor(encoded.as_bytes());
        
        let base64_str = STANDARD_NO_PAD.encode(encrypted_bytes);

        let mut result = Self::caesar_encrypt(&base64_str, key_len);
        result.push('|');
        result.push((self.original_key_fingerprint % 26 + b'a') as char);
        
        result
    }

    pub fn decrypt(&self, msg: &str) -> Result<String, Box<dyn Error>> {
        let parts: Vec<&str> = msg.split('|').collect();
        if parts.len() != 2 {
            return Err(Box::new(crate::error::CryptoError::InvalidFormat));
        }
        
        let stored_fingerprint = parts[1].chars().next().unwrap() as u8;
        let expected_fingerprint = self.original_key_fingerprint % 26 + b'a';
        if stored_fingerprint != expected_fingerprint {
            return Err(Box::new(crate::error::CryptoError::InvalidKey));
        }
        
        let key_len = self.key.key.len() as u8;

        let caesar_decrypted = Self::caesar_decrypt(parts[0], key_len);

        let encrypted_bytes = STANDARD_NO_PAD.decode(caesar_decrypted)?;

        let xor_decrypted_bytes = self.xor(&encrypted_bytes);

        let original_bytes = STANDARD_NO_PAD.decode(xor_decrypted_bytes)?;
        
        Ok(String::from_utf8(original_bytes)?)
    }

    fn xor(&self, data: &[u8]) -> Vec<u8> {
        let key_bytes = self.key.key.as_bytes();
        let mut result = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            result.push(byte ^ key_bytes[i % key_bytes.len()]);
        }

        result
    }
    
    fn caesar_encrypt(text: &str, shift: u8) -> String {
        let shift = (shift % 26) as u8;
        text.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    (((c as u8 - b'A' + shift) % 26) + b'A') as char
                } else if c.is_ascii_lowercase() {
                    (((c as u8 - b'a' + shift) % 26) + b'a') as char
                } else {
                    c
                }
            })
            .collect()
    }   

    fn caesar_decrypt(text: &str, shift: u8) -> String {
        Self::caesar_encrypt(text, 26 - (shift % 26)) 
    }
}

impl Key {
    pub fn new(key: String) -> Result<Self, Box<dyn Error>> {
        if key.len() > 64 {
            return Err(Box::new(KeyGenError::OverFlow));
        }
        if key.len() < 64 {
            return Err(Box::new(KeyGenError::UnderFlow));
        }

        Ok(Self { key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str = "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf";
    const INVALID_KEY: &str = "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdd";

    #[test]
    #[should_panic]
    fn it_rejects_invalid_key() {
        Key::new("short_key".to_string()).unwrap();
    }

    #[test]
    fn it_encrypts_and_decrypts_korean_and_nerd() {
        let key = Key::new(VALID_KEY.to_string()).unwrap();
        let oca = OCA::new(key);
        
        let cases = vec![
            "안녕, 세상!",
            "openoca   master  󱣘 v0.1.0 󰘧 ",
        ];

        for original in cases {
            let encrypted = oca.crypt(original);
            let decrypted = oca.decrypt(&encrypted).unwrap();
            assert_eq!(original, decrypted);
        }
    }

    #[test]
    fn it_cant_decrypt_with_wrong_key() {
        let key = Key::new(VALID_KEY.to_string()).unwrap();
        let oca = OCA::new(key);
        let encrypted = oca.crypt("Secret Message");

        let wrong_key = Key::new(INVALID_KEY.to_string()).unwrap();
        let wrong_oca = OCA::new(wrong_key);
        
        let decrypted = wrong_oca.decrypt(&encrypted);
        
        if let Ok(res) = decrypted {
            assert_ne!(res, "Secret Message");
        }
    }
}
