use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyGenError {
    #[error("Key too short")]
    UnderFlow,
    #[error("Key too long")]
    OverFlow
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid key")]
    InvalidKey,
}
