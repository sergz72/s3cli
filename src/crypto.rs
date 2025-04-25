use std::io::{Error, ErrorKind};
use base64::Engine;
use base64::engine::general_purpose;

pub trait CryptoProcessor {
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error>;
}

struct NoEncryption {}

impl CryptoProcessor for NoEncryption {
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }

    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }
}

struct ChachaEncryption {
    key: [u8; 32]
}

impl CryptoProcessor for ChachaEncryption {
    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }

    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }
}

impl ChachaEncryption {
    fn new(key_base64: &String) -> Result<Box<dyn CryptoProcessor>, Error> {
        let data = general_purpose::STANDARD.decode(key_base64)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        if data.len() != 32 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid key length"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data.as_slice());
        Ok(Box::new(ChachaEncryption{key}))
    }
}

pub fn build_crypto_processor(encryption_key: Option<&String>) -> Result<Box<dyn CryptoProcessor>, Error> {
    encryption_key
        .map(|key|ChachaEncryption::new(key))
        .unwrap_or(Ok(Box::new(NoEncryption{})))
}
