use std::io::{Error, ErrorKind};
use base64::Engine;
use base64::engine::general_purpose;
use chacha20::ChaCha20;
use chacha20::cipher::crypto_common::rand_core::{OsRng, RngCore};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Sha256, Digest};

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
        let mut iv = [0u8; 12];
        OsRng.try_fill_bytes(&mut iv)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let mut crc = create_hash(&data);
        let bytes = data.as_slice();
        let mut out_vec = self.transform(&iv, bytes)?;
        let mut result = iv.to_vec();
        result.append(&mut out_vec);
        result.append(&mut crc);
        Ok(result)
    }

    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let iv = &data[0..12];
        let encrypted = &data[12..data.len()-32];
        let decrypted = self.transform(iv, encrypted)?;
        let crc = create_hash(&decrypted);
        if crc != data[data.len()-32..] {
            return Err(Error::new(ErrorKind::Other, "Invalid CRC"));
        }
        Ok(decrypted)
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

    fn transform(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cipher = ChaCha20::new((&self.key).into(), iv.into());
        let mut out_vec = vec![0u8; data.len()];
        let out_bytes = out_vec.as_mut_slice();
        cipher.apply_keystream_b2b(data, out_bytes)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        Ok(out_vec)
    }
}

pub fn build_crypto_processor(encryption_key: Option<&String>) -> Result<Box<dyn CryptoProcessor>, Error> {
    encryption_key
        .map(|key|ChachaEncryption::new(key))
        .unwrap_or(Ok(Box::new(NoEncryption{})))
}

fn create_hash(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    Vec::from(hash.as_slice())
}
