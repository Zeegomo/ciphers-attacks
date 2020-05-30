use openssl::symm::{decrypt, encrypt, Cipher};
use rand::prelude::*;

pub fn random_key(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

pub fn encrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    encrypt(cipher, key, Some(iv), text).expect("AES_256_ECB encryption error")
}

pub fn decrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    decrypt(cipher, key, Some(iv), text).expect("AES_256_ECB encryption error")
}
