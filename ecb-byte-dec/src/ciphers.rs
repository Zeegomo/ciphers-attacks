use jacopone::{Function, Jacopone, Mode, Padding, Scheduler};
use openssl::symm::{encrypt, Cipher};
use rand::prelude::*;
use std::iter::repeat;

pub fn random_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..32).map(|_| rng.gen::<u8>()).collect()
}

pub fn encrypt_jacopone_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let mut message = text.to_vec();
    let cipher = Jacopone::new(Mode::ECB, Function::Sha3, Scheduler::Dummy, Padding::PKCS7);
    cipher.encrypt(&mut message, key, None);
    message[..text.len()].to_vec()
}

pub fn encrypt_aes_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_ecb();
    let plaintext = encrypt(cipher, key, None, text).expect("AES_256_ECB encryption error");
    plaintext[..text.len()].to_vec()
}

pub fn pad(text: &[u8], len: u8) -> Vec<u8> {
    let mut message = text.to_vec();
    let pl = len as usize - message.len() % len as usize;
    message.extend(repeat(pl as u8).take(pl as usize));
    message
}
