use jacopone::{Function, Jacopone, Mode, Padder, Padding, Scheduler};
use openssl::memcmp::eq;
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

pub fn encrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let plaintext = encrypt(cipher, key, None, text).expect("AES_256_CBC encryption error");
    plaintext[..text.len()].to_vec()
}

fn byte_xor(byte1: &[u8], byte2: &[u8]) -> Vec<u8> {
    let mut xor = Vec::new();
    for i in 0..byte1.len() {
        xor.push(byte1[i] ^ byte2[i]);
    }
    xor
}

pub fn pad(text: &[u8], len: u8) -> Vec<u8> {
    let mut message = text.to_vec();
    let pl = len as usize - message.len() % len as usize;
    message.extend(repeat(pl as u8).take(pl as usize));
    message
}
