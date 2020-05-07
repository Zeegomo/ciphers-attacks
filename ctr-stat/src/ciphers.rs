use jacopone::{Function, Jacopone, Mode, Padder, Padding, Scheduler};
use openssl::memcmp::eq;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode as OMode};
use rand::prelude::*;
use std::iter::repeat;

#[allow(dead_code)]
pub fn random_key(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}
#[allow(dead_code)]
pub fn encrypt_jacopone_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let mut message = text.to_vec();
    let cipher = Jacopone::new(Mode::ECB, Function::Sha3, Scheduler::Dummy, Padding::PKCS7);
    cipher.encrypt(&mut message, key, None);
    message[..text.len()].to_vec()
}
#[allow(dead_code)]
pub fn encrypt_aes_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = encrypt(cipher, key, None, text).expect("AES_256_ECB encryption error");
    plaintext[..text.len()].to_vec()
}
#[allow(dead_code)]
pub fn encrypt_jacopone_ctr(text: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut message = text.to_vec();
    let cipher = Jacopone::new(Mode::CTR, Function::Sha3, Scheduler::Dummy, Padding::PKCS7);
    cipher.encrypt(&mut message, key, Some(nonce));
    message[..text.len()].to_vec()
}
#[allow(dead_code)]
pub fn decrypt_aes_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, text).expect("AES_256_ECB encryption error");
    plaintext[..text.len()].to_vec()
}
#[allow(dead_code)]
pub fn encrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    encrypt(cipher, key, Some(iv), text).expect("AES_256_ECB encryption error")
}
#[allow(dead_code)]
pub fn decrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    decrypt(cipher, key, Some(iv), text).expect("AES_256_ECB encryption error")
}
#[allow(dead_code)]
pub fn encrypt_aes_ctr(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ctr();
    encrypt(cipher, key, Some(iv), text).expect("AES_128_CTR encryption error")
}
#[allow(dead_code)]
pub fn decrypt_aes_ctr(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ctr();
    decrypt(cipher, key, Some(iv), text).expect("AES_128_CTR encryption error")
}
#[allow(dead_code)]
fn byte_xor(byte1: &[u8], byte2: &[u8]) -> Vec<u8> {
    byte1
        .iter()
        .zip(byte2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}
#[allow(dead_code)]
pub fn pad(text: &[u8], len: u8) -> Vec<u8> {
    let mut message = text.to_vec();
    let pl = len as usize - message.len() % len as usize;
    message.extend(repeat(pl as u8).take(pl as usize));
    message
}

lazy_static! {
    static ref SCORE: Vec<u8> = {
        let v = vec![0; 256];
        v['a' as usize] = 8;
        v['e' as usize] = 12;
        v['h' as usize] = 6;
        v['i' as usize] = 7;
        v['n' as usize] = 7;
        v['o' as usize] = 8;
        v['t' as usize] = 8;
        v['s' as usize] = 6;
        v['r' as usize] = 6;
        v['d' as usize] = 4;
        v['l' as usize] = 4;
        v['c' as usize] = 3;
        v['u' as usize] = 3;
        v[' ' as usize] = 12;
    };
}

pub fn get_score(xor: &Vec<u8>) -> u32 {
    let mut score = 0;

    for c in xor {
        score += SCORE[*c as usize];
    }

    for c in xor {
        if *c as u8 > 127 {
            score = 0;
        }
    }

    score
}

pub fn single_byte_xor(string: &[u8], key: u8) -> Vec<u8> {
    string.iter().map(|s| s ^ key).collect()
}
