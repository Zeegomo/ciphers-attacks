use jacopone::{Function, Jacopone, Mode, Padder, Padding, Scheduler};
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode as OMode};
use rand::prelude::*;
use std::iter::repeat;

#[allow(dead_code)]
pub fn validate_padding(text: &[u8]) -> bool {
    let mut valid = true;
    let len = text.len();
    let last = text[len - 1];
    //println!("len: {}, last: {}",len,last);
    if last as usize >= len {
        valid = false;
    } else {
        for i in len - last as usize..len {
            if text[i] != last {
                valid = false;
            }
        }
    }
    if text[len - 1] == 0 {
        valid = false;
    }

    valid
}
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
pub fn decrypt_aes_ecb(text: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, text).expect("AES_256_ECB encryption error");
    plaintext[..text.len()].to_vec()
}
#[allow(dead_code)]
pub fn encrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), OMode::Encrypt, key, None).unwrap();

    let input = pad(&text, 16);
    let mut ciphertext = Vec::new();
    let mut last = iv.to_vec();
    let mut encrypted = vec![0; 32];
    let mut xored;

    for i in 0..input.len() / 16 {
        //println!("{}",i);
        xored = byte_xor(&input[16 * i..16 * i + 16], &last);
        //println!("input size: {}",input.len());
        decrypter.update(&xored, &mut encrypted).unwrap();
        //println!("encrypted: {:?}, len:{}",encrypted, encrypted.len());

        last.clear();
        for z in 0..16 as usize {
            ciphertext.push(encrypted[z]);
            last.push(encrypted[z]);
        }
    }
    ciphertext
}
#[allow(dead_code)]
pub fn decrypt_aes_cbc(text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), OMode::Decrypt, key, None).unwrap();

    let mut last = iv;
    let mut decrypted = vec![0; 32];
    let mut plaintext = Vec::new();
    let mut xored;
    for i in 0..text.len() / 16 {
        //println!("{}",i);

        decrypter
            .update(&text[16 * i..16 * i + 16], &mut decrypted)
            .unwrap();
        //println!("finalize error");
        //decrypter.finalize(&mut decrypted[count..]).unwrap();
        //decrypted = aes_ebc(&text[16*i..16*i+16],key);
        if i > 0 {
            xored = byte_xor(&decrypted[16..], last);
        } else {
            xored = byte_xor(&decrypted[0..16], last);
        }
        //println!("text: {:?}",&text[16*i..16*i+16]);
        //println!("last: {:?}",last);
        //println!("decrypted: {:?}",decrypted);
        //println!("xored: {:?}",xored);
        last = &text[16 * i..16 * i + 16];
        for z in 0..16 as usize {
            plaintext.push(xored[z]);
        }
    }
    plaintext
}
#[allow(dead_code)]
pub fn byte_xor(byte1: &[u8], byte2: &[u8]) -> Vec<u8> {
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
