mod ciphers;

fn main() {
    let key = ciphers::random_key();
    let secret = String::from("very important secret").as_bytes().to_owned();
    let crypt_jac = |message: &[u8]| ciphers::encrypt_jacopone_ecb(message, &key);
    let crypt_aes = |message: &[u8]| ciphers::encrypt_aes_ecb(message, &key);
    let guessed_jac = byte_ecb(&secret, crypt_jac, 64);
    let guessed_aes = byte_ecb(&secret, crypt_aes, 16);
    println!(
        "guessed: {}|{}",
        String::from_utf8(guessed_jac).unwrap(),
        String::from_utf8(guessed_aes).unwrap()
    );
}

// note that it does not have acces to the key
fn byte_ecb<F: Fn(&[u8]) -> Vec<u8>>(text: &[u8], crypter: F, pad_length: u8) -> Vec<u8> {
    let message_length = ciphers::pad(text, pad_length).len();
    let mut crafted = Vec::new();
    for _i in 0..message_length {
        crafted.push(0);
    }
    crafted.remove(0);
    crafted.extend_from_slice(text);

    let mut dict;
    let mut guessed = Vec::new();
    let mut ciphertext = crypter(&crafted);
    let mut brute_force;

    while crafted.len() >= message_length {
        brute_force = crafted[..message_length].to_vec();
        for i in 0..256 {
            brute_force.pop();
            brute_force.push(i as u8);
            dict = crypter(&brute_force);
            if dict == &ciphertext[0..dict.len()] {
                guessed.push(i as u8);
            }
        }

        crafted.remove(0);
        ciphertext = crypter(&crafted);
    }
    guessed
}
