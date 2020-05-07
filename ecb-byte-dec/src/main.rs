mod ciphers;

fn main() {
    let key = ciphers::random_key();
    let secret = String::from("very important secret").as_bytes().to_owned();
    let guessed_jac = byte_ecb(&secret, &key, ciphers::encrypt_jacopone_ecb, 64);
    let guessed_aes = byte_ecb(&secret, &key, ciphers::encrypt_aes_ecb, 16);
    println!(
        "guessed: {}|{}",
        String::from_utf8(guessed_jac).unwrap(),
        String::from_utf8(guessed_aes).unwrap()
    );
}

fn byte_ecb<F: Fn(&[u8], &[u8]) -> Vec<u8>>(
    text: &[u8],
    key: &[u8],
    cipher: F,
    pad_length: u8,
) -> Vec<u8> {
    let message_length = ciphers::pad(text, pad_length).len();
    let mut crafted = Vec::new();
    for _i in 0..message_length {
        crafted.push(0);
    }
    crafted.remove(0);
    crafted.extend_from_slice(text);

    let mut dict = Vec::new();
    let mut guessed = Vec::new();
    let mut ciphertext = cipher(&crafted, key);
    let mut brute_force = vec![0; message_length];

    while crafted.len() >= message_length {
        brute_force = crafted[..message_length].to_vec();
        for i in 0..256 {
            brute_force.pop();
            brute_force.push(i as u8);
            dict = cipher(&brute_force, key);
            if dict == &ciphertext[0..dict.len()] {
                guessed.push(i as u8);
            }
        }

        crafted.remove(0);
        ciphertext = cipher(&crafted, key);
    }
    guessed
}
