mod ciphers;

fn main() {
    let key = ciphers::random_key(16);
    let iv = &key;
    let recovered = recover_key(|message| decrypt_and_test_validity(message, &key, iv));
    assert_eq!(key, recovered);
}

fn decrypt_and_test_validity(text: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    let plaintext = ciphers::decrypt_aes_cbc(text, key, iv);
    if plaintext.iter().any(|c| *c > 128) {
        Some(plaintext)
    } else {
        // no invalid characters found
        None
    }
}

fn recover_key<O: Fn(&[u8]) -> Option<Vec<u8>>>(oracle: O) -> Vec<u8> {
    loop {
        // try until we get an invalid ascii code in the decrypted message (i.e. very soon)
        let c1 = ciphers::random_key(16);
        let res = oracle(&[c1.clone(), vec![0; 16], c1].concat());
        if let Some(text) = res {
            return ciphers::byte_xor(&text[32..], &text[..16]);
        }
    }
}
