mod ciphers;

fn main() {
    let key = ciphers::random_key(16);
    let iv = ciphers::random_key(16);
    let craft = craft_string(":admin<true:");
    let ciphertext = ciphers::encrypt_aes_cbc(craft.as_bytes(), &key, &iv);
    let flipped = bitflip(&ciphertext);
    assert!(detect_admin(&ciphers::decrypt_aes_cbc(&flipped, &key, &iv)));
}

fn craft_string(input: &str) -> String {
    [
        "comment1=cooking%20MCs;userdata=",
        &input.replace(";", "*").replace("=", "*"),
        ";comment2=%20like%20a%20pound%20of%20bacon",
    ]
    .join("")
}

fn detect_admin(text: &[u8]) -> bool {
    String::from_utf8_lossy(text).contains(";admin=true;")
}

fn bitflip(text: &[u8]) -> Vec<u8> {
    let mut flipped = text.to_vec();
    flipped[16] ^= 1;
    flipped[22] ^= 1;
    flipped[27] ^= 1;
    flipped
}
