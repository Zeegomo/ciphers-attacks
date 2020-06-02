mod ciphers;

fn main() {
    let key_jac = ciphers::random_key(32);
    let key_aes = ciphers::random_key(16);
    let iv = ciphers::random_key(16);
    let craft = craft_string(":admin<true:");
    assert!(!detect_admin(craft_string(";admin=true;").as_bytes()));
    let ciphertext_aes = ciphers::encrypt_aes_ctr(craft.as_bytes(), &key_aes, &iv);
    let ciphertext_jac = ciphers::encrypt_jacopone_ctr(craft.as_bytes(), &key_jac, &iv);
    let flipped_aes = bitflip(&ciphertext_aes);
    let flipped_jac = bitflip(&ciphertext_jac);
    assert!(detect_admin(&ciphers::encrypt_aes_ctr(
        &flipped_aes,
        &key_aes,
        &iv
    )));
    assert!(detect_admin(&ciphers::encrypt_jacopone_ctr(
        &flipped_jac,
        &key_jac,
        &iv
    )));
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
    flipped[16 + 16] ^= 1;
    flipped[22 + 16] ^= 1;
    flipped[27 + 16] ^= 1;
    flipped
}
