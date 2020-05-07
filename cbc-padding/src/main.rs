mod ciphers;

fn main() {
    let key = ciphers::random_key(16);
    let iv = ciphers::random_key(16);
    let message = "very important secret (do not distribute)";
    let ciphertext = ciphers::encrypt_aes_cbc(message.as_bytes(), &key, &iv);
    println!(
        "{}",
        String::from_utf8_lossy(&padding_oracle(&ciphertext, &key, &iv))
    );
}

fn padding_oracle(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut guessed = Vec::new();
    let mut first_block = iv.to_vec();
    first_block.extend_from_slice(&ciphertext[0..16]);
    guessed.extend(block_padding_oracle(&first_block, key));

    for z in 0..ciphertext.len() / 16 {
        if 16 * z + 32 <= ciphertext.len() {
            guessed.extend(block_padding_oracle(&ciphertext[16 * z..16 * z + 32], key));
        }
    }
    guessed
}

fn block_padding_oracle(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut found;
    let mut crafted = ciphertext.to_vec().clone();
    let mut guessed: Vec<u8> = Vec::new();
    let mut lol = Vec::new();
    let len = ciphertext.len();
    let iv = &[0; 16];
    let mut pre_xor;

    for z in 0..16 {
        found = false;

        while found == false {
            if crafted[len - 17 - z] < 255 {
                crafted[len - 17 - z] += 1;
            } else {
                crafted[len - 17 - z] = 0;
            }
            found = ciphers::validate_padding(&ciphers::decrypt_aes_cbc(&crafted, key, iv));
        }
        pre_xor = ciphers::byte_xor(&[crafted[len - 17 - z]], &[z as u8 + 1])[0];
        lol.push(pre_xor);

        for h in 0..(z + 1) {
            crafted[len - 17 - h] = ciphers::byte_xor(&[lol[h]], &[z as u8 + 2])[0];
        }
        guessed.insert(
            0,
            ciphers::byte_xor(&[pre_xor], &[ciphertext[len - 17 - z]])[0],
        );
    }
    guessed
}
