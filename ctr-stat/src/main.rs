mod ciphers;

fn main() {
    let mut input_encoded = lines_from_file("data.txt");
    let iv = ciphers::random_key(16);
    let key_aes = ciphers::random_key(16);
    let key_jac = ciphers::random_key(32);
    let (enc_jac, enc_aes) = input_encoded
        .iter()
        .map(|line| base64::decode(line).unwrap())
        .map(|message| {
            (
                ciphers::encrypt_jacopone_ctr(&message.clone(), &key, &iv),
                ciphers::encrypt_aes_ctr(&message, &key, &iv),
            )
        })
        .fold((Vec::new(), Vec::new()), |(vjac, vaes), (jac, aes)| {
            vjac.push(jac);
            vaes.push(aes);
            (vjac, vaes)
        });

    break_ctr(enc_jac);
    break_ctr(enc_aes);
}

fn break_ctr(input: Vec<Vec<u8>>) {
    let mut block = Vec::new();
    for i in 0..20 {
        block.push(Vec::new());
        for z in 0..input.len() {
            block[i].push(input[z][i]);
        }
    }
    let keystream = guess_keystream(block);
    println!("keystream: {:?}, len: {}", keystream, keystream.len());
    for i in 0..input.len() {
        println!(
            "plaintext: {}",
            String::from_utf8_lossy(&byte_xor(&keystream, &input[i]))
        );
    }
}

fn guess_keystream(text: Vec<Vec<u8>>) -> Vec<u8> {
    let mut round_score = 0;
    let mut best_score = 0;
    let mut best_key = 0;
    let mut xor = Vec::new();
    let mut keystream = Vec::new();
    for i in 0..text.len() {
        best_score = 0;
        best_key = 0;
        for z in 0..255 {
            xor = single_byte_xor(text[i], z as u8);
            round_score = get_score(&xor);
            if round_score > best_score {
                best_key = z;
                best_score = round_score;
            }
        }
        keystream.push(best_key);
    }
    keystream
}

pub fn lines_from_file(filename: &str) -> Vec<String> {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => panic!("no such file"),
    };
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)
        .ok()
        .expect("failed to read!");
    let lines: Vec<String> = file_contents
        .split("\n")
        .map(|s: &str| s.to_string())
        .collect();
    lines
}
