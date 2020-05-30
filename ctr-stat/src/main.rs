mod ciphers;
use std::io::Read;

fn main() {
    let input_encoded = lines_from_file("data.txt");
    let iv = ciphers::random_key(16);
    let key_aes = ciphers::random_key(16);
    let key_jac = ciphers::random_key(32);
    let (enc_jac, enc_aes) = input_encoded
        .iter()
        .map(|line| base64::decode(line).unwrap())
        .map(|message| {
            (
                ciphers::encrypt_jacopone_ctr(&message.clone(), &key_jac, &iv),
                ciphers::encrypt_aes_ctr(&message, &key_aes, &iv),
            )
        })
        .fold(
            (Vec::new(), Vec::new()),
            |(mut vjac, mut vaes), (jac, aes)| {
                vjac.push(jac);
                vaes.push(aes);
                (vjac, vaes)
            },
        );

    break_ctr(enc_jac);
    break_ctr(enc_aes);
}

fn break_ctr(input: Vec<Vec<u8>>) {
    // the i-th block contains the i-th character of each line
    let block = (0..20)
        .map(|i| input.iter().map(|v| v[i]).collect())
        .collect();
    let keystream = guess_keystream(block);
    println!("keystream: {:?}, len: {}", keystream, keystream.len());
    for line in input {
        println!(
            "plaintext: {}",
            String::from_utf8_lossy(&ciphers::byte_xor(&keystream, &line))
        );
    }
}

fn guess_keystream(text: Vec<Vec<u8>>) -> Vec<u8> {
    let mut round_score;
    let mut best_score;
    let mut best_key;
    let mut xor;
    let mut keystream = Vec::new();
    for line in text {
        best_score = 0;
        best_key = 0;
        for z in 0..255 {
            xor = ciphers::single_byte_xor(&line, z as u8);
            round_score = ciphers::get_score(&xor);
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
    let mut file = match std::fs::File::open(filename) {
        Ok(file) => file,
        Err(_) => panic!("no such file"),
    };
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)
        .expect("failed to read!");
    let lines: Vec<String> = file_contents
        .split('\n')
        .map(|s: &str| s.to_string())
        .collect();
    lines
}
