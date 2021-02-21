mod chacha20;

fn main() {
    /* Test vector 2.4.2 "Sunscreen": */
    let mut key: [u8; 32] = [0; 32];
    for n in 0..32 {
        key[n] = n as u8;
    }

    let mut nonce: [u8; 12] = [0; 12];
    nonce[7] = 0x4a;

    let block_num: u32 = 1;
    let plaintext_str = String::from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    let result = chacha20::chacha20_string(key, nonce, block_num, plaintext_str);
    
    for n in 0..result.len() {
        print!("{:02x} ", result[n]);
        if (n + 1) % 16 == 0 {
            println!("");
        }
    }
    if result.len() % 16 != 0 {
        println!("");
    }
}
