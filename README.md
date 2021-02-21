#### A quick and dirty implementation of ChaCha20 written in Rust

This is an implementation of ChaCha20 as defined at https://tools.ietf.org/html/rfc7539#page-24.

I mainly wrote this to help me learn Rust, so the code may not be the greatest as this is my first real Rust program.

main.rs includes the test vector 2.4.2 ("Sunscreen") from the same document.

chacha20.rs includes a chacha20 keystream generator and encryptor for strings and data.
