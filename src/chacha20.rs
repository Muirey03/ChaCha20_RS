/* As per https://tools.ietf.org/html/rfc7539#page-24 20/02/2021 */
/* Implementation written by Tommy Muir */

use std::ptr;

pub fn chacha20_string(key: [u8; 32], nonce: [u8; 12], initial_num: u32, plaintext: String) -> Vec<u8> {
	return chacha20(key, nonce, initial_num, plaintext.as_bytes().to_vec());
}

pub fn chacha20(key: [u8; 32], nonce: [u8; 12], initial_num: u32, plaintext: Vec<u8>) -> Vec<u8> {
	let len = plaintext.len();

	let mut ciphertext: Vec<u8> = vec![0; len];

	for n in 0..((len + 63) / 64) { //round up to find number of blocks needed
		let keystream = block(key, nonce, initial_num + n as u32);

		//TODO: 64 bit XORs would be more efficient
		for j in 0..keystream.len() {
			let text_index = n * 64 + j;
			//we won't need to use entire keystream for the final block if len % 64 != 0
			if text_index >= len {
				break; 
			}
			ciphertext[text_index] = plaintext[text_index] ^ keystream[j];
		}
	}

	ciphertext
}

pub fn block(key: [u8; 32], nonce: [u8; 12], block_num: u32) -> [u8; 64] {
	let mut input: [u32; 16] = [0; 16];
	
	populate_input(&mut input, key, nonce, block_num);

	let mut state: [u32; 16] = input.clone();

	//perform the 20 rounds:
	for _n in 0..10 {
		quarter_round(&mut state, 0, 4, 8, 12);
		quarter_round(&mut state, 1, 5, 9, 13);
		quarter_round(&mut state, 2, 6, 10, 14);
		quarter_round(&mut state, 3, 7, 11, 15);

		quarter_round(&mut state, 0, 5, 10, 15);
		quarter_round(&mut state, 1, 6, 11, 12);
		quarter_round(&mut state, 2, 7, 8, 13);
		quarter_round(&mut state, 3, 4, 9, 14);
	}

	//add input to state:
	for n in 0..16 {
		state[n] = state[n].wrapping_add(input[n]);
	}

	//serialize:
	let result: [u8; 64] = [0; 64];
	unsafe {
		ptr::copy(&state as *const u32 as *const u8, &result as *const u8 as *mut u8, 64);
	}
	
	result
}

//populate the inital state
fn populate_input(state: &mut [u32; 16], key: [u8; 32], nonce: [u8; 12], block_num: u32) {
	//populate constants:
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;

	//populate block num:
	state[12] = block_num;

	unsafe {
		//populate key:
		let block_ptr: *const u32 = &*state as *const u32;
		ptr::copy(&key as *const u8, block_ptr.offset(4) as *mut u8, 32);

		//populate nonce:
		let nonce_ptr: *const u32 = &nonce as *const u8 as *const u32;
		state[13] = *nonce_ptr;
		state[14] = *nonce_ptr.offset(1);
		state[15] = *nonce_ptr.offset(2);
	}
}

//rotate n by b bits to the left
fn rot_l(n: u32, b: usize) -> u32 {
	(n << b) | (n >> (32 - b))
}

//chacha20's ARX quarter round algorithm
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
	state[a] = state[a].wrapping_add(state[b]);
	state[d] = rot_l(state[d] ^ state[a], 16);

	state[c] = state[c].wrapping_add(state[d]);
	state[b] = rot_l(state[c] ^ state[b], 12);

	state[a] = state[a].wrapping_add(state[b]);
	state[d] = rot_l(state[d] ^ state[a], 8);

	state[c] = state[c].wrapping_add(state[d]);
	state[b] = rot_l(state[c] ^ state[b], 7);
}
