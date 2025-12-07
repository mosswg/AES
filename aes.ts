import * as $ from "jquery";

// circular left shift
function rotateleft (value: number, count: number): number {
	return (value << count) | (value >>> (32 - count) & 0xffffffff);
}

// sha256(data) returns the digest
// sha256() returns an object you can call .add(data) zero or more time and .digest() at the end
// digest is a 32-byte Uint8Array instance with an added .hex() function.
// Input should be either a string (that will be encoded as UTF-8) or an array-like object with values 0..255.
/// https://github.com/6502/sha256
function sha256(data: string): Uint8Array {
	let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
		h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19,
		tsz = 0, bp = 0;
	const k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
		rrot = rotateleft,
		w = new Uint32Array(64),
		buf = new Uint8Array(64),
		process = () => {
			for (let j=0,r=0; j<16; j++,r+=4) {
				w[j] = (buf[r]<<24) | (buf[r+1]<<16) | (buf[r+2]<<8) | buf[r+3];
			}
			for (let j=16; j<64; j++) {
				let s0 = rrot(w[j-15], 7) ^ rrot(w[j-15], 18) ^ (w[j-15] >>> 3);
				let s1 = rrot(w[j-2], 17) ^ rrot(w[j-2], 19) ^ (w[j-2] >>> 10);
				w[j] = (w[j-16] + s0 + w[j-7] + s1) | 0;
			}
			let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
			for (let j=0; j<64; j++) {
				let S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25),
					ch = (e & f) ^ ((~e) & g),
					t1 = (h + S1 + ch + k[j] + w[j]) | 0,
					S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22),
					maj = (a & b) ^ (a & c) ^ (b & c),
					t2 = (S0 + maj) | 0;
				h = g; g = f; f = e; e = (d + t1)|0; d = c; c = b; b = a; a = (t1 + t2)|0;
			}
			h0 = (h0 + a)|0; h1 = (h1 + b)|0; h2 = (h2 + c)|0; h3 = (h3 + d)|0;
			h4 = (h4 + e)|0; h5 = (h5 + f)|0; h6 = (h6 + g)|0; h7 = (h7 + h)|0;
			bp = 0;
		},
		add = data => {
			if (typeof data === "string") {
				data = typeof TextEncoder === "undefined" ? Buffer.from(data) : (new TextEncoder).encode(data);
			}
			for (let i=0; i<data.length; i++) {
				buf[bp++] = data[i];
				if (bp === 64) process();
			}
			tsz += data.length;
		},
		digest = (): any => {
			buf[bp++] = 0x80; if (bp == 64) process();
			if (bp + 8 > 64) {
				while (bp < 64) buf[bp++] = 0x00;
				process();
			}
			while (bp < 58) buf[bp++] = 0x00;
			// Max number of bytes is 35,184,372,088,831
			let L = tsz * 8;
			buf[bp++] = (L / 1099511627776.) & 255;
			buf[bp++] = (L / 4294967296.) & 255;
			buf[bp++] = L >>> 24;
			buf[bp++] = (L >>> 16) & 255;
			buf[bp++] = (L >>> 8) & 255;
			buf[bp++] = L & 255;
			process();
			let reply = new Uint8Array(32);
			reply[ 0] = h0 >>> 24; reply[ 1] = (h0 >>> 16) & 255; reply[ 2] = (h0 >>> 8) & 255; reply[ 3] = h0 & 255;
			reply[ 4] = h1 >>> 24; reply[ 5] = (h1 >>> 16) & 255; reply[ 6] = (h1 >>> 8) & 255; reply[ 7] = h1 & 255;
			reply[ 8] = h2 >>> 24; reply[ 9] = (h2 >>> 16) & 255; reply[10] = (h2 >>> 8) & 255; reply[11] = h2 & 255;
			reply[12] = h3 >>> 24; reply[13] = (h3 >>> 16) & 255; reply[14] = (h3 >>> 8) & 255; reply[15] = h3 & 255;
			reply[16] = h4 >>> 24; reply[17] = (h4 >>> 16) & 255; reply[18] = (h4 >>> 8) & 255; reply[19] = h4 & 255;
			reply[20] = h5 >>> 24; reply[21] = (h5 >>> 16) & 255; reply[22] = (h5 >>> 8) & 255; reply[23] = h5 & 255;
			reply[24] = h6 >>> 24; reply[25] = (h6 >>> 16) & 255; reply[26] = (h6 >>> 8) & 255; reply[27] = h6 & 255;
			reply[28] = h7 >>> 24; reply[29] = (h7 >>> 16) & 255; reply[30] = (h7 >>> 8) & 255; reply[31] = h7 & 255;
			return reply;
		};
	add(data);
	return digest();
}


function digest_key(value: string): string {
	let d = sha256(value);
	let str = '';
	for (let i: number = 0; i < d.length; i++) {
		str += String.fromCharCode(d[i]);
	}
	return str;
}

function string_to_num_array(str: string): number[] {
	let te = new TextEncoder();
	let out: number[] = [];
	for (let i: number = 0; i < str.length; i++) {
		out.push(te.encode(str[i])[0]);
	}
	return out;
}

function p_row(row: number) {
	let output = "";
	for (let column_index = 0; column_index < 4; column_index++) {
				output += ((row >> (24 - (column_index * 8))) & 0xff).toString(16);
				output += " ";
			}
			console.log(output);
}

function convert_be(data: string): number[] {
	let bits: number = 0;

	let out: number[] = [];

	for (let i = 0; i < data.length; i++) {
		if (bits % 32 == 0) {
			out.push(0);
		}

		out[Math.trunc(bits / 32)] |= ((data[i].charCodeAt(0) << (24 - (bits % 32))) & (0xFF << (24 - (bits % 32))));

		bits += 8;
	}

	return out;
}

function unconvert_be(data: number[]): string {
		let bits: number = 0;
	
		let out: string = '';

		let te = new TextDecoder();
	
		for (let n of data) {
			out += String.fromCharCode(((n >> 24)) & (0xFF));
			out += String.fromCharCode(((n >> 16)) & (0xFF));
			out += String.fromCharCode(((n >> 8)) & (0xFF));
			out += String.fromCharCode(((n)) & (0xFF));
		}
	
		return out;
}

function aes_get_round_constants(rounds: number): number[] {

	let rc: number[] = [];

	for (let round = 1; round <= rounds; round++) {
		if (round == 1) {
			rc[round] = 1;
		} else if (rc[round - 1] < 0x80) {
			rc[round] = 2 * rc[round - 1];
		} else {
			rc[round] = (2 * rc[round - 1]) ^ 0x11b;
		}
	}

	let output: number[] = [];
	for (let round = 1; round <= rounds; round++) {
		output[round] = (rc[round] << 24);
	}

	return output;
}


function aes_rot_word(word: number): number {
	return rotateleft(word, 8);
}

const sbox_matrix: number[][] = [[1, 0, 0, 0, 1, 1, 1, 1],
												[1, 1, 0, 0, 0, 1, 1, 1],
												[1, 1, 1, 0, 0, 0, 1, 1],
												[1, 1, 1, 1, 0, 0, 0, 1],
												[1, 1, 1, 1, 1, 0, 0, 0],
												[0, 1, 1, 1, 1, 1, 0, 0],
												[0, 0, 1, 1, 1, 1, 1, 0],
												[0, 0, 0, 1, 1, 1, 1, 1]];

const sbox_vector: number[] = [1, 1, 0, 0, 0, 1, 1, 0];

// let sbox: number[] = [];
// let inverse_sbox: number[] = [];

const AES_IRREDUCIBLE_POLYNOMIAL: number = 0b100011011;

const sbox: number[] = 
	[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

const inverse_sbox: number[] = 
	[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];


function gf2_8_reduce_product(value: number, polynomial: number): number {
	let polynomial_degree: number = 0; let polynomial_copy: number = polynomial, polynomial_leading_coefficient: number;
	for (; polynomial_copy >> (++polynomial_degree + 1););
	polynomial_leading_coefficient = 1 << polynomial_degree;

	while (value >= polynomial_leading_coefficient) {
		let output_degree: number = 0;
		let output_copy: number = value; polynomial_copy = polynomial;
		for (; output_copy >> (++output_degree + 1););

		let degree_difference: number = output_degree - polynomial_degree;

		let output_bits: number[] = [];

		for (let bit: number = 0; bit < 16; bit++) {
			output_bits[bit] = (value >> bit) & (0b1);
		}

		polynomial_copy = polynomial_copy << degree_difference;

		value ^= polynomial_copy;
	}

	return value;
}

function gf2_8_multiplication(a: number, b: number, polynomial: number) {
	let polynomial_degree: number = 0; let polynomial_copy: number = polynomial, polynomial_leading_coefficient: number;
	for (; polynomial_copy >> (++polynomial_degree + 1););
	polynomial_leading_coefficient = 1 << polynomial_degree;


	let output: number = 0;
	let b_copy: number = b;

	for (let bit: number = 0; bit < 8; bit++) {
		if ((a >> bit) & (0b1)) {
			output ^= b_copy << bit;
		}
	}

	if (output < polynomial_leading_coefficient)
		return output;

	return gf2_8_reduce_product(output, polynomial);
}
/*
/**
 *
 * @param a
 * @param b
 * @return A 16-bit value which is comprised of the quotient in the first 8-bits and the remainder in the last 8-bits
 *-/
uint16_t gf2_8_division(uint16_t a, uint16_t b) {
	if (b == 0) {
		std::cerr << "DIV ERROR: Divide by zero\n";
		exit(1);
	}

	uint8_t b_degree = 0; uint16_t b_copy = b, b_leading_coefficient;
	for (; b_copy >> (b_degree + 1); b_degree++);
	b_leading_coefficient = 1 << b_degree;

	uint8_t quotient = 0;

	while (a >= b_leading_coefficient) {
		uint8_t a_degree = 0;
		b_degree = 0;
		uint16_t a_copy = a;
		b_copy = b;
		for (; a_copy >> (a_degree + 1); a_degree++);
		for (; b_copy >> (b_degree + 1); b_degree++);

		uint8_t degree_difference = a_degree - b_degree;

		b_copy = b_copy << degree_difference;

		quotient |=  0b1 << degree_difference;

		a ^= b_copy;
	}

	return ((quotient << 8) | a);
}


/**
 *
 * @param value - Any value on the fininte field GF(2^8)
 * @param polynomial - any irreducible polynomial in binary (AES uses x^8 + x^4 + x^3 + x + 1 or 0b100011011)
 * @return The <b>value</b>'s inverse
 *
 * Uses the Extended Euclidean algorithm to find the inverse of the given value in GF(2^8).
 *-/
uint8_t gf_2_8_get_value_inverse(const uint8_t value, uint16_t polynomial) {

	std::vector<uint16_t> remainders = {polynomial, value};
	std::vector<uint16_t> quotients = {0};

	uint16_t first_result = gf2_8_division(polynomial, value);

	quotients.push_back((first_result >> 8) & 0xff);
	remainders.push_back(first_result & 0xff);

	for (int n = 2; remainders.back(); n++) {
		uint16_t result = gf2_8_division(remainders[n - 1], remainders[n]);

		quotients.push_back((result >> 8) & 0xff);
		remainders.push_back(result & 0xff);
	}

	uint8_t aux[quotients.size() + 1];

	aux[0] = 0; aux[1] = 1;

	for (int n = 2; n < quotients.size() + 1; n++) {
		aux[n] = aux[n - 2] ^ gf2_8_multiplication(quotients[n - 1], aux[n - 1], polynomial);
	}

	return aux[quotients.size() - 1];
}

uint8_t aes_generate_sbox_value(uint8_t value) {
	uint8_t inverse = 0;
	if (value != 0) {
		inverse = gf_2_8_get_value_inverse(value, AES_IRREDUCIBLE_POLYNOMIAL);
	}
	uint8_t result = 0;

	uint8_t current_bit;

	for (int bit = 0; bit < 8; bit++) {
		current_bit = ((sbox_matrix[bit][0] * (inverse & 0b00000001)) ^
					(sbox_matrix[bit][1] * ((inverse & 0b00000010) >> 1)) ^
					(sbox_matrix[bit][2] * ((inverse & 0b00000100) >> 2)) ^
					(sbox_matrix[bit][3] * ((inverse & 0b00001000) >> 3)) ^
					(sbox_matrix[bit][4] * ((inverse & 0b00010000) >> 4)) ^
					(sbox_matrix[bit][5] * ((inverse & 0b00100000) >> 5)) ^
					(sbox_matrix[bit][6] * ((inverse & 0b01000000) >> 6)) ^
					(sbox_matrix[bit][7] * ((inverse & 0b10000000) >> 7))) ^
					sbox_vector[bit];

		result |= current_bit << bit;
	}

	return result;
}


void aes_generate_sbox() {
	delete[] sbox;
	sbox = new uint8_t[256];

	for (int value = 0; value < 256; value++) {
		sbox[value] = aes_generate_sbox_value(value);
	}
}

void aes_generate_inverse_sbox() {
	delete[] inverse_sbox;
	inverse_sbox = new uint8_t[256];

	for (int index = 0; index < 256; index++) {
		inverse_sbox[sbox[index]] = index;
	}
}
*/

function aes_sub_word8(word: number): number {
	/*
	if (!sbox) {
		aes_generate_sbox();
	}
	*/

	return sbox[word];
}

function aes_sub_word32(word: number): number {
	let out: number = 0;

	out |= aes_sub_word8((word >> 24) & 0xff) << 24;
	out |= aes_sub_word8((word >> 16) & 0xff) << 16;
	out |= aes_sub_word8((word >> 8) & 0xff) << 8;
	out |= aes_sub_word8(word & 0xff);

	return out;
}


function aes_inverse_sub_word8(word: number): number {
	/*
	if (!inverse_sbox) {
		aes_generate_inverse_sbox();
	}
	*/

	return inverse_sbox[word];
}

function aes_inverse_sub_word32(word: number): number {
	let out: number = 0;

	out |= aes_inverse_sub_word8((word >> 24) & 0xff) << 24;
	out |= aes_inverse_sub_word8((word >> 16) & 0xff) << 16;
	out |= aes_inverse_sub_word8((word >> 8) & 0xff) << 8;
	out |= aes_inverse_sub_word8(word & 0xff);

	return out;
}

/**
 *
 * @param n - length of key (4 for 128-bit)
 * @param key - key as a vector of uint32_t
 * @param r - number of rounds (11 for 128-bit)
 * @return a vector of round keys
 */
function aes_get_round_keys(n: number, key: number[], r: number): number[] {
	let w: number[] = [];
	let rc: number[] = aes_get_round_constants(r);


	for (let round: number = 0; round <= n * r; round++) {
		if (round < n) {
			w[round] = key[round];
		}
		else if ((round % n) == 0) {
			w[round] = (w[round - n] ^ (aes_sub_word32(aes_rot_word(w[round - 1])))) ^ rc[Math.trunc(round / n)];
		}
		else if (n > 6 && (round % n) == 4) {
			w[round] = w[round - n] ^ aes_sub_word32(w[round - 1]);
		}
		else {
			w[round] = w[round - n] ^ w[round - 1];
		}
	}

	return w;
}


function aes_add_round_key(state: number[], round_key: number[]): number[] {
	for (let byte_index: number = 0; byte_index < 4; byte_index++) {
		state[byte_index] ^= round_key[byte_index];
	}
	return state;
}

/**
 * @param state
 * @param row_index
 * @return the row in the state at row_index
 *
 * Since the state is stored rotated from how AES operates we need to go through all the columns in the state and grab one byte of the row from each.
 */
function aes_extract_row(state: number[], row_index: number): number {
	let row: number = 0;
	for (let col: number = 0; col < 4; col++) {
		row |= ((state[col] >>> (24 - (row_index * 8))) & 0xff) << (24 - (8 * col));
	}
	return row;
}

/**
 * @param state
 * @param row
 * @param row_index
 *
 * Since the state is stored rotated from how AES operates we need to go through all the columns in the state and put one byte of the row into each.
 */
function aes_emplace_row(state: number[], row: number, row_index: number): number[] {
	for (let col: number = 0; col < 4; col++) {
		state[col] &= ~(0xff << (24 - (row_index * 8)));
		state[col] |= (((row >>> (24 - (col * 8))) & 0xff) << (24 - (row_index * 8)));
	}
	return state;
}

function aes_print_state(state: number[]) {
	let output: string = "";
	for (let row_index: number = 0; row_index < 4; row_index++) {
		let row: number = aes_extract_row(state, row_index);
		for (let column_index: number = 0; column_index < 4; column_index++) {
			output += ((row >>> (24 - (column_index * 8))) & 0xff).toString(16);
			output += " ";
		}
		output += "\n";
	}
	console.log(output);
}


function aes_shift_rows(state: number[]): number[] {
	let tmp: number[] = [];

	for (let row_index: number = 0; row_index < 4; row_index++) {
		let row: number = aes_extract_row(state, row_index);

		tmp[row_index] = row << (row_index * 8);
		tmp[row_index] |= row >>> (32 - (row_index * 8));
	}

	for (let row_index: number = 0; row_index < 4; row_index++) {
		state = aes_emplace_row(state, tmp[row_index], row_index);
	}
	return state;
}

function aes_reverse_shift_rows(state: number[]): number[] {
	let tmp: number[] = [];

	for (let row_index: number = 0; row_index < 4; row_index++) {
		let row: number = aes_extract_row(state, row_index);

		tmp[row_index] = row >>> (row_index * 8);
		tmp[row_index] |= row << (32 - (row_index * 8));
	}

	for (let row_index: number = 0; row_index < 4; row_index++) {
		state = aes_emplace_row(state, tmp[row_index], row_index);
	}
	return state;
}

function aes_mix_column_multiply(a: number, b: number): number {
	return gf2_8_multiplication(a, b, AES_IRREDUCIBLE_POLYNOMIAL);
}
/**
 *
 * @param value - a column from the state
 * @return the column after applying the mix to it
 *
 *  This is one implementation of the mix column function that uses matrix multiplication. I prefer the polynomial multiplication for its understandability but this also a correct implementation.
 */
function aes_mix_column_matrix(value: number): number {
	let b: number[] = [((value >>> 24) & 0xff), ((value >>> 16) & 0xff),
					((value >>> 8) & 0xff), (value & 0xff)];

	let d: number[] = [((aes_mix_column_multiply(2, b[0]) ^ aes_mix_column_multiply(3, b[1]) ^ b[2] ^ b[3]) & 0xff),
				(aes_mix_column_multiply(2, b[1]) ^ aes_mix_column_multiply(3, b[2]) ^ b[3] ^ b[0]) & 0xff,
				(aes_mix_column_multiply(2, b[2]) ^ aes_mix_column_multiply(3, b[3]) ^ b[0] ^ b[1]) & 0xff,
				(aes_mix_column_multiply(2, b[3]) ^ aes_mix_column_multiply(3, b[0]) ^ b[1] ^ b[2]) & 0xff];

	return (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
}

/**
 * @param value - a column from the state
 * @return the column after applying the mix to it
 *
 * This is my preferred implementation of the mix column function that uses polynomial multiplication. I prefer it because it uses the math that the matrix multiplication is derived from. This implementation doesn't use magical constants, and so I have an easier time understanding it.
 */
function aes_mix_column_polynomial(value: number): number {
	let a: number[] = [2, 1, 1, 3];
	let b: number[] = [((value >> 24) & 0xff), ((value >> 16) & 0xff),
				((value >> 8) & 0xff), (value & 0xff)];
	let c: number[] = [aes_mix_column_multiply(a[0], b[0]),
				((aes_mix_column_multiply(a[1], b[0]) ^ aes_mix_column_multiply(a[0], b[1]))),
				((aes_mix_column_multiply(a[2], b[0]) ^ aes_mix_column_multiply(a[1], b[1])) ^ aes_mix_column_multiply(a[0], b[2])),
				((aes_mix_column_multiply(a[3], b[0]) ^ aes_mix_column_multiply(a[2], b[1])) ^ aes_mix_column_multiply(a[1], b[2]) ^ aes_mix_column_multiply(a[0], b[3])),
				((aes_mix_column_multiply(a[3], b[1]) ^ aes_mix_column_multiply(a[2], b[2])) ^ aes_mix_column_multiply(a[1], b[3])),
				((aes_mix_column_multiply(a[3], b[2]) ^ aes_mix_column_multiply(a[2], b[3]))),
				aes_mix_column_multiply(a[3], b[3])];

	return ((c[0] ^ c[4]) << 24) | ((c[1] ^ c[5]) << 16) | ((c[2] ^ c[6]) << 8) | c[3];
}

// This is an alternative inverse which is harder to understand in my opinion, but I left it in in case it help someone understand.
//uint32_t aes_inverse_mix_column(uint32_t value) {
//    uint16_t d[] = {(uint8_t)((value >> 24) & 0xff), (uint8_t)((value >> 16) & 0xff),
//                    (uint8_t)((value >> 8) & 0xff), (uint8_t)(value & 0xff)};
//
//    uint8_t b[] = {(uint8_t)(aes_mix_column_multiply(14, b[0]) ^ aes_mix_column_multiply(11, b[1]) ^ aes_mix_column_multiply(13, b[2]) ^ aes_mix_column_multiply(9, b[3])),
//                   (uint8_t)(aes_mix_column_multiply(9, b[0]) ^ aes_mix_column_multiply(14, b[1]) ^ aes_mix_column_multiply(11, b[2]) ^ aes_mix_column_multiply(13, b[3])),
//                   (uint8_t)(aes_mix_column_multiply(13, b[0]) ^ aes_mix_column_multiply(9, b[1]) ^ aes_mix_column_multiply(14, b[2]) ^ aes_mix_column_multiply(11, b[3])),
//                   (uint8_t)(aes_mix_column_multiply(11, b[0]) ^ aes_mix_column_multiply(13, b[1]) ^ aes_mix_column_multiply(9, b[2]) ^ aes_mix_column_multiply(14, b[3]))};
//
//    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
//}

function aes_inverse_mix_column(value: number): number {
	const polynomial: number = 0b00011011;
	let a: number[] = [2, 1, 1, 3];
	let d: number[] = [((value >> 24) & 0xff), ((value >> 16) & 0xff),
					((value >> 8) & 0xff), (value & 0xff)];


	// 14 11 13 9
	// 9 14 11 13
	// 13 9 14 11
	// 11 13 9 14
	let m: number[] = [14, 11, 13, 9];

	let b: number[] = [];


	for (let column_index: number = 0; column_index < 4; column_index++) {
		b[column_index] = aes_mix_column_multiply(m[0], d[0]) ^
						aes_mix_column_multiply(m[1], d[1]) ^
						aes_mix_column_multiply(m[2], d[2]) ^
						aes_mix_column_multiply(m[3], d[3]);

		let tmp: number = m[3];
		m[3] = m[2];
		m[2] = m[1];
		m[1] = m[0];
		m[0] = tmp;
	}

	return (b[3]) | (b[2] << 8) | (b[1] << 16) | (b[0] << 24);
}

/**
 * @param state
 * @param column_index
 * @return The column of the state at the given index.
 *
 * This takes the column by simply indexing the array because the state is actually rotated 90 degrees from the way it's stored. This is quirk of AES.
 */
function aes_extract_column(state: number[], column_index: number): number {
	return state[column_index];
}

/**
 * @param state
 * @param column
 * @param column_index
 *
 * This places the column into the state based on the column index. It indexes the array directly to place the column because the state is actually rotated 90 degrees from the way it's stored. This is quirk of AES.
 */
function aes_emplace_column(state: number[], column: number, column_index: number): number[] {
	state[column_index] = column;
	return state;
}

//uint32_t aes_extract_column(const std::vector<uint32_t>& state, uint8_t column_index) {
//    uint32_t column = 0;
//    for (uint8_t row = 0; row < 4; row++) {
//        column |= ((state[row] >> (24 - (column_index * 8))) & 0xff) << (24 - (8 * row));
//    }
//    return column;
//}
//
//void aes_emplace_column(std::vector<uint32_t>& state, uint32_t column, uint8_t column_index) {
//    for (uint8_t row = 0; row < 4; row++) {
//        state[row] &= ~(0xff << (24 - (column_index * 8)));
//        state[row] |= (((column >> (24 - (row * 8))) & 0xff) << (24 - (column_index * 8)));
//    }
//}


function aes_mix_columns(state: number[]): number[] {

	for (let column_index: number = 0; column_index < 4; column_index++) {

		let column: number = aes_extract_column(state, column_index);

		column = aes_mix_column_polynomial(column);

		state = aes_emplace_column(state, column, column_index);
	}
	return state;
}

function aes_inverse_mix_columns(state: number[]): number[] {

	for (let column_index: number = 0; column_index < 4; column_index++) {

		let column: number = aes_extract_column(state, column_index);

		column = aes_inverse_mix_column(column);

		state = aes_emplace_column(state, column, column_index);
	}
	return state;
}


/**
 *
 *
 * |  128 bit  |  192 bit  |  256 bit  |
 * |  10 round |  12 round |  14 round |
 *
 * 16 byte key
 *
 * ----------------------
 * | k0 | k4 | k8 | kc |
 * | k1 | k5 | k9 | kd |
 * | k2 | k6 | ka | ke |
 * | k3 | k7 | kb | kf |
 * ----------------------
 *
 * expand using to get round keys
 *
 * round keys are
 * rij where i is the round and j is the byte index in hex
 * e.g. 5th byte from 3rd round: r35
 * e.g. 14th byte from the 12th round: rbd
 *
 *
 * 16 byte message
 *
 * ----------------------
 * | m0 | m4 | m8 | mc |
 * | m1 | m5 | m9 | md |
 * | m2 | m6 | ma | me |
 * | m3 | m7 | mb | mf |
 * ----------------------
 *
 * Xor the original key with the message
 *
 * ai = mi ^ ki
 * 
 * ----------------------
 * | a0 | a4 | a8 | ac |
 * | a1 | a5 | a9 | ad |
 * | a2 | a6 | aa | ae |
 * | a3 | a7 | ab | af |
 * ----------------------
 *
 * For each round
 *
 * Sub-byte the state
 *
 * si = subbyte(ai)
 *
 * ----------------------
 * | s0 | s4 | s8 | sc |
 * | s1 | s5 | s9 | sd |
 * | s2 | s6 | sa | se |
 * | s3 | s7 | sb | sf |
 * ----------------------
 *
 * Shift rows
 * ----------------------
 * | s0 | s4 | s8 | sc |
 * | s5 | s9 | sd | s1 |
 * | sa | se | s2 | s6 |
 * | sf | s3 | s7 | sb |
 * ----------------------
 *
 *
 *
 *
 */
const rounds: number = 10;
const key_len: number = 4;
function aes_encrypt(message: string, key: string): number[] {
	console.log("Encrypting \"", message, "\" with key: ", key, '\n');

	/// Split into 16 byte chunks
	if (message.length > 16) {
		let out: number[] = [];
		for (let chunk_index: number = 0; (chunk_index * 16) < message.length; chunk_index++) {
			let sub_result: number[] = aes_encrypt(message.substr(chunk_index * 16, 16), key);
			out.concat(sub_result);
		}
		return out;
	}
	else if (message.length != 16) {
		let te = new TextDecoder();
		message += '\x80';

		while (message.length != 16) {
			message += '\x00';
		}
	}


	let key_uint: number[] = convert_be(digest_key(key));
	/// Create round keys
	let round_keys: number[] = aes_get_round_keys(key_len, key_uint, rounds + 1);

	/// Rotate the state
	let state: number[] = convert_be(message);
	console.log("Initial State:\n");
	aes_print_state(state);

	/// Add original key to state.
	state = aes_add_round_key(state, round_keys);
	console.log("First Round Key:\n");
	aes_print_state(state);

	for (let round: number = 1; round < rounds; round++) {
		/// Sub-byte the state
		for (let i = 0; i < state.length; i++) {
			state[i] = aes_sub_word32(state[i]);
		}
		console.log(round, " Round s-box:\n");
		aes_print_state(state);

		/// Shift Rows
		state = aes_shift_rows(state);
		console.log(round, " Round row shift:\n");
		aes_print_state(state);

		/// Mix Columns
		state = aes_mix_columns(state);
		console.log(round, " Round mix:\n");
		aes_print_state(state);

		// Add Round Key
		state = aes_add_round_key(state, round_keys.slice((round * key_len)));
		console.log(round, " Round add round key:\n");
		aes_print_state(state);
	}


	/// Sub-byte the state
	for (let i = 0; i < state.length; i++) {
		state[i] = aes_sub_word32(state[i]);
	}
	console.log(" Last Round S-Box:\n");
	aes_print_state(state);

	/// Shift Rows
	state = aes_shift_rows(state);
	console.log(" Last Round Shift Rows:\n");
	aes_print_state(state);

	// Add Round Key
	state = aes_add_round_key(state, round_keys.slice(rounds * key_len));
	console.log(" Last Round key:\n");
	aes_print_state(state);

	return state;
}

class aes_state {
	state: number[] = [];
	prestep_state: number[] = [];
	round_keys: number[] = [];
	first_round_key: boolean = false;
	round: number = 1;
	round_step: number = 0;
	substep_index: number = 0;
	last_sub: boolean = false;
	last_shift: boolean = false;
	last_round_key: boolean = false;
	done: boolean = false;
	decrypt: boolean = false;
}

function aes_start(message: string, key: string): aes_state {
	console.log("Encrypting \"", message, "\" with key: ", key, '\n');

	/// Split into 16 byte chunks
	if (message.length > 16) {
		console.log("Cannot display encryption with messsage longer than 16 bytes")
	}
	else if (message.length != 16) {
		let te = new TextDecoder();
		message += '\x80';

		while (message.length != 16) {
			message += '\x00';
		}
	}

	let key_uint: number[] = convert_be(digest_key(key));
	/// Create round keys
	let round_keys: number[] = aes_get_round_keys(key_len, key_uint, rounds + 1);

	/// Rotate the state
	let state: number[] = convert_be(message);
	console.log("Initial State:\n");
	aes_print_state(state);

	let out: aes_state = new aes_state();
	out.state = state;
	out.round_keys = round_keys;
	return out;
}

function aes_step(state: aes_state): aes_state {
	if (state.decrypt) {
		return aes_decrypt_step(state);
	}
	for (let i: number = 0; i < key_len; i++) {
		$("#aes-state-col-" + i).css("background", "initial");
		$("#aes-state-2-col-" + i).css("background", "initial");
		$("#aes-state-3-col-" + i).css("background", "initial");
		for (let j: number = 0; j < key_len; j++) {
			$("#aes-" + i + "-" +j).css("background", "initial");
			$("#aes-2-" + i + "-" +j).css("background", "initial");
			$("#aes-3-" + i + "-" +j).css("background", "initial");
		}
	}
	state.substep_index = 0;
	if (!state.first_round_key) {
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys, "#aes-2-");
		state.state = aes_add_round_key(state.state, state.round_keys);
		console.log("First Round Key:\n");
		$("#aes-2-3-symbol").html("=");
		display_aes_state(state.state, "#aes-3-");
		$("#aes-step-name").html("Add Round Key");
		state.first_round_key = true;
		return state;
	}
	if (state.round < rounds) {
		switch (state.round_step) {
			case 0:
				/// do sb
				/// Sub-byte the state
				display_aes_state(state.state);
				$("#aes-1-2-symbol").html("->");
				display_aes_sbox(state.state, "#aes-2-");
				for (let i = 0; i < state.state.length; i++) {
					state.state[i] = aes_sub_word32(state.state[i]);
				}
				$("#aes-2-3-symbol").html("=");
				display_aes_state(state.state, "#aes-3-");
				console.log(state.round, " Round s-box:\n");
				$("#aes-step-name").html("Round " + state.round + " Substitution-box");
				break;
			case 1:
				/// do shift
				/// Shift Rows
				display_aes_state(state.state);
				state.state = aes_shift_rows(state.state);
				display_aes_state(state.state, "#aes-2-");
				$("#aes-3-state").addClass("hidden");
				console.log(state.round, " Round row shift:\n");
				$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&lt;&lt; 0</div><div style="font-size: 1.5rem;">&lt;&lt; 1</div><div style="font-size: 1.5rem;">&lt;&lt; 2</div><div style="font-size: 1.5rem;">&lt;&lt; 3</div>');
				$("#aes-2-3-symbol").html("");
				$("#aes-step-name").html("Round " + state.round + " Shift Rows");
				break;
			case 2:
				/// do mix
				/// Mix Columns
				display_aes_state(state.state);
				state.state = aes_mix_columns(state.state);
				console.log(state.round, " Round mix:\n");
				display_aes_state(state.state, "#aes-2-");
				$("#aes-3-state").addClass("hidden");
				$("#aes-1-2-symbol").html("->");
				$("#aes-2-3-symbol").html("");
				$("#aes-step-name").html("Round " + state.round + " Mix Columns");
				break;
			case 3:
				/// add key
				display_aes_state(state.state);
				$("#aes-1-2-symbol").html("&oplus;");
				display_aes_state(state.round_keys, "#aes-2-");
				state.state = aes_add_round_key(state.state, state.round_keys.slice((state.round * key_len)));
				console.log(state.round, " Round Key:\n");
				$("#aes-2-3-symbol").html("->")
				display_aes_state(state.state, "#aes-3-");
				$("#aes-step-name").html("Round " + state.round + " Add Round Key");
				state.round++;
				/// Dont reset on the last round so that we are in the right state for decryption
				if (state.round < rounds) {
					state.round_step = 0;
				}
				return state
			default:
				console.error("out of bounds round step");
		}
		state.round_step++;
		return state;
	}
	if (!state.last_sub) {
		/// do sb
		/// Sub-byte the state
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("->");
		display_aes_sbox(state.state, "#aes-2-");
		for (let i = 0; i < state.state.length; i++) {
			state.state[i] = aes_sub_word32(state.state[i]);
		}
		$("#aes-2-3-symbol").html("=");
		display_aes_state(state.state, "#aes-3-");
		console.log(state.round, " Round s-box:\n");
		$("#aes-step-name").html("Last Substitution-box");
		state.last_sub = true;
		return state;
	}
	if (!state.last_shift) {
		/// do shift
		/// Shift Rows
		display_aes_state(state.state);
		state.state = aes_shift_rows(state.state);
		display_aes_state(state.state, "#aes-2-");
		$("#aes-3-state").addClass("hidden");
		console.log(state.round, " Round row shift:\n");
		$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&lt;&lt; 0</div><div style="font-size: 1.5rem;">&lt;&lt; 1</div><div style="font-size: 1.5rem;">&lt;&lt; 2</div><div style="font-size: 1.5rem;">&lt;&lt; 3</div>');
		$("#aes-2-3-symbol").html("");
		$("#aes-step-name").html("Last Shift Rows");
		state.last_shift = true;
		return state;
	}
	
	if (!state.last_round_key) {
		/// add key
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys.slice(state.round * key_len), "#aes-2-");
		state.state = aes_add_round_key(state.state, state.round_keys.slice((state.round * key_len)));
		console.log(state.round, " Round Key:\n");
		$("#aes-2-3-symbol").html("->")
		display_aes_state(state.state, "#aes-3-");
		$("#aes-step-name").html("Last Add Round Key");
		state.last_round_key = true;
		return state;
	}

	state.done = true;
	display_aes_state(state.state);
	$("#aes-step-name").html("Encryption Result");
	$("#aes-1-2-symbol").html("");
	$("#aes-2-3-symbol").html("");
	$("#aes-2-state").addClass("hidden");
	$("#aes-3-state").addClass("hidden");
    $("#aes-submit-button").addClass("hidden");
    $("#aes-next-button").addClass("hidden");
    $("#aes-substep-button").addClass("hidden");
    $("#aes-decrypt-button").removeClass("hidden");
	return state;
}

function aes_decrypt_step(state: aes_state): aes_state {
	for (let i: number = 0; i < key_len; i++) {
		$("#aes-state-col-" + i).css("background", "initial");
		$("#aes-state-2-col-" + i).css("background", "initial");
		$("#aes-state-3-col-" + i).css("background", "initial");
		for (let j: number = 0; j < key_len; j++) {
			$("#aes-" + i + "-" +j).css("background", "initial");
			$("#aes-2-" + i + "-" +j).css("background", "initial");
			$("#aes-3-" + i + "-" +j).css("background", "initial");
		}
	}

	state.substep_index = 0;
	if (state.last_round_key) {
		/// add key
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys.slice(state.round * key_len), "#aes-2-");
		state.state = aes_add_round_key(state.state, state.round_keys.slice((state.round * key_len)));
		console.log(state.round, " Round Key:\n");
		$("#aes-2-3-symbol").html("->")
		display_aes_state(state.state, "#aes-3-");
		$("#aes-step-name").html("Last Add Round Key");
		state.last_round_key = false;
		state.round--;
		return state;
	}
	if (state.last_shift) {
		/// do shift
		/// Shift Rows
		display_aes_state(state.state);
		state.state = aes_reverse_shift_rows(state.state);
		display_aes_state(state.state, "#aes-2-");
		$("#aes-3-state").addClass("hidden");
		console.log(state.round, " Round row shift:\n");
		$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&gt;&gt; 0</div><div style="font-size: 1.5rem;">&gt;&gt; 1</div><div style="font-size: 1.5rem;">&gt;&gt; 2</div><div style="font-size: 1.5rem;">&gt;&gt; 3</div>');
		$("#aes-2-3-symbol").html("");
		$("#aes-step-name").html("Last Shift Rows");
		state.last_shift = false;
		return state;
	}
	if (state.last_sub) {
		/// do sb
		/// Sub-byte the state
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("->");
		display_aes_sbox(state.state, "#aes-2-", true);
		for (let i = 0; i < state.state.length; i++) {
			state.state[i] = aes_inverse_sub_word32(state.state[i]);
		}
		$("#aes-2-3-symbol").html("=");
		display_aes_state(state.state, "#aes-3-");
		console.log(state.round, " Round s-box:\n");
		$("#aes-step-name").html("Last Substitution-box");
		state.last_sub = false;
		return state;
	}
	if (state.round > 0) {
		switch (state.round_step) {
			case 0:
				/// do sb
				/// Sub-byte the state
				display_aes_state(state.state);
				$("#aes-1-2-symbol").html("->");
				display_aes_sbox(state.state, "#aes-2-", true);
				for (let i = 0; i < state.state.length; i++) {
					state.state[i] = aes_inverse_sub_word32(state.state[i]);
				}
				$("#aes-2-3-symbol").html("=");
				display_aes_state(state.state, "#aes-3-");
				console.log(state.round, " Round s-box:\n");
				$("#aes-step-name").html("Round " + state.round + " Substitution-box");
				state.round_step = 4;
				state.round--;
				break;
			case 1:
				/// do shift
				/// Shift Rows
				display_aes_state(state.state);
				state.state = aes_reverse_shift_rows(state.state);
				display_aes_state(state.state, "#aes-2-");
				$("#aes-3-state").addClass("hidden");
				console.log(state.round, " Round row shift:\n");
				$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&gt;&gt; 0</div><div style="font-size: 1.5rem;">&gt;&gt; 1</div><div style="font-size: 1.5rem;">&gt;&gt; 2</div><div style="font-size: 1.5rem;">&gt;&gt; 3</div>');
				$("#aes-2-3-symbol").html("");
				$("#aes-step-name").html("Round " + state.round + " Shift Rows");
				break;
			case 2:
				/// do mix
				/// Mix Columns
				display_aes_state(state.state);
				state.state = aes_inverse_mix_columns(state.state);
				console.log(state.round, " Round mix:\n");
				display_aes_state(state.state, "#aes-2-");
				$("#aes-3-state").addClass("hidden");
				$("#aes-1-2-symbol").html("->");
				$("#aes-2-3-symbol").html("");
				$("#aes-step-name").html("Round " + state.round + " Mix Columns");
				break;
			case 3:
				/// add key
				display_aes_state(state.state);
				$("#aes-1-2-symbol").html("&oplus;");
				display_aes_state(state.round_keys.slice(state.round * key_len), "#aes-2-");
				state.state = aes_add_round_key(state.state, state.round_keys.slice((state.round * key_len)));
				console.log(state.round, " Round Key:\n");
				$("#aes-2-3-symbol").html("->")
				display_aes_state(state.state, "#aes-3-");
				$("#aes-step-name").html("Round " + state.round + " Add Round Key");
				break;
			default:
				console.error("out of bounds round step");
		}
		state.round_step--;
		return state;
	}
	if (state.first_round_key) {
		display_aes_state(state.state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys, "#aes-2-");
		state.state = aes_add_round_key(state.state, state.round_keys);
		console.log("First Round Key:\n");
		$("#aes-2-3-symbol").html("=");
		display_aes_state(state.state, "#aes-3-");
		$("#aes-step-name").html("Add Round Key");
		state.first_round_key = false;
		return state;
	}

	
	state.done = true;
	display_aes_original(unconvert_be(state.state));
	$("#aes-step-name").html("Decryption Result");
	$("#aes-1-2-symbol").html("");
	$("#aes-2-3-symbol").html("");
	$("#aes-2-state").addClass("hidden");
	$("#aes-3-state").addClass("hidden");
	$("#aes-submit-button").val("Start Over");
	$("#aes-submit-button").removeClass("hidden");
    $("#aes-next-button").addClass("hidden");
    $("#aes-substep-button").addClass("hidden");
    $("#aes-decrypt-button").addClass("hidden");
	return state;
}


function aes_substep(state: aes_state): aes_state {
	for (let i: number = 0; i < key_len; i++) {
		$("#aes-state-col-" + i).css("background", "initial");
		$("#aes-state-2-col-" + i).css("background", "initial");
		$("#aes-state-3-col-" + i).css("background", "initial");
		for (let j: number = 0; j < key_len; j++) {
			$("#aes-" + i + "-" +j).css("background", "initial");
			$("#aes-2-" + i + "-" +j).css("background", "initial");
			$("#aes-3-" + i + "-" +j).css("background", "initial");
		}
	}
	if (state.substep_index === 0) {
		state.prestep_state = [...state.state];
	}
	if (!state.first_round_key) {
		display_aes_state(state.prestep_state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys, "#aes-2-");
		display_aes_state(state.state, "#aes-3-");
		state.state[state.substep_index] ^= state.round_keys[state.substep_index];
		$("#aes-state-col-" + state.substep_index).css("background", "green");
		$("#aes-state-2-col-" + state.substep_index).css("background", "green");
		$("#aes-state-3-col-" + state.substep_index).css("background", "green");
		console.log("First Round Key:\n");
		$("#aes-2-3-symbol").html("=");
		$("#aes-step-name").html("Add Round Key");
		state.substep_index++;
		if (state.substep_index >= 4) {
			state.first_round_key = true;
			state.substep_index = 0;
		}
		return state;
	}
	if (state.round < rounds) {
		switch (state.round_step) {
			case 0:
				/// do sb
				/// Sub-byte the state
				display_aes_state(state.prestep_state);
				$("#aes-1-2-symbol").html("->");
				display_aes_sbox(state.prestep_state, "#aes-2-");
				display_aes_state(state.state, "#aes-3-");
				state.state[state.substep_index] = aes_sub_word32(state.state[state.substep_index]);
				$("#aes-state-col-" + state.substep_index).css("background", "green");
				$("#aes-state-2-col-" + state.substep_index).css("background", "green");
				$("#aes-state-3-col-" + state.substep_index).css("background", "green");
				$("#aes-2-3-symbol").html("=");
				console.log(state.round, " Round s-box step ", );
				$("#aes-step-name").html("Round " + state.round + " Substitution-box");
				state.substep_index++;
				if (state.substep_index >= 4) {
					state.substep_index = 0;
					break;
				}
				return state;
			case 1:
				/// do shift
				/// Shift Rows
				display_aes_state(state.prestep_state);
				for (let i: number = 0; i < key_len; i++) {
					$("#aes-" + state.substep_index + "-" + i).css("background", "green");
					$("#aes-2-" + state.substep_index + "-" + i).css("background", "green");
				}
				display_aes_state(state.state, "#aes-2-");
				let row: number = aes_extract_row(state.state, state.substep_index);
			
				row = rotateleft(row, state.substep_index * 8);
			
				state.state = aes_emplace_row(state.state, row, state.substep_index);
				$("#aes-3-state").addClass("hidden");
				console.log(state.round, " Round row shift:\n");
				$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&lt;&lt; 0</div><div style="font-size: 1.5rem;">&lt;&lt; 1</div><div style="font-size: 1.5rem;">&lt;&lt; 2</div><div style="font-size: 1.5rem;">&lt;&lt; 3</div>');
				$("#aes-2-3-symbol").html("");
				$("#aes-step-name").html("Round " + state.round + " Shift Rows");
				state.substep_index++;
				if (state.substep_index >= 4) {
					state.substep_index = 0;
					break;
				}
				return state;
			case 2:
				/// do mix
				/// Mix Columns
				display_aes_state(state.prestep_state);
				let column: number = aes_extract_column(state.state, state.substep_index);

				column = aes_mix_column_polynomial(column);

				display_aes_state([0x01010302, 0x01030201, 0x03020101, 0x02010103], "#aes-2-");
				display_aes_state(state.state, "#aes-3-");
				state.state = aes_emplace_column(state.state, column, state.substep_index);
				console.log(state.round, " Round mix:\n");
				$("#aes-1-2-symbol").html("&#x2981;");
				$("#aes-2-3-symbol").html("=");
				$("#aes-3-state").removeClass("hidden");
				$("#aes-state-col-" + state.substep_index).css("background", "green");
				$("#aes-state-3-col-" + state.substep_index).css("background", "green");
				$("#aes-step-name").html("Round " + state.round + " Mix Columns");
				state.substep_index++;
				if (state.substep_index >= 4) {
					state.substep_index = 0;
					break;
				}
				return state;
			case 3:
				/// add key
				display_aes_state(state.prestep_state);
				$("#aes-1-2-symbol").html("&oplus;");
				display_aes_state(state.round_keys.slice(state.round * key_len), "#aes-2-");
				display_aes_state(state.state, "#aes-3-");
				state.state[state.substep_index] ^= state.round_keys[(state.round * key_len) + state.substep_index];
				$("#aes-state-col-" + state.substep_index).css("background", "green");
				$("#aes-state-2-col-" + state.substep_index).css("background", "green");
				$("#aes-state-3-col-" + state.substep_index).css("background", "green");
				console.log("First Round Key:\n");
				$("#aes-2-3-symbol").html("=");
				$("#aes-step-name").html("Round " + state.round + " Add Round Key");
				state.substep_index++;
				if (state.substep_index >= 4) {
					state.round_step = 0;
					state.round++;
					state.substep_index = 0;
				}
				return state;
			default:
				console.error("out of bounds round step");
		}
		state.round_step++;
		return state;
	}

	if (!state.last_sub) {
		/// do sb
		/// Sub-byte the state
		display_aes_state(state.prestep_state);
		$("#aes-1-2-symbol").html("->");
		display_aes_sbox(state.prestep_state, "#aes-2-");
		display_aes_state(state.state, "#aes-3-");
		state.state[state.substep_index] = aes_sub_word32(state.state[state.substep_index]);
		$("#aes-state-col-" + state.substep_index).css("background", "green");
		$("#aes-state-2-col-" + state.substep_index).css("background", "green");
		$("#aes-state-3-col-" + state.substep_index).css("background", "green");
		$("#aes-2-3-symbol").html("=");
		console.log(state.round, " Round s-box step ", );
		$("#aes-step-name").html("Last Substitution-box");
		state.substep_index++;
		if (state.substep_index >= 4) {
			state.substep_index = 0;
			state.last_sub = true;
		}
		return state;
	}
	

	if (!state.last_shift) {
		/// do shift
		/// Shift Rows
		display_aes_state(state.prestep_state);
		for (let i: number = 0; i < key_len; i++) {
			$("#aes-" + state.substep_index + "-" + i).css("background", "green");
			$("#aes-2-" + state.substep_index + "-" + i).css("background", "green");
		}
		display_aes_state(state.state, "#aes-2-");
		let row: number = aes_extract_row(state.state, state.substep_index);

		row = rotateleft(row, state.substep_index * 8);

		state.state = aes_emplace_row(state.state, row, state.substep_index);
		$("#aes-3-state").addClass("hidden");
		console.log(state.round, " Round row shift:\n");
		$("#aes-1-2-symbol").html('<div style="font-size: 1.5rem;">&lt;&lt; 0</div><div style="font-size: 1.5rem;">&lt;&lt; 1</div><div style="font-size: 1.5rem;">&lt;&lt; 2</div><div style="font-size: 1.5rem;">&lt;&lt; 3</div>');
		$("#aes-2-3-symbol").html("");
		$("#aes-step-name").html("Last Shift Rows");
		state.substep_index++;
		if (state.substep_index >= 4) {
			state.substep_index = 0;
			state.last_shift = true;
		}
		return state;
	}
	
	if (!state.last_round_key) {
		/// add key
		display_aes_state(state.prestep_state);
		$("#aes-1-2-symbol").html("&oplus;");
		display_aes_state(state.round_keys.slice(state.round * key_len), "#aes-2-");
		display_aes_state(state.state, "#aes-3-");
		state.state[state.substep_index] ^= state.round_keys[(state.round * key_len) + state.substep_index];
		$("#aes-state-col-" + state.substep_index).css("background", "green");
		$("#aes-state-2-col-" + state.substep_index).css("background", "green");
		$("#aes-state-3-col-" + state.substep_index).css("background", "green");
		console.log("First Round Key:\n");
		$("#aes-2-3-symbol").html("=");
		$("#aes-step-name").html("Last Add Round Key");
		state.substep_index++;
		if (state.substep_index >= 4) {
			state.last_round_key = true;
			state.substep_index = 0;
		}
		return state;
	}

	state.done = true;
	display_aes_state(state.state);
	$("#aes-step-name").html("Encryption Result");
	$("#aes-1-2-symbol").html("");
	$("#aes-2-3-symbol").html("");
	$("#aes-2-state").addClass("hidden");
	$("#aes-3-state").addClass("hidden");
    $("#aes-submit-button").addClass("hidden");
    $("#aes-next-button").addClass("hidden");
    $("#aes-substep-button").addClass("hidden");
    $("#aes-decrypt-button").addClass("hidden");
	return state;
}

function display_aes_original(state: string, base: string = "#aes-") {
	if ($(base + "state").hasClass('hidden')) {
		$(base + "state").removeClass('hidden');
	}
	for (let row_index: number = 0; row_index < 4; row_index++) {
		for (let column_index: number = 0; column_index < 4; column_index++) {
			let ch: string = state.charAt((column_index * 4) + row_index);
			$(base + row_index + "-" + column_index).html('"' + ch + '"');
		}
	}
}

function display_aes_sbox(state: number[], base: string = "#aes-", inverse: boolean = false) {
	if ($(base + "state").hasClass('hidden')) {
		$(base + "state").removeClass('hidden');
	}
	for (let row_index: number = 0; row_index < 4; row_index++) {
		let row: number = aes_extract_row(state, row_index);
		for (let column_index: number = 0; column_index < 4; column_index++) {
			$(base + row_index + "-" + column_index).html("s" + (inverse ? "-1" : "") + "[" + ((row >>> (24 - (column_index * 8))) & 0xff).toString(16).padStart(2, '0') + ']');
		}
	}
}


function display_aes_state(state: number[], base: string = "#aes-") {
	if ($(base + "state").hasClass('hidden')) {
		$(base + "state").removeClass('hidden');
	}
	for (let row_index: number = 0; row_index < 4; row_index++) {
		let row: number = aes_extract_row(state, row_index);
		for (let column_index: number = 0; column_index < 4; column_index++) {
			$(base + row_index + "-" + column_index).html(((row >>> (24 - (column_index * 8))) & 0xff).toString(16).padStart(2, '0'));
		}
	}
}


function aes_decrypt(data: number[], key: string): number[] {
	console.log("Decrypting with key: ", key, '\n');

	/// Split into 16 byte chunks
	if (data.length > 4) {
		let out: number[] = [];
		for (let chunk_index: number = 0; (chunk_index * 4) < data.length; chunk_index++) {
			let sub_result: number[] = aes_decrypt(data.slice(chunk_index * 16, 16), key);
			out.concat(sub_result);
		}
		return out;
	}

	let key_uint: number[] = convert_be(digest_key(key));
	/// Create round keys
	let round_keys: number[] = aes_get_round_keys(key_len, key_uint, rounds + 1);

	let state: number[] = data;

	console.log("Initial State:\n");
	aes_print_state(state);

	/// Add Round Key
	state = aes_add_round_key(state, round_keys.slice(rounds * key_len));
	console.log("First Round Key:\n");
	aes_print_state(state);

	/// Shift Rows
	state = aes_reverse_shift_rows(state);
	console.log("First row shift:\n");
	aes_print_state(state);

	/// Sub-byte the state
	for (let i = 0; i < state.length; i++) {
		state[i] = aes_inverse_sub_word32(state[i]);
	}
	console.log("First sub box:\n");
	aes_print_state(state);


	for (let round: number = rounds - 1; round > 0; round--) {
		// Add Round Key
		state = aes_add_round_key(state, round_keys.slice((round * key_len)));
		console.log(round, " Round add round key:\n");
		aes_print_state(state);

		/// Mix Columns
		state = aes_inverse_mix_columns(state);
		console.log(round, " Round mix:\n");
		aes_print_state(state);

		/// Shift Rows
		state = aes_reverse_shift_rows(state);
		console.log(round, " Round row shift:\n");
		aes_print_state(state);

		/// Sub-byte the state
		for (let i = 0; i < state.length; i++) {
			state[i] = aes_inverse_sub_word32(state[i]);
		}
		console.log(round, " Round s-box:\n");
		aes_print_state(state);
	}

	/// Add original key to state.
	state = aes_add_round_key(state, key_uint);
	console.log(" Last Round key:\n");
	aes_print_state(state);

	return state;
}