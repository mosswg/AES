#include <iostream>
#include <climits>
#include <vector>
#include <sstream>
#include <cmath>
#include <bitset>

/// Source: https://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
uint32_t rotateleft (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
     count &= mask;
    return (value << count) | (value >> (-count & mask));
}

/// Source: https://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
uint32_t rotateright (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

void print_uint_bytes(uint32_t word) {
    uint32_t b0 = ((word >> 24) & 0xff);
    uint32_t b1 = ((word >> 16) & 0xff);
    uint32_t b2 = ((word >> 8) & 0xff);
    uint32_t b3 = (word & 0xff);

    std::cout << std::hex << ((b0 < 0x10) ? "0" : "") << b0 << ((b1 < 0x10) ? " 0" : " ") << b1 << ((b2 < 0x10) ? " 0" : " ") << b2 << ((b3 < 0x10) ? " 0" : " ") << b3 << '\n' << std::dec;
}

void convert_be(const std::string& data, uint32_t* output, uint32_t bit_limit = 0) {
    int bits = 0;

    for (char ch : data) {
        if (bits % 32 == 0) {
            output[bits / 32] = 0;
        }

        output[bits / 32] |= ((ch << (24 - (bits % 32))) & (0xFF << (24 - (bits % 32))));

        if (bit_limit != 0 && bits == bit_limit)
            return;

        bits += 8;
    }
}

std::vector<uint32_t> convert_be(const std::string& data) {
    int bits = 0;

    std::vector<uint32_t> out;

    for (char ch : data) {
        if (bits % 32 == 0) {
            out.push_back(0);
        }

        out[bits / 32] |= ((ch << (24 - (bits % 32))) & (0xFF << (24 - (bits % 32))));

        bits += 8;
    }

    return out;
}

std::string convert_be(uint32_t* data, uint32_t data_size) {
    std::string out;

    for (int i = 0; i < data_size / 4; i++) {
        out += ((data[i] & 0xFF000000) >> 24);
        out += ((data[i] & 0xFF0000) >> 16);
        out += ((data[i] & 0xFF00) >> 8);
        out += (data[i] & 0xFF);
    }

    return out;
}


void convert_le(const std::string& data, uint32_t* output, uint32_t bit_limit = 0) {
    int bits = 0;

    for (char ch : data) {
        output[bits / 32] |= ((ch << (bits % 32)) & (0xFF << (bits % 32)));

        if (bits == bit_limit)
            return;

        bits += 8;
    }
}


void set_byte_in_uint_array(uint32_t* data, int byte_index, uint8_t byte) {
    int uint_index = byte_index / 4;
    int sub_byte_index = byte_index % 4;

    uint32_t mask = ~(0xFF000000 >> (sub_byte_index * 8));

    data[uint_index] &= mask;
    data[uint_index] |= byte << ((3-sub_byte_index) * 8);
}

/// Source: https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
void sha1(const uint32_t* data, int data_size_bytes, uint32_t* output) {


    // Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
    //      ml, the message length, which is a 64-bit quantity, and
    //      hh, the message digest, which is a 160-bit quantity.
    // Note 2: All constants in this pseudo code are in big endian.
    //      Within each word, the most significant byte is stored in the leftmost byte position

    // Initialize variables:

    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;


    uint64_t ml = data_size_bytes * 8;

    uint32_t data_size = data_size_bytes / 4 + ((data_size_bytes % 4) != 0);

    // Pre-processing:
    // append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    //        append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    // is congruent to −64 ≡ 448 (mod 512)
    // append ml, the original message length in bits, as a 64-bit big-endian integer.
    //        Thus, the total length is a multiple of 512 bits.

    int size_away_from_512 = 512 - ((data_size * 32) % 512);

    auto* message = new uint32_t[data_size + (size_away_from_512 / 32)];

    for (int i = 0; i < data_size; i++) {
        message[i] = data[i];
    }

    while ((data_size * 32) % 512 != 448) {
        message[data_size++] = (int)0;
    }

    set_byte_in_uint_array(message, data_size_bytes, 0b10000000);

    data_size += 2;
    message[data_size - 2] = (ml & 0xFFFFFFFF00000000);
    message[data_size - 1] = (ml & 0xFFFFFFFF);

    // Process the message in successive 512-bit chunks:
    // break message into 512-bit chunks

    std::vector<uint32_t*> chunks;

    for (int i = 0; i < data_size; i++) {
        if ((i % 16) == 0) {
            chunks.push_back(new uint32_t[80]);
        }

        chunks.back()[i % 16] = message[i];
    }

//    for (auto& chunk : chunks) {
//        for (int i = 0; i < 16; i++) {
//            std::cout << chunk[i] << '\n';
//        }
//    }

    for (auto& chunk : chunks) {
        // break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15

        // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words:
        // for i from 16 to 79
        // Note 3: SHA-0 differs by not having this leftrotate.
        for (int i = 16; i < 80; i++) {
            chunk[i] = rotateleft((chunk[i - 3] xor chunk[i - 8] xor chunk[i - 14] xor chunk[i - 16]), 1);
        }

        // Initialize hash value for this chunk:
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        //  Main loop:[10][56]
        for (int i = 0; i < 80; i++) {
            uint32_t f;
            uint32_t k;
            if (0 <= i && i <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i >= 20 && i <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i >= 40 && i <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b xor c xor d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = (rotateleft(a, 5)) + f + e + k + chunk[i];
            e = d;
            d = c;
            c = rotateleft(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result so far:
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
    }

    for (auto& chunk : chunks) {
        delete[] chunk;
    }

    delete[] message;



    output[0] = h0;
    output[1] = h1;
    output[2] = h2;
    output[3] = h3;
    output[4] = h4;
}

/// Source: https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
void sha1(const std::string& data, uint32_t* output) {
    auto* converted_data = new uint32_t[data.size() / 4 + 1];

    convert_be(data, converted_data);

    sha1(converted_data, data.size(), output);

    delete[] converted_data;
}

/// Source: https://en.wikipedia.org/wiki/HMAC#Implementation
uint32_t* compute_block_sized_key(const std::string& key, int block_size) {
    uint32_t block_size_in_uints = block_size / 4 + ((block_size % 4) != 0);
    auto* output = new uint32_t[block_size_in_uints];
    for (int i = 0; i < block_size_in_uints; i++) {
        output[i] = 0;
    }

    if (key.size() > block_size) {
        sha1(key, output);
    }
    else {
        convert_be(key, output);
    }

    return output;
}

/// Source: https://en.wikipedia.org/wiki/HMAC#Implementation
void hmac(const std::string& key, const std::string& message, uint32_t* output) {
    int blockSize = 64;

    uint32_t block_size_in_uints = blockSize / 4 + ((blockSize % 4) != 0);

    uint32_t* block_sized_key = compute_block_sized_key(key, blockSize);

    auto* message_converted = new uint32_t[message.size()];
    convert_be(message, message_converted);

    auto* o_key_pad = new uint32_t[block_size_in_uints];
    auto* i_key_pad = new uint32_t[block_size_in_uints];

    for (int i = 0; i < blockSize; i++) {
        int uint_index = i / 4;
        int sub_byte_index = i % 4;

        uint32_t mask = 0xFF000000 >> (sub_byte_index * 8);
        uint8_t xor_byte = (block_sized_key[uint_index] & mask) >> ((3-sub_byte_index) * 8);

        o_key_pad[uint_index] |= (0x5c ^ xor_byte) << ((3-sub_byte_index) * 8);

        i_key_pad[uint_index] |= (0x36 ^ xor_byte) << ((3-sub_byte_index) * 8);
    }

    auto* initial = new uint32_t[block_size_in_uints * 2];

    for (int i = 0; i < block_size_in_uints * 2; i++) {
        if (i < block_size_in_uints) {
            initial[i] = i_key_pad[i];
        }
        else {
            initial[i] = message_converted[i % block_size_in_uints];
        }
    }

    auto* hash_output = new uint32_t[5];

    sha1(initial, blockSize + message.size(), hash_output);

    auto* semifinal = new uint32_t[block_size_in_uints * 2];

    for (int i = 0; i < block_size_in_uints * 2; i++) {
        if (i < block_size_in_uints) {
            semifinal[i] = o_key_pad[i];
        }
        else if (i - block_size_in_uints < 5){
            semifinal[i] = hash_output[i % block_size_in_uints];
        }
        else {
            semifinal[i] = 0;
        }
    }


    sha1(semifinal, blockSize + 20, output);

    delete[] message_converted;
    delete[] o_key_pad;
    delete[] i_key_pad;
    delete[] initial;
    delete[] hash_output;
    delete[] semifinal;
}

void hmac(const std::string& key, uint32_t* message, uint32_t message_length, uint32_t* output) {
    int blockSize = 64;

    uint32_t block_size_in_uints = blockSize / 4 + ((blockSize % 4) != 0);

    uint32_t* block_sized_key = compute_block_sized_key(key, blockSize);

    auto* o_key_pad = new uint32_t[block_size_in_uints];
    auto* i_key_pad = new uint32_t[block_size_in_uints];

    for (int i = 0; i < blockSize; i++) {
        int uint_index = i / 4;
        int sub_byte_index = i % 4;

        uint32_t mask = 0xFF000000 >> (sub_byte_index * 8);
        uint8_t xor_byte = (block_sized_key[uint_index] & mask) >> ((3-sub_byte_index) * 8);

        o_key_pad[uint_index] |= (0x5c ^ xor_byte) << ((3-sub_byte_index) * 8);

        i_key_pad[uint_index] |= (0x36 ^ xor_byte) << ((3-sub_byte_index) * 8);
    }

    auto* initial = new uint32_t[block_size_in_uints * 2];

    for (int i = 0; i < block_size_in_uints * 2; i++) {
        if (i < block_size_in_uints) {
            initial[i] = i_key_pad[i];
        }
        else {
            initial[i] = message[i % block_size_in_uints];
        }
    }

    auto* hash_output = new uint32_t[5];

    sha1(initial, blockSize + message_length, hash_output);

    auto* semifinal = new uint32_t[block_size_in_uints * 2];

    for (int i = 0; i < block_size_in_uints * 2; i++) {
        if (i < block_size_in_uints) {
            semifinal[i] = o_key_pad[i];
        }
        else if (i - block_size_in_uints < 5){
            semifinal[i] = hash_output[i % block_size_in_uints];
        }
        else {
            semifinal[i] = 0;
        }
    }


    sha1(semifinal, blockSize + 20, output);

    delete[] o_key_pad;
    delete[] i_key_pad;
    delete[] initial;
    delete[] hash_output;
    delete[] semifinal;
}


uint32_t big_endianify(uint32_t value) {
    uint32_t out = 0;

    out |= (value & 0xFF << 24);
    out |= (value & 0xFF00 << 8);
    out |= (value & 0xFF0000 >> 8);
    out |= (value & 0xFF000000 >> 24);

    return out;
}

uint32_t* pbkdf2_xor(uint32_t* a, const uint32_t* b) {
    a[0] ^= b[0];
    a[1] ^= b[1];
    a[2] ^= b[2];
    a[3] ^= b[3];
    a[4] ^= b[4];

    return a;
}

/// Source: https://en.wikipedia.org/wiki/PBKDF2#Key_derivation_process
std::string pbkdf2(const std::string& password, std::string salt, int iterations, int length) {

    std::string dk;

    std::vector<uint32_t*> T;

    for (int i = 1; i <= ceil(length/20.0); i++) {




        std::vector<uint32_t*> U;
        U.push_back(new uint32_t[5]);

        salt.push_back((i >> 24) & 0xff);
        salt.push_back((i >> 16) & 0xff);
        salt.push_back((i >> 8) & 0xff);
        salt.push_back(i & 0xff);

        hmac(password, salt, U[0]);



        for (int c = 2; c <= iterations; c++) {
            U.push_back(new uint32_t[5]);
            hmac(password, U[i-1], 20, U[i]);
            pbkdf2_xor(U[0], U[1]);
        }

        dk += convert_be(U[0], 20);

        for (auto& j : U) {
            delete[] j;
        }
    }

    return dk.substr(0, length);
}





std::vector<uint32_t> aes_get_round_constants(uint8_t rounds) {

    auto *rc = new uint8_t[rounds + 1];

    for (int i = 1; i <= rounds; i++) {
        if (i == 1) {
            rc[i] = 1;
        } else if (rc[i - 1] < 0x80) {
            rc[i] = 2 * rc[i - 1];
        } else {
            rc[i] = (2 * rc[i - 1]) ^ 0x11b;
        }
    }

    std::vector<uint32_t> out(1);
    for (int i = 1; i <= rounds; i++) {
        out.push_back(rc[i] << 24);
    }


    return out;
}


uint32_t aes_rot_word(uint32_t word) {
    return rotateleft(word, 8);
}

void aes_rotate_state(std::vector<uint32_t>::iterator state) {
    std::vector<uint32_t> state_copy(4);

    for (int i = 0; i < 4; i++) {
        state_copy[i] = state[i];
    }

    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            state[j] &= ~(0xff << (24 - (8 * i)));
            state[j] |= (((state_copy[i] >> (24 - (8 * j))) & 0xff) << (24 - (8 * i)));
        }
    }
}

/*
aes affine transformation individual values
{{1, 0, 0, 0, 1, 1, 1, 1},
{1, 1, 0, 0, 0, 1, 1, 1},
{1, 1, 1, 0, 0, 0, 1, 1},
{1, 1, 1, 1, 0, 0, 0, 1},
{1, 1, 1, 1, 1, 0, 0, 0},
{0, 1, 1, 1, 1, 1, 0, 0},
{0, 0, 1, 1, 1, 1, 1, 0},
{0, 0, 0, 1, 1, 1, 1, 1}}
 */

/*
 *
aes affine transformation combined values
 {0b10001111,
0b11000111,
0b11100011,
0b11110001,
0b11111000,
0b01111100,
0b00111110,
0b00011111}
 */

std::vector<std::vector<uint8_t>> sbox_matrix = {{1, 0, 0, 0, 1, 1, 1, 1},
                                                {1, 1, 0, 0, 0, 1, 1, 1},
                                                {1, 1, 1, 0, 0, 0, 1, 1},
                                                {1, 1, 1, 1, 0, 0, 0, 1},
                                                {1, 1, 1, 1, 1, 0, 0, 0},
                                                {0, 1, 1, 1, 1, 1, 0, 0},
                                                {0, 0, 1, 1, 1, 1, 1, 0},
                                                {0, 0, 0, 1, 1, 1, 1, 1}};

uint8_t sbox_vector[] = {1, 1, 0, 0, 0, 1, 1, 0};

uint8_t* sbox = nullptr;

const uint16_t AES_IRREDUCIBLE_POLYNOMIAL = 0b100011011;

//const uint8_t sbox_const[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
//           0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
//           0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
//           0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
//           0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
//           0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
//           0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
//           0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
//           0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
//           0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
//           0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
//           0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
//           0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
//           0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
//           0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
//           0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};



uint8_t gf2_8_reduce_product(uint16_t value, uint16_t polynomial) {
    uint8_t polynomial_degree = 0; uint16_t polynomial_copy = polynomial, polynomial_leading_coefficient;
    for (; polynomial_copy >> (++polynomial_degree + 1););
    polynomial_leading_coefficient = 1 << polynomial_degree;

    while (value >= polynomial_leading_coefficient) {
        uint8_t output_degree = 0;
        uint16_t output_copy = value; polynomial_copy = polynomial;
        for (; output_copy >> (++output_degree + 1););

        uint8_t degree_difference = output_degree - polynomial_degree;

        uint8_t output_bits[16];

        for (int i = 0; i < 16; i++) {
            output_bits[i] = (value >> i) & (0b1);
        }

        polynomial_copy = polynomial_copy << degree_difference;

        value ^= polynomial_copy;
    }

    return value;
}

uint8_t gf2_8_multiplication(uint8_t a, uint8_t b, uint16_t polynomial) {
    uint8_t polynomial_degree = 0; uint16_t polynomial_copy = polynomial, polynomial_leading_coefficient;
    for (; polynomial_copy >> (++polynomial_degree + 1););
    polynomial_leading_coefficient = 1 << polynomial_degree;


    uint16_t output = 0;
    uint16_t b_copy = b;

    uint8_t a_bits[8];

    for (int i = 0; i < 8; i++) {
        a_bits[i] = (a >> i) & (0b1);
    }

    for (int i = 0; i < 8; i++) {
        if (a_bits[i]) {
            output ^= b_copy << i;
        }
    }

    if (output < polynomial_leading_coefficient)
        return output;

    return gf2_8_reduce_product(output, polynomial);
}

/**
 *
 * @param a
 * @param b
 * @return A 16-bit value which is comprised of the quotient in the first 8-bits and the remainder in the last 8-bits
 */
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
 * Uses the Extended Euclidean algorithm
 */
uint8_t gf_2_8_get_value_inverse(const uint8_t value, uint16_t polynomial) {

    std::vector<uint16_t> remainders = {polynomial, value};
    std::vector<uint16_t> quotients = {0};

    uint16_t first_result = gf2_8_division(polynomial, value);

    quotients.push_back((first_result >> 8) & 0xff);
    remainders.push_back(first_result & 0xff);

    for (int i = 2; remainders.back(); i++) {
        uint16_t result = gf2_8_division(remainders[i-1], remainders[i]);

        quotients.push_back((result >> 8) & 0xff);
        remainders.push_back(result & 0xff);
    }

    uint8_t aux[quotients.size() + 1];

    aux[0] = 0; aux[1] = 1;

    for (int i = 2; i < quotients.size() + 1; i++) {
        aux[i] = aux[i-2] ^ gf2_8_multiplication(quotients[i-1], aux[i-1], polynomial);
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

    for (int i = 0; i < 8; i++) {
        current_bit = ((sbox_matrix[i][0] * (inverse & 0b00000001)) ^
                (sbox_matrix[i][1] * ((inverse & 0b00000010) >> 1)) ^
                (sbox_matrix[i][2] * ((inverse & 0b00000100) >> 2)) ^
                (sbox_matrix[i][3] * ((inverse & 0b00001000) >> 3)) ^
                (sbox_matrix[i][4] * ((inverse & 0b00010000) >> 4)) ^
                (sbox_matrix[i][5] * ((inverse & 0b00100000) >> 5)) ^
                (sbox_matrix[i][6] * ((inverse & 0b01000000) >> 6)) ^
                (sbox_matrix[i][7] * ((inverse & 0b10000000) >> 7))) ^
                sbox_vector[i];

        // std::cout << (uint16_t)current_bit << std::endl;

        result |= current_bit << i;
    }

    return result;
}


void aes_generate_sbox() {
    sbox = new uint8_t[256];

    for (int i = 0; i < 256; i++) {
        sbox[i] = aes_generate_sbox_value(i);
    }
}

uint8_t aes_sub_word8(uint8_t word) {
    if (!sbox) {
        aes_generate_sbox();
    }

    return sbox[word];
}

uint32_t aes_sub_word32(uint32_t word) {
    uint32_t out = 0;

    out |= aes_sub_word8((word >> 24) & 0xff) << 24;
    out |= aes_sub_word8((word >> 16) & 0xff) << 16;
    out |= aes_sub_word8((word >> 8) & 0xff) << 8;
    out |= aes_sub_word8(word & 0xff);

    return out;
}

/**
 *
 * @param n - length of key (4 for 128-bit)
 * @param key - key as a vector of uint32_t
 * @param r - number of rounds (11 for 128-bit)
 * @return a vector of round keys
 */
std::vector<uint32_t> aes_get_round_keys(uint8_t n, std::vector<uint32_t> key, uint8_t r) {
    std::vector<uint32_t> w(4 * r);
    std::vector<uint32_t> rc = aes_get_round_constants(10);


    for (int i = 0; i <= n * r; i++) {
        if (i < n) {
            w[i] = key[i];
        }
        else if ((i % n) == 0) {
            w[i] = (w[i - n] ^ (aes_sub_word32(aes_rot_word(w[i-1])))) ^ rc[i / n];
        }
        else if (n > 6 && (i % n) == 4) {
            w[i] = w[i - n] ^ aes_sub_word32(w[i-1]);
        }
        else {
            w[i] = w[i - n] ^ w[i - 1];
        }
    }

    for (int i = 0; i <= r; i++) {
        aes_rotate_state(w.begin() + (n * i));
    }

    return w;
}


void aes_add_round_key(std::vector<uint32_t>& state, std::vector<uint32_t>::iterator round_key) {
    for (uint8_t i = 0; i < 4; i++) {
        state[i] ^= round_key[i];
    }
}

void aes_print_state(const std::vector<uint32_t>& state) {
    for (uint32_t u32 : state) {
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << ((u32 >> (24 - (i * 8))) & 0xff) << ' ';
        }
        std::cout << '\n';
    }
    std::cout << '\n' << std::dec;
}

void aes_print_state(std::vector<uint32_t>::iterator state) {
    for (uint8_t i = 0; i < 4; i++) {
        for (uint8_t j = 0; j < 4; j++) {
            std::cout << std::hex << ((state[i] >> (24 - (j * 8))) & 0xff) << ' ';
        }
        std::cout << '\n';
    }
    std::cout << '\n' << std::dec;
}


void aes_shift_rows(std::vector<uint32_t>& state) {

    uint8_t bytes[4];

    std::vector<uint32_t> tmp(4);

    for (uint8_t col = 0; col < 4; col++) {
        tmp[col] = state[col] << (col * 8);
        tmp[col] |= state[col] >> (32 - (col * 8));
    }

    for (uint8_t col = 0; col < 4; col++) {
        state[col] = tmp[col];
    }
}

uint8_t aes_mix_column_multiply(uint8_t a, uint8_t b) {
    uint8_t polynomial = 0b00011011;

    switch (a) {
        case 1:
            return b;
        case 2:
            return b << 1 ^ ((b >> 7 & 1) * polynomial);
        case 3:
            return ((b << 1) ^ ((b >> 7 & 1) * polynomial) ^ b);
        default:
            std::cerr << "AES MULTIPLICATION ERROR: Invalid value in a: " << a << std::endl;
            exit(4);
    }
}



uint32_t aes_mix_column_const(uint32_t value) {
    uint16_t b[] = {(uint8_t)((value >> 24) & 0xff), (uint8_t)((value >> 16) & 0xff),
                    (uint8_t)((value >> 8) & 0xff), (uint8_t)(value & 0xff)};

    uint8_t d[] = {(uint8_t)(aes_mix_column_multiply(2, b[0]) ^ aes_mix_column_multiply(3, b[1]) ^ b[2] ^ b[3]),
                   (uint8_t)(aes_mix_column_multiply(2, b[1]) ^ aes_mix_column_multiply(3, b[2]) ^ b[3] ^ b[0]),
                   (uint8_t)(aes_mix_column_multiply(2, b[2]) ^ aes_mix_column_multiply(3, b[3]) ^ b[0] ^ b[1]),
                   (uint8_t)(aes_mix_column_multiply(2, b[3]) ^ aes_mix_column_multiply(3, b[0]) ^ b[1] ^ b[2])};

    return (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
}

uint32_t aes_mix_column(uint32_t value) {
    uint16_t polynomial = 0b00011011;
    uint8_t a[] = {2, 1, 1, 3};
    uint16_t b[] = {(uint8_t)((value >> 24) & 0xff), (uint8_t)((value >> 16) & 0xff),
                   (uint8_t)((value >> 8) & 0xff), (uint8_t)(value & 0xff)};
    uint8_t c[] = {aes_mix_column_multiply(a[0], b[0]),
                   (uint8_t)((aes_mix_column_multiply(a[1], b[0]) ^ aes_mix_column_multiply(a[0], b[1]))),
                   (uint8_t)((aes_mix_column_multiply(a[2], b[0]) ^ aes_mix_column_multiply(a[1], b[1])) ^ aes_mix_column_multiply(a[0], b[2])),
                   (uint8_t)((aes_mix_column_multiply(a[3], b[0]) ^ aes_mix_column_multiply(a[2], b[1])) ^ aes_mix_column_multiply(a[1], b[2]) ^ aes_mix_column_multiply(a[0], b[3])),
                   (uint8_t)((aes_mix_column_multiply(a[3], b[1]) ^ aes_mix_column_multiply(a[2], b[2])) ^ aes_mix_column_multiply(a[1], b[3])),
                   (uint8_t)((aes_mix_column_multiply(a[3], b[2]) ^ aes_mix_column_multiply(a[2], b[3]))),
                   aes_mix_column_multiply(a[3], b[3])};

    return ((c[0] ^ c[4]) << 24) | ((c[1] ^ c[5]) << 16) | ((c[2] ^ c[6]) << 8) | c[3];
}

uint32_t aes_extract_column(const std::vector<uint32_t>& state, uint8_t column_index) {
    uint32_t column = 0;
    for (uint8_t row = 0; row < 4; row++) {
        column |= ((state[row] >> (24 - (column_index * 8))) & 0xff) << (24 - (8 * row));
    }
    return column;
}

void aes_emplace_column(std::vector<uint32_t>& state, uint32_t column, uint8_t column_index) {
    for (uint8_t row = 0; row < 4; row++) {
        state[row] &= ~(0xff << (24 - (column_index * 8)));
        state[row] |= (((column >> (24 - (row * 8))) & 0xff) << (24 - (column_index * 8)));
    }
}


void aes_mix_columns(std::vector<uint32_t>& state) {

    for (uint8_t i = 0; i < 4; i++) {

        uint32_t column = aes_extract_column(state, i);

        column = aes_mix_column(column);

        aes_emplace_column(state, column, i);
    }
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
 * rij where i is the round and j is the byte index
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
void aes(const std::string& message, const std::string& key) {
    const uint8_t rounds = 10;
    const uint8_t key_len = 4;


    std::vector<uint32_t> key_uint = convert_be(key);
    /// Create round keys
    std::vector<uint32_t> round_keys = aes_get_round_keys(key_len, key_uint, rounds + 1);

    std::vector<uint32_t> state = convert_be(message);

    /// Add original key to state.
    aes_add_round_key(state, key_uint);

    for (int i = 0; i < rounds - 1; i++) {

        /// Sub-byte the state
        for (auto& uint : state) {
            uint = aes_sub_word32(uint);
        }

        /// Shirt rows
        aes_shift_rows(state);
    }

}


int main() {
    std::string password = "peanuts";
    int iterations = 1;
    std::string salt = "saltysalt";
    int length = 16;


    std::string dk = pbkdf2(password, salt, iterations, length);



    uint8_t key[32];

    char output[128];

    char iv[16];

    for (char &c: iv) {
        c = ' ';
    }

    for (char &c: output) {
        c = 0;
    }

    std::string key_str = "Thats my Kung Fu";

    std::vector<uint32_t> key_uint = convert_be(key_str);


//    std::vector<uint32_t> round_keys = aes_get_round_keys(4, key_uint, 11);


    std::vector<uint32_t> test = {0x00102030, 0x01112131, 0x02122232, 0x03132133};

//    int idx = 0;
//    for (auto rkey : round_keys) {
//        print_uint_bytes(rkey);
//
//        if (++idx == 4) {
//            std::cout << '\n';
//            idx = 0;
//        }
//        else {
//            std::cout << ' ';
//        }
//    }
//    std::cout << std::endl;


    return 0;
}