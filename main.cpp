#include <iostream>
#include <climits>
#include <vector>
#include <bitset>

/// Source: https://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
uint32_t rotateleft (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
     count &= mask;
    return (value << count) | (value >> (-count & mask));
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

void aes_get_round_constants(uint8_t rounds, uint32_t* output) {

    uint8_t rc[rounds + 1];

    for (int round = 1; round <= rounds; round++) {
        if (round == 1) {
            rc[round] = 1;
        } else if (rc[round - 1] < 0x80) {
            rc[round] = 2 * rc[round - 1];
        } else {
            rc[round] = (2 * rc[round - 1]) ^ 0x11b;
        }
    }

    for (int round = 1; round <= rounds; round++) {
        output[round] = (rc[round] << 24);
    }
}


uint32_t aes_rot_word(uint32_t word) {
    return rotateleft(word, 8);
}

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
uint8_t* inverse_sbox = nullptr;

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

        for (int bit = 0; bit < 16; bit++) {
            output_bits[bit] = (value >> bit) & (0b1);
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

    for (int bit = 0; bit < 8; bit++) {
        if ((a >> bit) & (0b1)) {
            output ^= b_copy << bit;
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
 * Uses the Extended Euclidean algorithm to find the inverse of the given value in GF(2^8).
 */
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


uint8_t aes_inverse_sub_word8(uint8_t word) {
    if (!inverse_sbox) {
        aes_generate_inverse_sbox();
    }

    return inverse_sbox[word];
}

uint32_t aes_inverse_sub_word32(uint32_t word) {
    uint32_t out = 0;

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
std::vector<uint32_t> aes_get_round_keys(uint8_t n, std::vector<uint32_t> key, uint8_t r) {
    std::vector<uint32_t> w(4 * r);
    uint32_t rc[r];
    aes_get_round_constants(r, rc);


    for (int round = 0; round <= n * r; round++) {
        if (round < n) {
            w[round] = key[round];
        }
        else if ((round % n) == 0) {
            w[round] = (w[round - n] ^ (aes_sub_word32(aes_rot_word(w[round - 1])))) ^ rc[round / n];
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


void aes_add_round_key(std::vector<uint32_t>& state, std::vector<uint32_t>::iterator round_key) {
    for (uint8_t byte_index = 0; byte_index < 4; byte_index++) {
        state[byte_index] ^= round_key[byte_index];
    }
}

/**
 * @param state
 * @param row_index
 * @return the row in the state at row_index
 *
 * Since the state is stored rotated from how AES operates we need to go through all the columns in the state and grab one byte of the row from each.
 */
uint32_t aes_extract_row(const std::vector<uint32_t>& state, uint8_t row_index) {
    uint32_t row = 0;
    for (uint8_t col = 0; col < 4; col++) {
        row |= ((state[col] >> (24 - (row_index * 8))) & 0xff) << (24 - (8 * col));
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
void aes_emplace_row(std::vector<uint32_t>& state, uint32_t row, uint8_t row_index) {
    for (uint8_t col = 0; col < 4; col++) {
        state[col] &= ~(0xff << (24 - (row_index * 8)));
        state[col] |= (((row >> (24 - (col * 8))) & 0xff) << (24 - (row_index * 8)));
    }
}

void aes_print_state(const std::vector<uint32_t>& state) {
    for (uint8_t row_index = 0; row_index < 4; row_index++) {
        uint32_t row = aes_extract_row(state, row_index);
        for (int column_index = 0; column_index < 4; column_index++) {
            std::cout << std::hex << ((row >> (24 - (column_index * 8))) & 0xff) << ' ';
        }
        std::cout << '\n';
    }
    std::cout << '\n' << std::dec;
}


void aes_shift_rows(std::vector<uint32_t>& state) {
    std::vector<uint32_t> tmp(4);

    for (uint8_t row_index = 0; row_index < 4; row_index++) {
        uint32_t row = aes_extract_row(state, row_index);

        tmp[row_index] = row << (row_index * 8);
        tmp[row_index] |= row >> (32 - (row_index * 8));
    }

    for (uint8_t row_index = 0; row_index < 4; row_index++) {
        aes_emplace_row(state, tmp[row_index], row_index);
    }
}

void aes_reverse_shift_rows(std::vector<uint32_t>& state) {
    std::vector<uint32_t> tmp(4);

    for (uint8_t row_index = 0; row_index < 4; row_index++) {
        uint32_t row = aes_extract_row(state, row_index);

        tmp[row_index] = row >> (row_index * 8);
        tmp[row_index] |= row << (32 - (row_index * 8));
    }

    for (uint8_t row_index = 0; row_index < 4; row_index++) {
        aes_emplace_row(state, tmp[row_index], row_index);
    }
}

uint8_t aes_mix_column_multiply(uint8_t a, uint8_t b) {
    return gf2_8_multiplication(a, b, AES_IRREDUCIBLE_POLYNOMIAL);
}
/**
 *
 * @param value - a column from the state
 * @return the column after applying the mix to it
 *
 *  This is one implementation of the mix column function that uses matrix multiplication. I prefer the polynomial multiplication for its understandability but this also a correct implementation.
 */
uint32_t aes_mix_column_matrix(uint32_t value) {
    uint16_t b[] = {(uint8_t)((value >> 24) & 0xff), (uint8_t)((value >> 16) & 0xff),
                    (uint8_t)((value >> 8) & 0xff), (uint8_t)(value & 0xff)};

    uint8_t d[] = {(uint8_t)(aes_mix_column_multiply(2, b[0]) ^ aes_mix_column_multiply(3, b[1]) ^ b[2] ^ b[3]),
                   (uint8_t)(aes_mix_column_multiply(2, b[1]) ^ aes_mix_column_multiply(3, b[2]) ^ b[3] ^ b[0]),
                   (uint8_t)(aes_mix_column_multiply(2, b[2]) ^ aes_mix_column_multiply(3, b[3]) ^ b[0] ^ b[1]),
                   (uint8_t)(aes_mix_column_multiply(2, b[3]) ^ aes_mix_column_multiply(3, b[0]) ^ b[1] ^ b[2])};

    return (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
}

/**
 * @param value - a column from the state
 * @return the column after applying the mix to it
 *
 * This is my preferred implementation of the mix column function that uses polynomial multiplication. I prefer it because it uses the math that the matrix multiplication is derived from. This implementation doesn't use magical constants, and so I have an easier time understanding it.
 */
uint32_t aes_mix_column_polynomial(uint32_t value) {
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

uint32_t aes_inverse_mix_column(uint32_t value) {
    uint16_t polynomial = 0b00011011;
    uint8_t a[] = {2, 1, 1, 3};
    uint16_t d[] = {(uint8_t)((value >> 24) & 0xff), (uint8_t)((value >> 16) & 0xff),
                    (uint8_t)((value >> 8) & 0xff), (uint8_t)(value & 0xff)};


    // 14 11 13 9
    // 9 14 11 13
    // 13 9 14 11
    // 11 13 9 14
    uint8_t m[4] = {14, 11, 13, 9};

    uint8_t b[4];


    for (int column_index = 0; column_index < 4; column_index++) {
        b[column_index] = aes_mix_column_multiply(m[0], d[0]) ^
                        aes_mix_column_multiply(m[1], d[1]) ^
                        aes_mix_column_multiply(m[2], d[2]) ^
                        aes_mix_column_multiply(m[3], d[3]);

        uint8_t tmp = m[3];
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
uint32_t aes_extract_column(const std::vector<uint32_t>& state, uint8_t column_index) {
    return state[column_index];
}

/**
 * @param state
 * @param column
 * @param column_index
 *
 * This places the column into the state based on the column index. It indexes the array directly to place the column because the state is actually rotated 90 degrees from the way it's stored. This is quirk of AES.
 */
void aes_emplace_column(std::vector<uint32_t>& state, uint32_t column, uint8_t column_index) {
    state[column_index] = column;
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


void aes_mix_columns(std::vector<uint32_t>& state) {

    for (uint8_t column_index = 0; column_index < 4; column_index++) {

        uint32_t column = aes_extract_column(state, column_index);

        column = aes_mix_column_polynomial(column);

        aes_emplace_column(state, column, column_index);
    }
}

void aes_inverse_mix_columns(std::vector<uint32_t>& state) {

    for (uint8_t column_index = 0; column_index < 4; column_index++) {

        uint32_t column = aes_extract_column(state, column_index);

        column = aes_inverse_mix_column(column);

        aes_emplace_column(state, column, column_index);
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
std::vector<uint32_t> aes_encrypt(std::string message, const std::string& key) {
    const uint8_t rounds = 10;
    const uint8_t key_len = 4;


    std::cout << "Encrypting \"" << message << "\" with key: " << key << '\n';

    /// Verify key length
    if (key.size() != 16) {
        std::cerr << "AES KEY ERROR: Size of " << key.size() << " is invalid supported sizes are: 16";
        exit(5);
    }
    /// Split into 16 byte chunks
    if (message.size() > 16) {
        std::vector<uint32_t> out;
        for (uint16_t chunk_index = 0; (chunk_index * 16) < message.size(); chunk_index++) {
            std::vector<uint32_t> sub_result = aes_encrypt(message.substr(chunk_index * 16, 16), key);
            out.insert(out.end(), sub_result.begin(), sub_result.end());
        }
        return out;
    }
    else if (message.size() != 16) {
        message.push_back(0x80);

        while (message.size() != 16) {
            message.push_back(0);
        }
    }


    std::vector<uint32_t> key_uint = convert_be(key);
    /// Create round keys
    std::vector<uint32_t> round_keys = aes_get_round_keys(key_len, key_uint, rounds + 1);

    /// Rotate the state
    std::vector<uint32_t> state = convert_be(message);
    std::cout << "Initial State:\n";
    aes_print_state(state);

    /// Add original key to state.
    aes_add_round_key(state, key_uint.begin());
    std::cout << "First Round Key:\n";
    aes_print_state(state);

    for (int round = 1; round < rounds; round++) {

        /// Sub-byte the state
        for (auto& uint : state) {
            uint = aes_sub_word32(uint);
        }
        std::cout << round << " Round s-box:\n";
        aes_print_state(state);

        /// Shift Rows
        aes_shift_rows(state);
        std::cout << round << " Round row shift:\n";
        aes_print_state(state);

        /// Mix Columns
        aes_mix_columns(state);
        std::cout << round << " Round mix:\n";
        aes_print_state(state);

        // Add Round Key
        aes_add_round_key(state, round_keys.begin() + (round * 4));
        std::cout << round << " Round add round key:\n";
        aes_print_state(state);
    }


    /// Sub-byte the state
    for (auto& uint : state) {
        uint = aes_sub_word32(uint);
    }
    std::cout << " Last Round S-Box:\n";
    aes_print_state(state);

    /// Shift Rows
    aes_shift_rows(state);
    std::cout << " Last Round Shift Rows:\n";
    aes_print_state(state);

    // Add Round Key
    aes_add_round_key(state, round_keys.begin() + (10 * 4));
    std::cout << " Last Round key:\n";
    aes_print_state(state);

    return state;
}


std::vector<uint32_t> aes_decrypt(const std::vector<uint32_t>& data, const std::string& key) {
    const uint8_t rounds = 10;
    const uint8_t key_len = 4;

    std::cout << "Decrypting with key: " << key << '\n';

    /// Verify key length
    if (key.size() != 16) {
        std::cerr << "AES KEY ERROR: Size of " << key.size() << " is invalid supported sizes are: 16";
        exit(5);
    }

    /// Split into 16 byte chunks
    if (data.size() > 4) {
        std::vector<uint32_t> out;
        for (uint16_t chunk_index = 0; (chunk_index * 4) < data.size(); chunk_index++) {
            std::vector<uint32_t> sub_result = aes_decrypt(std::vector<uint32_t>(data.begin() + chunk_index * 4, data.begin() + ((chunk_index + 1) * 4)), key);
            out.insert(out.end(), sub_result.begin(), sub_result.end());
        }
        return out;
    }

    std::vector<uint32_t> key_uint = convert_be(key);
    /// Create round keys
    std::vector<uint32_t> round_keys = aes_get_round_keys(key_len, key_uint, rounds + 1);

    std::vector<uint32_t> state = data;

    std::cout << "Initial State:\n";
    aes_print_state(state);

    /// Add Round Key
    aes_add_round_key(state, round_keys.begin() + (10 * 4));
    std::cout << "First Round Key:\n";
    aes_print_state(state);

    /// Shift Rows
    aes_reverse_shift_rows(state);
    std::cout << "First row shift:\n";
    aes_print_state(state);

    /// Sub-byte the state
    for (auto& uint : state) {
        uint = aes_inverse_sub_word32(uint);
    }
    std::cout << "First sub box:\n";
    aes_print_state(state);


    for (int round = rounds - 1; round > 0; round--) {
        // Add Round Key
        aes_add_round_key(state, round_keys.begin() + (round * 4));
        std::cout << round << " Round key:\n";
        aes_print_state(state);

        /// Mix Columns
        aes_inverse_mix_columns(state);
        std::cout << round << " Round mix:\n";
        aes_print_state(state);

        /// Shift Rows
        aes_reverse_shift_rows(state);
        std::cout << round << " Round shift:\n";
        aes_print_state(state);

        /// Sub-byte the state
        for (auto& uint : state) {
            uint = aes_inverse_sub_word32(uint);
        }
        std::cout << round << " Round s-box:\n";
        aes_print_state(state);
    }

    /// Add original key to state.
    aes_add_round_key(state, key_uint.begin());
    std::cout << " Last Round key:\n";
    aes_print_state(state);

    return state;
}

int main() {
    std::string msg = "Two One Nine Two";

    std::string key_str = "Thats my Kung Fu";

    std::vector<uint32_t> state = aes_encrypt(msg, key_str);

    std::vector<uint32_t> original = aes_decrypt(state, key_str);

    return 0;
}