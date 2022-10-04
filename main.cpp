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

    std::cout << std::hex << ((b0 < 0x10) ? "0" : "") << b0 << ((b1 < 0x10) ? " 0" : " ") << b1 << ((b2 < 0x10) ? " 0" : " ") << b2 << ((b3 < 0x10) ? " 0" : " ") << b3 << std::dec;
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

//    for (int i = 0; i < 16; i++) {
//        std::cout << std::hex << chunks[0][i] << ' ';
//    }
//    std::cout << '\n';

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
void hmac(std::string key, std::string message, int blockSize, int outputSize) {
// Compute the block sized key
    uint32_t* block_sized_key = compute_block_sized_key(key, blockSize);

    auto* message_converted = new uint32_t[message.size()];
    convert_be(message, message_converted);

    auto* o_key_pad = new uint32_t[blockSize];
    auto* i_key_pad = new uint32_t[blockSize];

    for (int i = 0; i < blockSize; i++) {
        o_key_pad[i] = 0x5c ^ block_sized_key[i];
        i_key_pad[i] = 0x36 ^ block_sized_key[i];
    }

    auto* initial = new uint32_t[blockSize * 2];

    for (int i = 0; i < blockSize * 2; i++) {
        if (i < blockSize) {
            initial[i] = i_key_pad[i];
        }
        else {
            initial[i] = message_converted[i];
        }
    }

    auto* hash_output = new uint32_t[5];

    sha1(initial, blockSize * 2, hash_output);

    // return hash(o_key_pad)
}

/// Source: https://en.wikipedia.org/wiki/PBKDF2#Key_derivation_process
std::string pbkdf2(const std::string& password, const std::string& salt, int iterations, int length) {

}


int main() {

    std::string password = "peanuts";
    int iterations = 1;
    std::string salt = "saltysalt";
    int length = 16;



    uint8_t key[32];

    char output[128];

    char iv[16];

    for (char& c : iv) {
    c = ' ';
    }

    for (char& c : output) {
    c = 0;
    }


    auto *sha = new uint32_t[5];
    auto *sha2 = new uint32_t[5];

    std::string test = "";
    for (int i = 0; i < 64; i++) {

        test += (char)('a' + (i % ('z' - 'a')));

        sha1(test, sha2);


        auto* test_uint = new uint32_t[test.size() / 4 + 1];

        for (int i = 0; i < test.size() / 4 + 1; i++) {
            test_uint[i] = 0;
        }

        convert_be(test, test_uint);

        sha1(test_uint, test.size(), sha);

        delete[] test_uint;

        bool equal = true;
        for (int j = 0; j < 5; j++) {
            equal = equal && (sha[j] == sha2[j]);
        }

        if (!equal) {
            std::cout << i << ": " << test << std::endl;
            for (int j = 0; j < 5; j++) {
                std::cout << sha[j];
            }
            std::cout << " =/= ";
            for (int j = 0; j < 5; j++) {
                std::cout << sha2[j];
            }
            std::cout << std::endl;
        }


    }

    delete[] sha;
    delete[] sha2;

    // 30b59bc6c7c1622283a23950f2984bc5cd4fdd51
    // 30b59bc6c7c1622283a23950f2984bc5cd4fdd51

    // EVP_KDF_PBKDF2(password.c_str(), salt.c_str(), iterations, output, 0);

    return 0;
}
