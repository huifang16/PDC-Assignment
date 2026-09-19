#include "aes.h"
#include <fstream>
#include <random>
#include <iomanip>
#include <vector>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <omp.h>

static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = { 0,1,2,4,8,0x10,0x20,0x40,0x80,0x1B,0x36 };

AES128::AES128(const AESKey& key) { keyExpansion(key); }

uint8_t AES128::sbox(uint8_t x) { return SBOX[x]; }
uint8_t AES128::xtime(uint8_t x) { return uint8_t((x << 1) ^ ((x >> 7) * 0x1b)); }

void AES128::keyExpansion(const AESKey& key) {
    for (int i = 0; i < 16; i++) roundKey[i] = key[i];
    int bytes = 16, rcon = 1;
    uint8_t temp[4];
    while (bytes < 176) {
        for (int i = 0; i < 4; i++) temp[i] = roundKey[bytes - 4 + i];
        if (bytes % 16 == 0) {
            uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (int i = 0; i < 4; i++) temp[i] = sbox(temp[i]);
            temp[0] ^= RCON[rcon++];
        }
        for (int i = 0; i < 4; i++) {
            roundKey[bytes] = roundKey[bytes - 16] ^ temp[i];
            bytes++;
        }
    }
}

void AES128::addRoundKey(uint8_t* s, int round) const {
    for (int i = 0; i < 16; i++) s[i] ^= roundKey[round * 16 + i];
}

void AES128::subBytes(uint8_t* s) { for (int i = 0; i < 16; i++) s[i] = sbox(s[i]); }

void AES128::shiftRows(uint8_t* s) {
    uint8_t t[16];
    for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) t[4 * c + r] = s[4 * ((c + r) % 4) + r];
    std::memcpy(s, t, 16);
}

void AES128::mixColumns(uint8_t* s) {
    for (int c = 0; c < 4; c++) {
        uint8_t* a = &s[4 * c];
        uint8_t t = a[0] ^ a[1] ^ a[2] ^ a[3];
        uint8_t u = a[0];
        a[0] ^= t ^ xtime(a[0] ^ a[1]);
        a[1] ^= t ^ xtime(a[1] ^ a[2]);
        a[2] ^= t ^ xtime(a[2] ^ a[3]);
        a[3] ^= t ^ xtime(a[3] ^ u);
    }
}

void AES128::encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16]; std::memcpy(s, in, 16);
    addRoundKey(s, 0);
    for (int r = 1; r <= 9; r++) {
        subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, r);
    }
    subBytes(s); shiftRows(s); addRoundKey(s, 10);
    std::memcpy(out, s, 16);
}

AESKey generateRandomKey() {
    AESKey key{};
    std::random_device rd;
    std::mt19937_64 gen(((uint64_t)rd() << 32) ^ rd() ^
        (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (auto& b : key) b = static_cast<uint8_t>(gen() & 0xff);
    return key;
}

uint64_t generateRandom64() {
    std::random_device rd;
    std::mt19937_64 gen(((uint64_t)rd() << 32) ^ rd() ^
        (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count());
    return gen();
}

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256Transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(data[i * 4]) << 24) | (uint32_t(data[i * 4 + 1]) << 16) |
            (uint32_t(data[i * 4 + 2]) << 8) | uint32_t(data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bitlen = len * 8;
    size_t i = 0;
    while (i + 64 <= len) {
        sha256Transform(state, data + i);
        i += 64;
    }

    uint8_t buffer[64] = { 0 };
    size_t rem = len - i;
    std::memcpy(buffer, data + i, rem);
    buffer[rem] = 0x80;

    if (rem >= 56) {
        sha256Transform(state, buffer);
        std::memset(buffer, 0, 64);
    }
    for (int j = 0; j < 8; j++) buffer[63 - j] = uint8_t(bitlen >> (8 * j));
    sha256Transform(state, buffer);

    std::array<uint8_t, 32> out{};
    for (int j = 0; j < 8; j++) {
        out[j * 4 + 0] = uint8_t(state[j] >> 24);
        out[j * 4 + 1] = uint8_t(state[j] >> 16);
        out[j * 4 + 2] = uint8_t(state[j] >> 8);
        out[j * 4 + 3] = uint8_t(state[j]);
    }
    return out;
}

static std::array<uint8_t, 32> hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen) {
    uint8_t k[64] = { 0 };
    if (keyLen > 64) {
        auto hashed = sha256(key, keyLen);
        std::memcpy(k, hashed.data(), 32);
    }
    else {
        std::memcpy(k, key, keyLen);
    }

    uint8_t o_pad[64], i_pad[64];
    for (int i = 0; i < 64; i++) {
        o_pad[i] = k[i] ^ 0x5c;
        i_pad[i] = k[i] ^ 0x36;
    }

    std::vector<uint8_t> inner(64 + msgLen);
    std::memcpy(inner.data(), i_pad, 64);
    std::memcpy(inner.data() + 64, msg, msgLen);
    auto innerHash = sha256(inner.data(), inner.size());

    std::vector<uint8_t> outer(64 + 32);
    std::memcpy(outer.data(), o_pad, 64);
    std::memcpy(outer.data() + 64, innerHash.data(), 32);
    return sha256(outer.data(), outer.size());
}

AESKey deriveKeyPBKDF2(const std::string& password, uint64_t salt, int iterations) {
    uint8_t saltBytes[8];
    for (int i = 0; i < 8; i++) saltBytes[7 - i] = uint8_t(salt >> (8 * i));

    std::vector<uint8_t> saltBlock(8 + 4, 0);
    std::memcpy(saltBlock.data(), saltBytes, 8);
    saltBlock[11] = 1;

    auto u = hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        saltBlock.data(), saltBlock.size());
    auto t = u;

    for (int i = 1; i < iterations; i++) {
        u = hmacSha256(reinterpret_cast<const uint8_t*>(password.data()), password.size(),
            u.data(), u.size());
        for (int j = 0; j < 32; j++) t[j] ^= u[j];
    }

    AESKey key{};
    std::memcpy(key.data(), t.data(), 16); 
    return key;
}

bool saveKey(const AESKey& key, const char* filename) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(key.data()), key.size());
    return true;
}

bool loadKey(AESKey& key, const char* filename) {
    std::ifstream f(filename, std::ios::binary);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(key.data()), key.size());
    return f.gcount() == 16;
}

static void makeCounter(uint8_t block[16], uint64_t nonce, uint64_t counter) {
    for (int i = 0; i < 8; i++) block[7 - i] = uint8_t(nonce >> (8 * i));
    for (int i = 0; i < 8; i++) block[15 - i] = uint8_t(counter >> (8 * i));
}

void ctrCryptSerial(const uint8_t* in, uint8_t* out, size_t len,
    const AESKey& key, uint64_t nonce, uint64_t initialCounter) {
    AES128 aes(key);
    size_t blocks = (len + 15) / 16;
    for (size_t i = 0; i < blocks; i++) {
        uint8_t ctr[16], stream[16];
        makeCounter(ctr, nonce, initialCounter + i);
        aes.encryptBlock(ctr, stream);
        size_t n = std::min<size_t>(16, len - i * 16);
        for (size_t j = 0; j < n; j++) out[i * 16 + j] = in[i * 16 + j] ^ stream[j];
    }
}

void ctrCryptOpenMP(const uint8_t* in, uint8_t* out, size_t len,
    const AESKey& key, int threads, bool dynamic,
    uint64_t nonce, uint64_t initialCounter) {
    if (len == 0) return;

    AES128 aes(key);
    size_t blocks = (len + 15) / 16;
    omp_set_num_threads(threads);

    #pragma omp parallel for schedule(static)
    for (long long i = 0; i < (long long)blocks; i++) {
            uint8_t ctr[16], stream[16];
            makeCounter(ctr, nonce, initialCounter + i);
            aes.encryptBlock(ctr, stream);
            size_t n = std::min<size_t>(16, len - i * 16);
            for (size_t j = 0; j < n; j++) {
                out[i * 16 + j] = in[i * 16 + j] ^ stream[j];
            }
    }
   
}

bool readFile(const char* filename, std::vector<uint8_t>& data) {
    std::ifstream f(filename, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto size = f.tellg();
    f.seekg(0);
    data.resize((size_t)size);
    return f.read(reinterpret_cast<char*>(data.data()), size).good() || f.eof();
}

bool writeFile(const char* filename, const std::vector<uint8_t>& data) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return (bool)f;
}