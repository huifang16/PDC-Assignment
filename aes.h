#pragma once
#include <array>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

using AESKey = std::array<uint8_t, 16>;

struct AES128 {
    explicit AES128(const AESKey& key);
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
    const uint8_t* expandedKey() const { return roundKey.data(); }

    std::array<uint8_t, 176> roundKey{};
    static uint8_t sbox(uint8_t x);
    static uint8_t xtime(uint8_t x);
    static void subBytes(uint8_t* state);
    static void shiftRows(uint8_t* state);
    static void mixColumns(uint8_t* state);
    void addRoundKey(uint8_t* state, int round) const;
    void keyExpansion(const AESKey& key);
};

AESKey generateRandomKey();
uint64_t generateRandom64();

AESKey deriveKeyPBKDF2(const std::string& password, uint64_t salt, int iterations = 10000);

bool saveKey(const AESKey& key, const char* filename);
bool loadKey(AESKey& key, const char* filename);

void ctrCryptSerial(const uint8_t* input, uint8_t* output, size_t length,
    const AESKey& key, uint64_t nonce = 0, uint64_t initialCounter = 0);

void ctrCryptOpenMP(const uint8_t* input, uint8_t* output, size_t length,
    const AESKey& key, int threads, bool dynamic = false,
    uint64_t nonce = 0, uint64_t initialCounter = 0);

void ctrCryptCUDA(const uint8_t* input, uint8_t* output, size_t length,
    const AESKey& key, int blockSize = 256,
    uint64_t nonce = 0, uint64_t initialCounter = 0);

void warmUpCUDA();

bool readFile(const char* filename, std::vector<uint8_t>& data);
bool writeFile(const char* filename, const std::vector<uint8_t>& data);