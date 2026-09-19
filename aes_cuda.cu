#include "aes.h"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <iostream>
#include <cstring>

__constant__ uint8_t d_sbox[256] = {
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

__constant__ uint8_t d_roundKey[176];

__device__ __forceinline__ uint8_t xtime_dev(uint8_t x) {
    return uint8_t((x << 1) ^ ((x >> 7) * 0x1b));
}

__device__ void aes128EncryptBlockDev(const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    for (int i = 0; i < 16; i++) {
        s[i] = in[i];
    }

    for (int r = 0; r < 9; r++) {
        for (int i = 0; i < 16; i++) {
            s[i] = d_sbox[s[i]];
        }

        uint8_t t[16];
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                t[4 * col + row] = s[4 * ((col + row) % 4) + row];
            }
        }

        for (int col = 0; col < 4; col++) {
            uint8_t* a = &t[4 * col];
            uint8_t tx = a[0] ^ a[1] ^ a[2] ^ a[3];
            uint8_t u = a[0];
            s[4 * col + 0] = a[0] ^ tx ^ xtime_dev(a[0] ^ a[1]);
            s[4 * col + 1] = a[1] ^ tx ^ xtime_dev(a[1] ^ a[2]);
            s[4 * col + 2] = a[2] ^ tx ^ xtime_dev(a[2] ^ a[3]);
            s[4 * col + 3] = a[3] ^ tx ^ xtime_dev(a[3] ^ u);
        }

        const uint8_t* rk = &d_roundKey[r * 16];
        for (int i = 0; i < 16; i++) {
            s[i] ^= rk[i];
        }
    }

    for (int i = 0; i < 16; i++) {
        s[i] = d_sbox[s[i]];
    }

    uint8_t t[16];
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            t[4 * col + row] = s[4 * ((col + row) % 4) + row];
        }
    }

    const uint8_t* rk10 = &d_roundKey[144];
    for (int i = 0; i < 16; i++) {
        out[i] = t[i] ^ rk10[i];
    }
}

__global__ void aesCtrKernel(const uint8_t* __restrict__ in, uint8_t* __restrict__ out,
    size_t len, size_t totalBlocks, uint64_t nonce, uint64_t initialCounter) {
    size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= totalBlocks) return;

    uint8_t ctr[16];
    for (int i = 0; i < 8; i++) {
        ctr[7 - i] = uint8_t(nonce >> (8 * i));
    }
    uint64_t c = initialCounter + idx;
    for (int i = 0; i < 8; i++) {
        ctr[15 - i] = uint8_t(c >> (8 * i));
    }

    uint8_t stream[16];
    aes128EncryptBlockDev(ctr, stream);

    size_t offset = idx * 16;
    size_t bytes = (offset + 16 <= len) ? 16 : (len - offset);

    for (size_t j = 0; j < bytes; j++) {
        out[offset + j] = in[offset + j] ^ stream[j];
    }
}

static void launchAesCtrKernel(int grid, int block, const uint8_t* in, uint8_t* out,
    size_t len, size_t totalBlocks, uint64_t nonce, uint64_t initialCounter) {
    dim3 g(grid);
    dim3 b(block);
    void* kernelArgs[] = {
        (void*)&in,
        (void*)&out,
        (void*)&len,
        (void*)&totalBlocks,
        (void*)&nonce,
        (void*)&initialCounter
    };
    cudaLaunchKernel((const void*)aesCtrKernel, g, b, kernelArgs, 0, nullptr);
}

void warmUpCUDA() {
    uint8_t dummy[16] = { 0 };
    uint8_t* d_dummy = nullptr;
    if (cudaMalloc(&d_dummy, 16) != cudaSuccess) return;
    cudaMemcpy(d_dummy, dummy, 16, cudaMemcpyHostToDevice);

    launchAesCtrKernel(1, 32, d_dummy, d_dummy, 16, 1, 0, 0);

    cudaDeviceSynchronize();
    cudaFree(d_dummy);
}

void ctrCryptCUDA(const uint8_t* in, uint8_t* out, size_t len,
    const AESKey& key, int blockSize, uint64_t nonce, uint64_t initialCounter) {
    if (len == 0 || in == nullptr || out == nullptr) return;

    AES128 aes(key);
    if (cudaMemcpyToSymbol(d_roundKey, aes.expandedKey(), 176, 0, cudaMemcpyHostToDevice) != cudaSuccess) {
        return;
    }

    uint8_t* d_in = nullptr;
    uint8_t* d_out = nullptr;
    if (cudaMalloc(&d_in, len) != cudaSuccess) {
        cudaGetLastError();
        return;
    }
    if (cudaMalloc(&d_out, len) != cudaSuccess) {
        cudaFree(d_in);
        cudaGetLastError();
        return;
    }

    cudaMemcpy(d_in, in, len, cudaMemcpyHostToDevice);

    size_t totalBlocks = (len + 15) / 16;
    int numBlocks = (int)((totalBlocks + blockSize - 1) / blockSize);
    if (numBlocks < 1) numBlocks = 1;

    launchAesCtrKernel(numBlocks, blockSize, d_in, d_out, len, totalBlocks, nonce, initialCounter);

    cudaDeviceSynchronize();
    cudaMemcpy(out, d_out, len, cudaMemcpyDeviceToHost);

    cudaFree(d_in);
    cudaFree(d_out);
}