#include "sha256.h"
#include <cstring>

// Every constant and formula here comes from FIPS PUB 180-4:
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//   section 4.2.2  the 64 round constants K
//   section 4.1.2  the Ch, Maj and sigma mixing functions
//   section 5.1.1  the padding scheme
//   section 5.3.3  the eight initial state words
//   section 6.2    the message schedule and the per-round update

namespace {

// Round constants: the first 32 bits of the fractional parts of the cube roots
// of the first 64 primes (FIPS 180-4, 4.2.2).
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Initial state: the first 32 bits of the fractional parts of the square roots
// of the first 8 primes (FIPS 180-4, 5.3.3).
const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// The six mixing functions (FIPS 180-4, 4.1.2).
inline uint32_t big_sigma0(uint32_t x)   { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t big_sigma1(uint32_t x)   { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t small_sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t small_sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

}  // namespace

void sha256_compress(uint32_t state[8], const uint8_t block[SHA256_BLOCK_BYTES]) {
    uint32_t w[64];

    // Load 16 message words. SHA-256 reads each word big-endian, so the first
    // byte of the block is the top byte of w[0].
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t(block[i * 4])     << 24) |
               (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) <<  8) |
               (uint32_t(block[i * 4 + 3]));
    }
    // Extend to 64 words (6.2.2 step 1).
    for (int i = 16; i < 64; i++) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // 64 rounds (6.2.2 step 3).
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = big_sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_BYTES]) {
    uint32_t state[8];
    for (int i = 0; i < 8; i++) state[i] = H0[i];

    // Fold every whole 64-byte block.
    size_t full = len / SHA256_BLOCK_BYTES;
    for (size_t i = 0; i < full; i++) {
        sha256_compress(state, data + i * SHA256_BLOCK_BYTES);
    }

    // Padding (5.1.1): append a 0x80 byte, then zeros, then the message length
    // in bits as a 64-bit big-endian number. That tail is one or two blocks.
    uint8_t tail[128];
    size_t rem = len % SHA256_BLOCK_BYTES;
    memcpy(tail, data + full * SHA256_BLOCK_BYTES, rem);
    tail[rem] = 0x80;

    // The length has to fit after the 0x80; if it does not, spill to a second
    // block.
    size_t tail_blocks = (rem + 1 + 8 > (size_t)SHA256_BLOCK_BYTES) ? 2 : 1;
    size_t tail_len = tail_blocks * SHA256_BLOCK_BYTES;
    for (size_t i = rem + 1; i < tail_len - 8; i++) tail[i] = 0;

    uint64_t bits = uint64_t(len) * 8;
    for (int i = 0; i < 8; i++) {
        tail[tail_len - 1 - i] = uint8_t(bits >> (8 * i));
    }

    for (size_t i = 0; i < tail_blocks; i++) {
        sha256_compress(state, tail + i * SHA256_BLOCK_BYTES);
    }

    // Write the state out big-endian.
    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = uint8_t(state[i] >> 24);
        digest[i * 4 + 1] = uint8_t(state[i] >> 16);
        digest[i * 4 + 2] = uint8_t(state[i] >>  8);
        digest[i * 4 + 3] = uint8_t(state[i]);
    }
}

void sha256d(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_BYTES]) {
    uint8_t first[SHA256_DIGEST_BYTES];
    sha256(data, len, first);
    sha256(first, SHA256_DIGEST_BYTES, digest);
}
