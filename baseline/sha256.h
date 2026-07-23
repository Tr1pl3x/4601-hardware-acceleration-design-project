#ifndef SHA256_H
#define SHA256_H

#include <cstdint>
#include <cstddef>

// SHA-256, defined in FIPS PUB 180-4 (Secure Hash Standard).
// Spec PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
// The round constants, the initial state, and the round and message-schedule
// formulas in sha256.cpp are taken directly from that document. Nothing here
// is invented.
//
// The code avoids STL, heap allocation and I/O so it ports cleanly to Vitis
// HLS. sha256_compress() is the piece that becomes the FPGA kernel later; the
// variable-length sha256() wrapper is for the software baseline and tests. Keep
// this file free of anything that cannot synthesize.

// A digest is 32 bytes (256 bits).
static const int SHA256_DIGEST_BYTES = 32;
// SHA-256 works through the message one 64-byte (512-bit) block at a time.
static const int SHA256_BLOCK_BYTES = 64;

// Hash len bytes of data. Writes 32 bytes into digest.
void sha256(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_BYTES]);

// Double SHA-256: sha256(sha256(data)). This is Bitcoin's "sha256d".
void sha256d(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_BYTES]);

// Fold one 64-byte block into the eight-word state. Exposed on its own because
// the miner will reuse it for the midstate trick during acceleration.
void sha256_compress(uint32_t state[8], const uint8_t block[SHA256_BLOCK_BYTES]);

#endif
