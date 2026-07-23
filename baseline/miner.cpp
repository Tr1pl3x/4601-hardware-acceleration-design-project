#include "sha256.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

// Block header layout and the compact "nBits" target encoding follow the
// Bitcoin protocol docs:
//   header format: https://developer.bitcoin.org/reference/block_chain.html#block-headers
//   hashing:       https://en.bitcoin.it/wiki/Block_hashing_algorithm
//   nBits target:  https://en.bitcoin.it/wiki/Difficulty
// Genesis block field values in genesis_header() are from:
//   https://en.bitcoin.it/wiki/Genesis_block

// The header is always 80 bytes: six fields in a fixed order.
static const int HEADER_BYTES = 80;

struct BlockHeader {
    uint32_t version;
    uint8_t  prev_hash[32];    // internal byte order (see the note below)
    uint8_t  merkle_root[32];  // internal byte order
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
};

// Byte order is the trap in this whole project. Bitcoin writes the integer
// fields little-endian, and the two 32-byte hashes are stored as the byte
// reversal of the values you see on a block explorer. So prev_hash and
// merkle_root already hold the internal order here, not the display order.

static void put_le32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

// Lay the header out into its 80 raw bytes, ready to hash.
static void serialize_header(const BlockHeader& h, uint8_t out[HEADER_BYTES]) {
    put_le32(out + 0, h.version);
    memcpy(out + 4, h.prev_hash, 32);
    memcpy(out + 36, h.merkle_root, 32);
    put_le32(out + 68, h.time);
    put_le32(out + 72, h.bits);
    put_le32(out + 76, h.nonce);
}

// Expand the 4-byte compact target into a full 32-byte big-endian target.
// Top byte is the exponent, low three bytes are the mantissa, and the value is
// mantissa * 256^(exponent - 3).
static void bits_to_target(uint32_t bits, uint8_t target[32]) {
    memset(target, 0, 32);
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x00ffffff;
    for (int i = 0; i < 3; i++) {
        int shift = int(exponent) - 3 + (2 - i);  // byte offset from the low end
        if (shift >= 0 && shift < 32) {
            target[31 - shift] = uint8_t(mantissa >> (8 * (2 - i)));
        }
    }
}

// A hash wins if, read as a 256-bit number, it is below the target. The raw
// sha256d output is little-endian, so walk it back to front to get the
// big-endian view and compare most significant byte first.
static bool hash_below_target(const uint8_t raw_hash[32], const uint8_t target[32]) {
    for (int i = 0; i < 32; i++) {
        uint8_t hb = raw_hash[31 - i];
        uint8_t tb = target[i];
        if (hb < tb) return true;
        if (hb > tb) return false;
    }
    return false;  // exactly equal does not count as below
}

// Print a hash the way explorers show it: byte-reversed, as hex.
static void print_hash_display(const uint8_t raw_hash[32]) {
    for (int i = 0; i < 32; i++) printf("%02x", raw_hash[31 - i]);
}

// Search nonces in [start, end). This is the loop that moves into the FPGA
// during acceleration, so it stays self-contained: fixed-size buffers, one
// double hash per nonce, no allocation. For now it re-lays the whole header
// every iteration. The midstate optimization (only the nonce changes, so the
// first compression can be cached) belongs to the acceleration phase, not the
// baseline.
static bool mine_range(BlockHeader header, const uint8_t target[32],
                       uint64_t start, uint64_t end,
                       uint32_t& found_nonce, uint64_t& hashes_done) {
    uint8_t block[HEADER_BYTES];
    uint8_t hash[32];
    hashes_done = 0;
    for (uint64_t n = start; n < end; n++) {
        header.nonce = uint32_t(n);
        serialize_header(header, block);
        sha256d(block, HEADER_BYTES, hash);
        hashes_done++;
        if (hash_below_target(hash, target)) {
            found_nonce = uint32_t(n);
            return true;
        }
    }
    return false;
}

// The real Bitcoin genesis block. Used as a known-answer check and as the base
// header for benchmarking and the demo.
static BlockHeader genesis_header() {
    BlockHeader h;
    memset(&h, 0, sizeof(h));
    h.version = 1;
    // prev_hash is all zeros for the genesis block.
    // Merkle root in internal order (the display value reversed). Display value:
    // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
    static const uint8_t merkle_internal[32] = {
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
        0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a};
    memcpy(h.merkle_root, merkle_internal, 32);
    h.time  = 1231006505;   // 2009-01-03 18:15:05 UTC
    h.bits  = 0x1d00ffff;
    h.nonce = 2083236893;   // the known winning nonce
    return h;
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "help";

    if (mode == "genesis") {
        // Rebuild the genesis header from its fields and confirm sha256d gives
        // the published block hash.
        BlockHeader h = genesis_header();
        uint8_t block[HEADER_BYTES], hash[32];
        serialize_header(h, block);
        sha256d(block, HEADER_BYTES, hash);

        printf("genesis hash: ");
        print_hash_display(hash);
        printf("\nexpected:     "
               "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\n");

        uint8_t target[32];
        bits_to_target(h.bits, target);
        printf("below target: %s\n", hash_below_target(hash, target) ? "yes" : "no");
        return 0;
    }

    if (mode == "bench") {
        // Throughput: double hashes per second, on one thread by default or on
        // T threads sweeping disjoint nonce slices. The 4-thread run on the
        // board's A53 cores is the fair software baseline the accelerator gets
        // compared against.
        BlockHeader h = genesis_header();
        uint8_t target[32];
        memset(target, 0, 32);  // unreachable target, so the loops never stop early
        uint64_t count = (argc > 2) ? strtoull(argv[2], nullptr, 10) : 2000000;
        int nthreads = (argc > 3) ? atoi(argv[3]) : 1;
        if (nthreads < 1) nthreads = 1;

        std::vector<uint64_t> done(nthreads, 0);
        std::vector<std::thread> pool;
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < nthreads; i++) {
            uint64_t begin = count * uint64_t(i) / nthreads;
            uint64_t end   = count * uint64_t(i + 1) / nthreads;
            pool.emplace_back([&h, &target, &done, i, begin, end] {
                // mine_range bumps its counter every nonce; adjacent vector
                // slots would false-share a cache line, so count locally and
                // store once at the end
                uint64_t local = 0;
                uint32_t found = 0;
                mine_range(h, target, begin, end, found, local);
                done[i] = local;
            });
        }
        for (auto& th : pool) th.join();
        auto t1 = std::chrono::steady_clock::now();

        uint64_t total = 0;
        for (uint64_t d : done) total += d;
        double secs = std::chrono::duration<double>(t1 - t0).count();
        printf("hashed %llu headers in %.3f s = %.2f kH/s (%d thread%s)\n",
               (unsigned long long)total, secs, total / secs / 1000.0,
               nthreads, nthreads == 1 ? "" : "s");
        return 0;
    }

    if (mode == "demo") {
        // Mine against an easy target so a winner shows up fast. The target is
        // "the top N bytes must be zero"; N defaults to 2 (about 65k tries).
        int zeros = (argc > 2) ? atoi(argv[2]) : 2;
        BlockHeader h = genesis_header();
        uint8_t target[32];
        memset(target, 0xff, 32);
        for (int i = 0; i < zeros && i < 32; i++) target[i] = 0x00;

        uint32_t found = 0;
        uint64_t done = 0;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = mine_range(h, target, 0, 0x100000000ULL, found, done);
        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();

        if (ok) {
            uint8_t block[HEADER_BYTES], hash[32];
            h.nonce = found;
            serialize_header(h, block);
            sha256d(block, HEADER_BYTES, hash);
            printf("found nonce %u after %llu tries (%.3f s)\nhash: ",
                   found, (unsigned long long)done, secs);
            print_hash_display(hash);
            printf("\n");
        } else {
            printf("no nonce below target in the whole range\n");
        }
        return 0;
    }

    if (mode == "golden") {
        // Dump header/hash pairs for the HLS C testbench to check against, the
        // same role out.gold.dat plays in the labs. One pair per line:
        //   <80-byte header hex> <32-byte sha256d hex in display order>
        int n = (argc > 2) ? atoi(argv[2]) : 16;
        BlockHeader h = genesis_header();
        uint8_t block[HEADER_BYTES], hash[32];
        for (int i = 0; i < n; i++) {
            h.nonce = 2083236893u + uint32_t(i) - uint32_t(n / 2);
            serialize_header(h, block);
            sha256d(block, HEADER_BYTES, hash);
            for (int b = 0; b < HEADER_BYTES; b++) printf("%02x", block[b]);
            printf(" ");
            print_hash_display(hash);
            printf("\n");
        }
        return 0;
    }

    printf("usage: %s [genesis | bench [n] [threads] | demo [zerobytes] | golden [n]]\n", argv[0]);
    printf("  genesis   verify the real genesis block hash\n");
    printf("  bench     measure hashes per second on 1 (default) or T threads\n");
    printf("  demo      mine against an easy target and print the winning nonce\n");
    printf("  golden    dump header/hash pairs for the HLS testbench\n");
    return 0;
}
