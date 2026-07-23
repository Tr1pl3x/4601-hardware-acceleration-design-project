#include "sha256.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

// Known-answer tests for the SHA-256 core. The plain SHA-256 vectors are from
// FIPS 180-4 Appendix B and the widely published empty-string value. The final
// test hashes the real Bitcoin genesis block header, which is what makes this a
// trustworthy baseline: if these bytes produce the published block hash, the
// core and its byte handling are correct.
//   FIPS 180-4: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//   genesis block: https://en.bitcoin.it/wiki/Genesis_block

static int g_pass = 0;
static int g_fail = 0;

static void to_hex(const uint8_t* d, int n, char* out) {
    static const char* hx = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2]     = hx[d[i] >> 4];
        out[i * 2 + 1] = hx[d[i] & 0xf];
    }
    out[n * 2] = 0;
}

static void from_hex(const char* hex, uint8_t* out, int n) {
    for (int i = 0; i < n; i++) {
        int hi = hex[i * 2], lo = hex[i * 2 + 1];
        hi = (hi >= 'a') ? hi - 'a' + 10 : (hi >= 'A') ? hi - 'A' + 10 : hi - '0';
        lo = (lo >= 'a') ? lo - 'a' + 10 : (lo >= 'A') ? lo - 'A' + 10 : lo - '0';
        out[i] = uint8_t(hi * 16 + lo);
    }
}

static void check(const char* name, const uint8_t* digest, const char* expect_hex) {
    char got[65];
    to_hex(digest, 32, got);
    if (strcmp(got, expect_hex) == 0) {
        printf("[pass] %s\n", name);
        g_pass++;
    } else {
        printf("[FAIL] %s\n  got:      %s\n  expected: %s\n", name, got, expect_hex);
        g_fail++;
    }
}

int main() {
    uint8_t d[32];

    // Single-block message.
    sha256((const uint8_t*)"abc", 3, d);
    check("sha256(\"abc\")", d,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Empty message. Exercises a padding-only block.
    sha256((const uint8_t*)"", 0, d);
    check("sha256(\"\")", d,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 56-byte message. The 0x80 pad plus the 8-byte length spill into a second
    // block, so this checks the two-block padding path.
    const char* two_block = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t*)two_block, strlen(two_block), d);
    check("sha256(56-byte message, spills to two blocks)", d,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Double hash of the empty string, a known sha256d value.
    sha256d((const uint8_t*)"", 0, d);
    check("sha256d(\"\")", d,
          "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

    // The genesis block header, 80 raw bytes in internal order:
    //   version 01000000
    //   prev    32 zero bytes
    //   merkle  3ba3edfd...4b1e5e4a  (display value reversed)
    //   time    29ab5f49            (little-endian 1231006505)
    //   bits    ffff001d            (little-endian 0x1d00ffff)
    //   nonce   1dac2b7c            (little-endian 2083236893)
    const char* genesis_hex =
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49" "ffff001d" "1dac2b7c";
    uint8_t header[80];
    from_hex(genesis_hex, header, 80);
    sha256d(header, 80, d);
    // Expected raw sha256d output (internal order). Reversed for display this is
    // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.
    check("sha256d(genesis header)", d,
          "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
