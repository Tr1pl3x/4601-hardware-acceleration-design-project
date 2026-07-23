// C testbench for the miner HLS kernel.
//
// Two checks:
//   Test 1 (hashing): read golden.dat, hash every header with the kernel's
//       sha256d_80, and compare against the golden hash. This proves the
//       kernel computes the same double hash as the software baseline.
//   Test 2 (search): give the kernel an easy target (the same one as
//       "./miner demo 2") and confirm its nonce search finds nonce 8603.
//
// Vitis copies files listed as tb.file into the C simulation working folder,
// so golden.dat is opened by its plain name. main() returns non-zero on any
// failure, which is how C simulation reports PASS or FAIL.

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Functions from mine.cpp. In HLS C simulation the design file and this
// testbench are compiled together, so these declarations are enough.
void sha256d_80(const uint8_t header[80], uint8_t out[32]);
void mine(const uint8_t header[80], const uint8_t target[32],
          uint32_t nonce_start, uint32_t nonce_count,
          uint32_t *found_nonce, int *found);

// Turn a hex string into bytes. Returns how many bytes were written.
static int hex_to_bytes(const char *hex, uint8_t *out, int max_bytes) {
    int n = 0;
    while (n < max_bytes && hex[2 * n] && hex[2 * n + 1]) {
        unsigned v;
        sscanf(hex + 2 * n, "%2x", &v);
        out[n] = (uint8_t)v;
        n++;
    }
    return n;
}

int main() {
    // ---------- Test 1: hashing against golden.dat ----------
    FILE *fp = fopen("golden.dat", "r");
    if (!fp) {
        printf("ERROR: cannot open golden.dat\n");
        return 1;
    }

    char hdr_hex[256];
    char hash_hex[128];
    int lines = 0;
    int hash_mismatches = 0;
    uint8_t first_header[80];
    int have_first = 0;

    // Each line: <160 hex chars header> <64 hex chars hash>
    while (fscanf(fp, "%160s %64s", hdr_hex, hash_hex) == 2) {
        uint8_t hdr[80];
        uint8_t gold[32];
        hex_to_bytes(hdr_hex, hdr, 80);
        hex_to_bytes(hash_hex, gold, 32);

        if (!have_first) {
            memcpy(first_header, hdr, 80);
            have_first = 1;
        }

        uint8_t raw[32];
        sha256d_80(hdr, raw);

        // The golden hash is in display order, which is the raw hash reversed.
        // So gold[i] must equal raw[31 - i].
        int ok = 1;
        for (int i = 0; i < 32; i++) {
            if (gold[i] != raw[31 - i]) { ok = 0; break; }
        }
        if (!ok) {
            hash_mismatches++;
            if (hash_mismatches <= 3) printf("  hash mismatch on line %d\n", lines);
        }
        lines++;
    }
    fclose(fp);

    int test1_ok = (lines > 0 && hash_mismatches == 0);
    printf("Test 1 (hashing): %d lines, %d mismatches -> %s\n",
           lines, hash_mismatches, test1_ok ? "PASS" : "FAIL");

    if (!have_first) {
        printf("ERROR: golden.dat had no lines\n");
        return 1;
    }

    // ---------- Test 2: the search finds the demo nonce ----------
    // Easy target: the top two bytes must be zero, everything else 0xff.
    // This is exactly what "./miner demo 2" uses, and it finds nonce 8603.
    uint8_t target[32];
    memset(target, 0xff, 32);
    target[0] = 0x00;
    target[1] = 0x00;

    uint32_t found_nonce = 0;
    int found = 0;
    // The first golden header shares the genesis 76-byte prefix, so searching
    // from nonce 0 reproduces the demo. 20000 is more than enough (8603 < 20000).
    mine(first_header, target, 0, 20000, &found_nonce, &found);

    int test2_ok = (found == 1 && found_nonce == 8603);
    printf("Test 2 (search): found=%d nonce=%u -> %s\n",
           found, found_nonce, test2_ok ? "PASS" : "FAIL");

    int failed = (!test1_ok) || (!test2_ok);
    printf("%s\n", failed ? "FAILED" : "ALL PASS");
    return failed;
}
