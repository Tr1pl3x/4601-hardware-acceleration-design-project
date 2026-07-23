# Bitcoin miner software baseline

This folder is the team's software baseline and golden reference model for the
COMP4601 Bitcoin miner project. It is plain C++17 and contains no HLS code yet. Every later
piece (the HLS kernel, the board host program) gets checked against the
answers this code produces.

## Files

| File | What it is |
|---|---|
| `sha256.h` / `sha256.cpp` | SHA-256 and the double hash `sha256d`. Every constant is cited to FIPS 180-4 by section. `sha256_compress()` is the part that later becomes the FPGA kernel. |
| `miner.cpp` | The block header struct and serializer, the nBits target decoder, the win check, the `mine_range` search loop, and the command line. |
| `sha256_test.cpp` | Five known-answer tests. Exits non-zero if any fail. |
| `Makefile` | Build rules, see below. |

## Build and run

Needs g++ with C++17 (MSYS2 g++ on Windows works too).

```
make              # builds ./miner and ./sha256_test
make run-test     # runs the five tests, all must pass
make clean
```

The miner has four modes:

```
./miner genesis           # hash the real 2009 genesis block; must print 000000000019d668...
./miner demo 2            # mine against an easy target; finds nonce 8603 in milliseconds
./miner bench 2000000     # speed test, single thread, prints kH/s
./miner bench 8000000 4   # same on 4 threads (the fair software baseline on the board)
./miner golden 16         # print header/hash pairs for the future HLS testbench
```

## Cross-compile for the KV260

```
make arm CXX=<path to your aarch64-linux-gnu-g++>
```

With a local Vitis 2025.2 install:

```
make arm CXX=/tools/Xilinx/2025.2/Vitis/gnu/aarch64/lin/aarch64-linux/bin/aarch64-linux-gnu-g++
```

Copy `miner_arm` to the board and run the same modes there. We report speedup
against the board numbers, not against laptop numbers.

## One warning

Byte order is the trap in this code. Bitcoin stores header numbers
little-endian, and block explorers show hashes byte-reversed. The reversal
logic lives in `serialize_header`, `print_hash_display`, and
`hash_below_target`. If you change anything near those, run `./miner genesis`
again. A matching genesis hash proves the whole pipeline at once: the hash
core, the double hash, the header layout, the byte order, and the target
decoder.
