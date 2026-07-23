# Bitcoin miner HLS baseline

This folder is a saved snapshot of the first HLS version of the miner, made for
the report.

## Files

| File | What it is |
|---|---|
| `mine.cpp` | The HLS kernel. Top function `mine`. SHA-256 compression, a fixed-size double hash, and the nonce search loop. |
| `mine_test.cpp` | The C testbench. Reads `golden.dat`, checks the hashes match, then checks the search finds nonce 8603. |
| `golden.dat` | 32 header/hash pairs made by the software baseline (`./miner golden 32`). The answer key the testbench checks against. |
| `hls_config.cfg` | The Vitis HLS settings: part, clock, top function, and the source and testbench files. |
| `morris-basline-syn-report.rpt` | The C synthesis report from Vitis for this kernel. |

## How to build it yourself

You need Vitis 2025.2 with `vitis` and `v++` on your PATH. All three input files
and `hls_config.cfg` are in this folder, and the config uses plain file names, so
it builds from here with no extra setup.


### Vitis Setup 

1. Open Vitis and pick a workspace folder.
2. Go to File, New Component, HLS. Name it `mine_hls`.
3. Add `mine.cpp` as the design file and set the top function to `mine`.
4. Add `mine_test.cpp` and `golden.dat` as testbench files.
5. On the part page, choose `xck26-sfvc784-2LV-c`.
6. Open the component's `hls_config.cfg` and set `clock=200MHz` (5 ns).
7. Run C SIMULATION, then C SYNTHESIS.

The settings to match are all in `hls_config.cfg`: part `xck26-sfvc784-2LV-c`,
clock 5 ns (200 MHz), `flow_target=vitis`, `package.output.format=xo`, top `mine`.

Make sure the testbench is the file `mine_test.cpp`, not the `hls_src` folder. If
C simulation fails with `undefined symbol: main`, the testbench file was not
added.

## How `mine.cpp` relates to the software baseline

`mine.cpp` is not a plain merge of `sha256.cpp` and `miner.cpp`. It takes only
the pieces that can run on the FPGA and rewrites them for hardware.

| Piece | From | What happened |
|---|---|---|
| `sha256_compress` + the `K[]` / `H0[]` constants + `rotr` | `sha256.cpp` | Copied almost exactly |
| `hash_below_target` (the win rule) | `miner.cpp` | Copied |
| `sha256d_80` (fixed double hash) | replaces `sha256()` / `sha256d()` | Rewritten. The originals handle any length; the kernel only ever hashes 80 bytes, so the padding is now hardcoded constants |
| `mine()` (the top function) | replaces `mine_range` | Rewritten for hardware: it takes a ready-made 80-byte header, writes the nonce into bytes 76 to 79, and has the HLS interface pragmas |

Left out of `mine.cpp` on purpose (these stay on the software or host side, not
the FPGA):

- `BlockHeader`, `serialize_header`, `bits_to_target`, `genesis_header`
- the command line (`main` and the `genesis` / `bench` / `demo` / `golden` modes)
- the variable-length `sha256()` wrapper

The header building and target decoding come back later in the host program that
runs on the board's ARM CPU and feeds the kernel.

## Synthesis result (version 1 baseline)

Full numbers are in `morris-basline-syn-report.rpt`. Summary:

| Item | Value |
|---|---|
| Nonce loop II | 231 (resource limited; the goal in later versions is 1) |
| Cycles per nonce | about 231, so about 1155 ns, about 0.87 MH/s for one core |
| BRAM | 23 (7%) |
| DSP | 0 |
| FF | 39,286 (16%) |
| LUT | 68,653 (58%) |
| Timing | met at 200 MHz, worst slack +0.09 ns |

The nonce loop hit an II violation because the `hdr` array has only two memory
ports, so the pipeline cannot read and write it fast enough. This is expected
for the plain version and marks where the next optimization goes: partition the
`hdr` array so each byte is its own register. One SHA-256 core already uses about
half the LUTs, so shrinking that logic matters before adding parallel cores.
