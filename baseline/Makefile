# Baseline software miner and its self-tests.
#
# Native build (your laptop / a CSE machine):
#   make            build miner and sha256_test
#   make run-test   build and run the known-answer tests
#   make clean
#
# Build for the Kria ARM cores (Cortex-A53, aarch64). Override CXX with your
# cross-compiler or the Vitis sysroot toolchain, for example:
#   make arm CXX=aarch64-linux-gnu-g++

CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -pthread

all: miner sha256_test

miner: miner.cpp sha256.cpp sha256.h
	$(CXX) $(CXXFLAGS) miner.cpp sha256.cpp -o miner

sha256_test: sha256_test.cpp sha256.cpp sha256.h
	$(CXX) $(CXXFLAGS) sha256_test.cpp sha256.cpp -o sha256_test

run-test: sha256_test
	./sha256_test

arm:
	$(CXX) $(CXXFLAGS) miner.cpp sha256.cpp -o miner_arm

clean:
	rm -f miner sha256_test miner_arm

.PHONY: all run-test arm clean
