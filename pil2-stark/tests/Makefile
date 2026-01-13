# pil2-stark/tests Makefile
#
# Builds test binaries that validate STARK components.

# Directories
ROOT_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))..
BUILD_DIR := ./build
GOLDILOCKS_SRC := $(ROOT_DIR)/src/goldilocks/src

# Platform detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    HOMEBREW_PREFIX := $(shell brew --prefix)
    CXX      = clang++
    SDKPATH  = /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
    CXXFLAGS = -std=c++17 -Wall -pthread -O3 \
               -I$(GOLDILOCKS_SRC) \
               -I$(HOMEBREW_PREFIX)/include \
               -I$(HOMEBREW_PREFIX)/opt/libomp/include \
               -isysroot $(SDKPATH) -Xpreprocessor -fopenmp
    LDFLAGS  = -L$(HOMEBREW_PREFIX)/lib \
               -L$(HOMEBREW_PREFIX)/opt/libomp/lib \
               -L$(SDKPATH)/usr/lib
    LDLIBS   = -lomp -lgtest -lgtest_main -lgmpxx -lgmp -lpthread
endif

ifeq ($(UNAME_S),Linux)
    CXX      = g++
    CXXFLAGS = -std=c++17 -Wall -pthread -O3 \
               -I$(GOLDILOCKS_SRC) \
               -I/usr/include -I/usr/local/include \
               -fopenmp -mavx2 -D__AVX2__ -D__USE_ASSEMBLY__
    LDFLAGS  = -L/usr/lib -L/usr/local/lib
    LDLIBS   = -fopenmp -lgtest -lgtest_main -lgmpxx -lgmp -lpthread -lstdc++
endif

# Goldilocks source files (needed for Poseidon2 and field operations)
GOLDILOCKS_SRCS := $(shell find $(GOLDILOCKS_SRC) -name "*.cpp")
GOLDILOCKS_OBJS := $(patsubst $(GOLDILOCKS_SRC)/%.cpp,$(BUILD_DIR)/goldilocks/%.o,$(GOLDILOCKS_SRCS))

# FRI Pinning Test
FRI_PINNING_SRC := fri-pinning/fri_pinning_test.cpp
FRI_PINNING_OBJ := $(BUILD_DIR)/fri-pinning/fri_pinning_test.o
FRI_PINNING_BIN := $(BUILD_DIR)/fri-pinning-test

# Include path for local headers
FRI_PINNING_CXXFLAGS := $(CXXFLAGS) -Ifri-pinning

# Default target
.PHONY: all clean fri-pinning-test

all: fri-pinning-test

fri-pinning-test: $(FRI_PINNING_BIN)

$(FRI_PINNING_BIN): $(FRI_PINNING_OBJ) $(GOLDILOCKS_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $^ $(LDFLAGS) $(LDLIBS) -o $@

$(FRI_PINNING_OBJ): $(FRI_PINNING_SRC)
	@mkdir -p $(dir $@)
	$(CXX) $(FRI_PINNING_CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/goldilocks/%.o: $(GOLDILOCKS_SRC)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
