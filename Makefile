# DPI Engine -- dependency-free build.
# Requires only a C++17 compiler. See CMakeLists.txt for a CMake build.

CXX      ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Iinclude
LDFLAGS  ?= -pthread

CORE = src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp

ENGINE = src/dpi_engine.cpp src/connection_tracker.cpp src/rule_manager.cpp \
         src/fast_path.cpp src/load_balancer.cpp

BINARIES = dpi_engine dpi_mt dpi_simple

.PHONY: all clean test
all: $(BINARIES)

# Modular multi-threaded engine: rules files, wildcard domains, per-thread stats.
dpi_engine: src/main_dpi.cpp $(ENGINE) $(CORE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

# Self-contained multi-threaded engine: same pipeline, one translation unit.
dpi_mt: src/dpi_mt.cpp $(CORE)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

# Single-threaded reference implementation.
dpi_simple: src/main_working.cpp $(CORE)
	$(CXX) $(CXXFLAGS) -o $@ $^

test: test_sni
	./test_sni

test_sni: tests/test_sni.cpp src/types.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(BINARIES) test_sni
	rm -rf *.dSYM
