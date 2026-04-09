# Makefile for flow_extractor
# Usage:
#   make          — build release binary
#   make debug    — build with debug symbols
#   make clean    — remove build artifacts
#   make install  — install to /usr/local/bin (requires sudo)

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
INCLUDES := -I.
LIBS     := -lpcap -lpthread

# Debug variant
DBGFLAGS := -std=c++17 -Wall -Wextra -g -fsanitize=address,undefined

SRCS := flow_extractor.cpp \
        flow_table.cpp     \
        feature_writer.cpp \
        connection_tracker.cpp

TARGET := flow_extractor

.PHONY: all debug clean install check-deps

all: check-deps $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)
	@echo "[OK] Built: ./$(TARGET)"

debug: $(SRCS)
	$(CXX) $(DBGFLAGS) $(INCLUDES) $^ -o $(TARGET)_debug $(LIBS)
	@echo "[OK] Debug build: ./$(TARGET)_debug"

check-deps:
	@which $(CXX) > /dev/null 2>&1 || (echo "Error: $(CXX) not found" && exit 1)
	@echo "#include <pcap.h>\nint main(){return 0;}" | \
		$(CXX) -x c++ - -lpcap -o /dev/null 2>/dev/null || \
		(echo "Error: libpcap not found. Install with:" && \
		 echo "  Ubuntu/Debian: sudo apt install libpcap-dev" && \
		 echo "  RHEL/CentOS:   sudo yum install libpcap-devel" && \
		 echo "  macOS:         brew install libpcap" && exit 1)
	@echo "[OK] Dependencies satisfied"

install: all
	sudo cp $(TARGET) /usr/local/bin/
	@echo "[OK] Installed to /usr/local/bin/$(TARGET)"

clean:
	rm -f $(TARGET) $(TARGET)_debug
	@echo "[OK] Cleaned"