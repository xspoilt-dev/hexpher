CXX      := g++
CC       := gcc
TARGET   := hexpher

CXXFLAGS := -std=c++17 -O2 -Wall -Wextra \
            $(shell pkg-config --cflags libcapstone 2>/dev/null || echo "-I/usr/include/capstone")

CFLAGS   := -O2 -Wall \
            $(shell pkg-config --cflags libcapstone 2>/dev/null || echo "-I/usr/include/capstone")

LDFLAGS  := -lboost_system -lboost_filesystem \
            $(shell pkg-config --libs libcapstone 2>/dev/null || echo "-lcapstone") \
            -lstdc++

CXX_SRCS := main.cpp helper.cpp transmitter.cpp
C_SRCS   := disassembler.c

CXX_OBJS := $(CXX_SRCS:.cpp=.o)
C_OBJS   := $(C_SRCS:.c=.o)
OBJS     := $(CXX_OBJS) $(C_OBJS)

.PHONY: all clean install-deps

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)
	@echo ""
	@echo "  Build successful!  Run: ./hexpher <go_binary> [0|1]"
	@echo ""

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install-deps:
	sudo apt-get install -y libboost-all-dev libcapstone-dev build-essential

clean:
	rm -f $(OBJS) $(TARGET)
