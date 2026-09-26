#!/bin/bash

set -e

IFACE="${1:-wlan0}"

clang -target bpf -g -O2 -c ./src/kernel/packet_filter.bpf.c -o packet_filter.o
g++ -g -O2 -std=c++23 ./src/user/*.cpp -o loader -lbpf

./loader "$IFACE" ./packet_filter.o
