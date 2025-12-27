# Nab

A lightweight, modern C++23 network packet capture and analysis tool.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Example Usage](#example-usage)
4. [Building](#building)
5. [Technical Highlights](#technical-highlights)

## Overview

Built as a learning project to gain experience with networking concepts and modern C++ systems programming practices, `nab` captures live network traffic and displays packet information in real time with flexible filtering capabilities.

## Features

- **Live packet capture** - Captures packets from network interfaces
- **Protocol filtering** - Filters for TCP, UDP, ICMP, or IGMP
- **Port and host filtering** - Filters by source/destination IP or port
- **Service recognition** - Identifies HTTP, HTTPS, DNS, and SSH
- **PCAP file export** - Saves captures for analysis in Wireshark, `tcpdump`, or similar
- **Graceful shutdown** - Exits cleanly with a statistics summary on Ctrl+C

## Example Usage

```bash
# Capture all traffic
sudo ./nab

# Capture only TCP traffic
sudo ./nab --protocol tcp

# Monitor DNS traffic
sudo ./nab --port 53

# Monitor traffic to/from a specific host
sudo ./nab --host 192.168.1.100

# Capture HTTPS traffic and save to file
sudo ./nab --port 443 -o https_traffic.pcap
```

### Sample output:

```
Writing packets to: example.pcap
Active filter(s): protocol=TCP
Using interface: enp0s1

Capturing packets... (Press Ctrl+C to stop)

#310: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 74B
#334: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#335: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
#338: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 1514B
#339: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 165B
#340: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#341: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#350: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 2590B
#351: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
#352: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 2596B
#353: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
#356: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 134B
#357: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#358: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 177B
#359: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#373: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 598B
#374: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 85B
#379: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#382: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 85B
#387: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 788B
#388: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
#390: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 102B
#392: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#394: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 78B
#396: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#402: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
#403: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#419: 104.18.26.120:443 -> 10.0.2.15:42178 TCP/HTTPS 60B
#420: 10.0.2.15:42178 -> 104.18.26.120:443 TCP/HTTPS 54B
^C

Total packets captured: 598
  Filtered out: 10
  SSH packets (excluded from display): 559
  Displayed: 29
Packets written to: example.pcap
```

## Building

### Prerequisites

- Modern C++23 compiler such as GCC 14+ or Clang 18+ (tested with GCC 14 and 15)
- CMake 3.25+
- Conan 2.x
- [just](https://github.com/casey/just) command runner (optional)
- System packet capture library such as `libpcap`
- `sudo` privileges to capture network packets

### Build Steps

Using `just`:

```bash
just rebuild
just test
sudo just run
# Or to pass args: sudo just run [args]
```

Or running the commands manually:

```bash
# Install dependencies and configure
conan install . --output-folder=build --build=missing
cmake -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Run the program
sudo ./build/nab
```

## Technical Highlights

- **Modern C++23** - Latest features and idioms such as `std::optional`, `std::ranges`, `std::print`, brace initialization, trailing return types, and const-correctness
- **Low-level networking** - Manual parsing of Ethernet and IPv4 headers from raw bytes
- **Memory safety** - `std::span` and `std::string_view` for zero-copy buffer access, smart pointers for RAII
- **Concurrency** - Thread-safe packet handling with atomics and condition variables
- **Testing** - Comprehensive test suite with Catch2 covering edge cases (truncated packets, invalid data)
- **Modern tooling** - Conan package management, CMake build system, `clang-tidy` static analysis
