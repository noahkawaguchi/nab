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
Active filter(s): port=443
Using interface: enp0s1

Capturing packets... (Press Ctrl+C to stop)

#22: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 74B
#23: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#24: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#25: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 1514B
#26: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 165B
#27: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#28: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#29: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 1282B
#30: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 1494B
#31: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#32: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#33: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 1525B
#34: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#35: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 134B
#36: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 177B
#37: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#38: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#39: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 607B
#40: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 85B
#41: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#42: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 212B
#43: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 644B
#44: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#45: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 102B
#46: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#47: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 78B
#48: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
#49: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#50: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#51: 104.18.27.120:443 -> 10.0.2.15:45386 TCP/HTTPS 60B
#52: 10.0.2.15:45386 -> 104.18.27.120:443 TCP/HTTPS 54B
^C

Total packets captured: 52
  Filtered out: 21
  Displayed: 31

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
