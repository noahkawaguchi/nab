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

- Captures packets live from network interfaces
- Filters for TCP, UDP, ICMP, or IGMP
- Filters by source/destination IP or port
- Identifies HTTP, HTTPS, DNS, and SSH
- Saves captures as PCAP files for analysis in Wireshark, `tcpdump`, or similar
- Shuts down gracefully with a statistics summary on Ctrl+C

## Example Usage

```bash
# Capture all traffic
./nab

# Capture only TCP traffic
./nab --protocol tcp

# Capture only DNS traffic
./nab --port 53

# Capture traffic to/from a specific host
./nab --host 192.168.1.100

# Capture HTTPS traffic and save to file
./nab --port 443 -o https_traffic.pcap
```

### Sample Output

<details>
<summary><i>Sample output (click to expand)</i></summary>
<br />

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

</details>

## Building

### Prerequisites

- `sudo` privileges or equivalent for capturing network packets (on Linux, specifically CAP_NET_RAW and CAP_NET_ADMIN)
- For [Nix](https://github.com/NixOS/nix) users, the toolchain is included as a flake.
- Otherwise, the following toolchain must be installed:
  - C++23 compiler such as GCC 14+ or Clang 18+ (tested with GCC 15 and Clang 21 in CI)
  - CMake 3.25+
  - Conan 2.x
  - The command runner [Just](https://github.com/casey/just)
  - `clang-tidy` and `clang-format` (only if linting/formatting)
  - [Termshark](https://github.com/gcla/termshark) or [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) (only if inspecting PCAP files)

### Steps

#### Development tasks

```bash
just test            # Run tests with Catch2
just lint            # Lint with Clang-Tidy
just fmt-check       # Check formatting with Clang-Format
just inspect <pcap>  # Read the PCAP file <pcap> with Termshark or TShark
```

#### Running the binary

For Linux, there is a dedicated `caps` recipe to grant the binary granular capabilities and avoid running it as root.

```bash
sudo just caps
just run
# Or to pass args: just run [args]
```

On non-Linux, it may be necessary to run the binary with elevated privileges.

```bash
sudo just run
# Or to pass args: sudo just run [args]
```

You can also inspect the [`justfile`](justfile) and run any recipe manually.

With the binary running, create some network activity (e.g. `curl example.com`) to see the traffic captured.

## Technical Highlights

- Modern C++23 features and idioms such as `std::optional`, `std::ranges`, `std::print`, brace initialization, trailing return types, and const correctness
- Manual parsing of Ethernet and IPv4 headers from raw bytes
- Memory management with `std::span` and `std::string_view` for zero-copy buffer access and smart pointers for RAII
- Thread-safe packet handling with atomics and condition variables
- Comprehensive test suite with Catch2 covering edge cases (truncated packets, invalid data)
- Conan package management, CMake build system, and `clang-tidy` static analysis
- Tests, linting, formatting checks, and spell checks in CI that must all pass before a branch is merged into main
