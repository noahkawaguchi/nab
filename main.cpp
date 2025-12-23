#include <atomic>
#include <csignal>
#include <format>
#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <thread>

std::atomic<bool> stop_capture{false};
std::atomic<int> packet_count{0};
std::atomic<int> ssh_packet_count{0};

void signal_handler(int /*signal*/) {
  std::cout << "\nStopping capture...\n";
  stop_capture = true;
}

void on_packet(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice * /*unused*/, void * /*unused*/) {
  const uint8_t *data{raw_packet->getRawData()};
  const int len{raw_packet->getRawDataLen()};

  const int count{++packet_count};

  // Packet length must be enough for valid Ethernet header
  if (len < 14) {
    std::cout << std::format("#{}: Invalid ({}B)\n", count, len);
    return;
  }

  // Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype (14 total)
  // Ethertype is big-endian (2 bytes at offset 12-13)
  const auto ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);

  // Parse IPv4 packets to check for SSH before printing (prevents feedback loop over SSH)
  if (ethertype == 0x0800) {
    // IPv4 header starts at byte 14, after Ethernet header
    if (len < 14 + 20) {
      std::cout << std::format("#{}: IPv4 (truncated, {}B)\n", count, len);
      return;
    }

    const uint8_t *ip_header{data + 14};

    // Byte 0: version (top 4 bits) and header length (bottom 4 bits)
    const auto ihl = static_cast<uint8_t>(ip_header[0] & 0x0F); // Header length in 32-bit words

    // Byte 9: protocol (6=TCP, 17=UDP, 1=ICMP, etc.)
    const uint8_t protocol{ip_header[9]};

    // Bytes 12-15: source IP address
    const uint8_t *src_ip{&ip_header[12]};

    // Bytes 16-19: destination IP address
    const uint8_t *dst_ip{&ip_header[16]};

    // Parse TCP/UDP if present
    if (protocol == 6 || protocol == 17) {
      // Transport layer header starts after IP header
      const int ip_header_len{ihl * 4};
      const int transport_offset{14 + ip_header_len};

      // TCP needs at least 20 bytes, UDP needs at least 8 bytes
      const int min_transport_len{(protocol == 6) ? 20 : 8};

      if (len < transport_offset + min_transport_len) {
        std::cout << std::format("#{}: {}.{}.{}.{} -> {}.{}.{}.{} {} (truncated, {}B)\n", count,
                                 src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1],
                                 dst_ip[2], dst_ip[3], protocol == 6 ? "TCP" : "UDP", len);
        return;
      }

      const uint8_t *transport_header{data + transport_offset};

      // Both TCP and UDP have ports in the same location:
      // Bytes 0-1: source port (big-endian)
      // Bytes 2-3: destination port (big-endian)
      const auto src_port = static_cast<uint16_t>((transport_header[0] << 8) | transport_header[1]);
      const auto dst_port = static_cast<uint16_t>((transport_header[2] << 8) | transport_header[3]);

      // Filter SSH silently to prevent feedback loop. Any terminal output over SSH generates
      // packets, which would be captured and printed, creating exponential growth.
      if (src_port == 22 || dst_port == 22) {
        ssh_packet_count++;
        return;
      }

      // Not SSH, safe to print
      std::cout << std::format("#{}: {}.{}.{}.{}:{} -> {}.{}.{}.{}:{} ", count, src_ip[0],
                               src_ip[1], src_ip[2], src_ip[3], src_port, dst_ip[0], dst_ip[1],
                               dst_ip[2], dst_ip[3], dst_port);

      // Protocol name
      std::cout << (protocol == 6 ? "TCP" : "UDP");

      // Add service name if it's a well-known port
      auto get_service = [](uint16_t port) -> const char * {
        switch (port) {
        case 80: return "/HTTP";
        case 443: return "/HTTPS";
        case 53: return "/DNS";
        case 22: return "/SSH";
        default: return "";
        }
      };

      const char *src_service = get_service(src_port);
      const char *dst_service = get_service(dst_port);

      // Show service name (prefer destination port for typical client->server traffic)
      if (dst_service[0] != '\0') {
        std::cout << dst_service;
      } else if (src_service[0] != '\0') {
        std::cout << src_service;
      }

      std::cout << std::format(" {}B\n", len);
    } else {
      // Non-TCP/UDP protocols (ICMP, etc.)
      std::cout << std::format("#{}: {}.{}.{}.{} -> {}.{}.{}.{} ", count, src_ip[0], src_ip[1],
                               src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

      switch (protocol) {
      case 1: std::cout << "ICMP"; break;
      case 2: std::cout << "IGMP"; break;
      default: std::cout << std::format("Proto-{}", protocol); break;
      }

      std::cout << std::format(" {}B\n", len);
    }
  } else {
    // Non-IPv4 packets (ARP, IPv6, etc.)
    std::cout << std::format("#{}: ", count);

    switch (ethertype) {
    case 0x0806: std::cout << "ARP"; break;
    case 0x86DD: std::cout << "IPv6"; break;
    default: std::cout << std::format("EtherType-0x{:04x}", ethertype); break;
    }

    std::cout << std::format(" {}B\n", len);
  }
}

auto capture_packet() -> int {
  // Set up signal handler for Ctrl+C
  std::signal(SIGINT, signal_handler);

  // Get the first non-loopback device
  pcpp::PcapLiveDevice *device{nullptr};

  for (auto *dev : pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList()) {
    if (dev->getName() != "lo") {
      device = dev;
      break;
    }
  }

  if (device == nullptr) {
    std::cerr << "No suitable network interface found\n";
    return 1;
  }

  std::cout << "Using interface: " << device->getName() << '\n';

  if (!device->open()) {
    std::cerr << "Failed to open device\n";
    return 1;
  }

  std::cout << "Capturing packets... (Press Ctrl+C to stop)\n";
  device->startCapture(on_packet, nullptr);

  // Keep capturing until Ctrl+C
  while (!stop_capture) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

  device->stopCapture();
  device->close();

  const int total = packet_count.load();
  const int ssh = ssh_packet_count.load();
  const int non_ssh = total - ssh;

  std::cout << "\nTotal packets captured: " << total << '\n';
  std::cout << "  SSH packets (filtered): " << ssh << '\n';
  std::cout << "  Non-SSH packets (displayed): " << non_ssh << '\n';

  return 0;
}

auto main() -> int { return capture_packet(); }
