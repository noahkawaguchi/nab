#include <atomic>
#include <csignal>
#include <format>
#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <thread>

std::atomic<bool> stop_capture{false};
std::atomic<int> packet_count{0};

void signal_handler(int /*signal*/) {
  std::cout << "\nStopping capture...\n";
  stop_capture = true;
}

void on_packet(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice * /*unused*/, void * /*unused*/) {
  const uint8_t *data{raw_packet->getRawData()};
  const int len{raw_packet->getRawDataLen()};

  packet_count++;
  std::cout << "\n--- Packet #" << packet_count << " (" << len << " bytes) ---\n";

  if (len < 14) {
    std::cout << "  Too short for Ethernet\n";
    return;
  }

  // Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype
  std::cout << std::format("  Dst MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", data[0],
                           data[1], data[2], data[3], data[4], data[5]);
  std::cout << std::format("  Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", data[6],
                           data[7], data[8], data[9], data[10], data[11]);

  // Ethertype is big-endian
  const auto ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);
  std::cout << std::format("  EtherType: 0x{:04x}", ethertype);

  switch (ethertype) {
  case 0x0800: std::cout << " (IPv4)"; break;
  case 0x0806: std::cout << " (ARP)"; break;
  case 0x86DD: std::cout << " (IPv6)"; break;
  default: std::cout << " (unknown)"; break;
  }
  std::cout << '\n';

  // Parse IPv4 if present
  if (ethertype == 0x0800) {
    // IPv4 header starts after Ethernet header (14 bytes)
    if (len < 14 + 20) {
      std::cout << "  Too short for IPv4 header\n";
      return;
    }

    const uint8_t *ip_header{data + 14};

    // Byte 0: version (top 4 bits) and header length (bottom 4 bits)
    const auto version = static_cast<uint8_t>((ip_header[0] >> 4) & 0x0F);
    const auto ihl = static_cast<uint8_t>(ip_header[0] & 0x0F); // Header length in 32-bit words

    // Byte 9: protocol
    const uint8_t protocol{ip_header[9]};

    // Bytes 12-15: source IP (4 bytes)
    const uint8_t *src_ip{&ip_header[12]};

    // Bytes 16-19: destination IP (4 bytes)
    const uint8_t *dst_ip{&ip_header[16]};

    std::cout << std::format("  IPv4: version={}, header_len={} bytes\n", version, ihl * 4);
    std::cout << std::format("  Src IP: {}.{}.{}.{}\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    std::cout << std::format("  Dst IP: {}.{}.{}.{}\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
    std::cout << std::format("  Protocol: {}", protocol);

    switch (protocol) {
    case 1: std::cout << " (ICMP)"; break;
    case 6: std::cout << " (TCP)"; break;
    case 17: std::cout << " (UDP)"; break;
    default: std::cout << " (other)"; break;
    }
    std::cout << '\n';

    // Parse TCP/UDP if present
    if (protocol == 6 || protocol == 17) {
      // Transport layer header starts after IP header
      const int ip_header_len{ihl * 4};
      const int transport_offset{14 + ip_header_len};

      // TCP needs at least 20 bytes, UDP needs at least 8 bytes
      const int min_transport_len{(protocol == 6) ? 20 : 8};

      if (len < transport_offset + min_transport_len) {
        std::cout << "  Too short for TCP/UDP header\n";
        return;
      }

      const uint8_t *transport_header{data + transport_offset};

      // Both TCP and UDP have ports in the same location:
      // Bytes 0-1: source port (big-endian)
      // Bytes 2-3: destination port (big-endian)
      const auto src_port = static_cast<uint16_t>((transport_header[0] << 8) | transport_header[1]);
      const auto dst_port = static_cast<uint16_t>((transport_header[2] << 8) | transport_header[3]);

      // Show well-known port names
      std::cout << std::format("  Src Port: {}", src_port);
      switch (src_port) {
      case 80: std::cout << " (HTTP)"; break;
      case 443: std::cout << " (HTTPS)"; break;
      case 53: std::cout << " (DNS)"; break;
      case 22: std::cout << " (SSH)"; break;
      }
      std::cout << '\n';

      std::cout << std::format("  Dst Port: {}", dst_port);
      switch (dst_port) {
      case 80: std::cout << " (HTTP)"; break;
      case 443: std::cout << " (HTTPS)"; break;
      case 53: std::cout << " (DNS)"; break;
      case 22: std::cout << " (SSH)"; break;
      }
      std::cout << '\n';
    }
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

  std::cout << "\nTotal packets captured: " << packet_count << '\n';

  return 0;
}

auto main() -> int { return capture_packet(); }
