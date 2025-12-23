#include <atomic>
#include <format>
#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <thread>

std::atomic<bool> packet_received{false};

/** Lists available network interfaces. */
void list_devices() {
  const auto &devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

  std::cout << "Available interfaces:\n";

  for (const auto *device : devices) {
    std::cout << "  " << device->getName();
    if (!device->getDesc().empty()) { std::cout << " (" << device->getDesc() << ")"; }
    std::cout << '\n';
  }
}

void on_packet(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice * /*unused*/, void * /*unused*/) {
  const uint8_t *data = raw_packet->getRawData();
  const int len = raw_packet->getRawDataLen();

  std::cout << "Captured packet: " << len << " bytes\n";

  if (len < 14) {
    std::cout << "  Too short for Ethernet\n";
    packet_received = true;
    return;
  }

  // Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype
  std::cout << std::format("  Dst MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", data[0],
                           data[1], data[2], data[3], data[4], data[5]);
  std::cout << std::format("  Src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n", data[6],
                           data[7], data[8], data[9], data[10], data[11]);

  // Ethertype is big-endian
  const uint16_t ethertype = (data[12] << 8) | data[13];
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
      packet_received = true;
      return;
    }

    const uint8_t *ip_header = data + 14;

    // Byte 0: version (top 4 bits) and header length (bottom 4 bits)
    const uint8_t version = (ip_header[0] >> 4) & 0x0F;
    const uint8_t ihl = ip_header[0] & 0x0F; // Header length in 32-bit words

    // Byte 9: protocol
    const uint8_t protocol = ip_header[9];

    // Bytes 12-15: source IP (4 bytes)
    const uint8_t *src_ip = &ip_header[12];

    // Bytes 16-19: destination IP (4 bytes)
    const uint8_t *dst_ip = &ip_header[16];

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
  }

  packet_received = true;
}

auto capture_packet() -> int {
  // Get the first non-loopback device
  pcpp::PcapLiveDevice *device = nullptr;

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

  std::cout << "Waiting for a packet...\n";

  device->startCapture(on_packet, nullptr);

  while (!packet_received) {
    // Sleep a bit to avoid burning CPU
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  device->stopCapture();
  device->close();

  return 0;
}

auto main() -> int {
  list_devices();
  return capture_packet();
}
