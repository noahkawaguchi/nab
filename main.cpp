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
