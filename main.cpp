#include <atomic>
#include <format>
#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/RawPacket.h>
#include <thread>

/** Lists available network interfaces */
void list_devices() {
  const auto &devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

  std::cout << "Available interfaces:\n";

  for (const auto *device : devices) {
    std::cout << "  " << device->getName();
    if (!device->getDesc().empty()) { std::cout << " (" << device->getDesc() << ")"; }
    std::cout << '\n';
  }
}

std::atomic<bool> packet_received{false};

void on_packet(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice * /*unused*/, void * /*unused*/) {
  std::cout << "Captured packet:\n";
  std::cout << "  Length: " << raw_packet->getRawDataLen() << " bytes\n";
  std::cout << "  First 20 bytes (hex): ";

  const uint8_t *data = raw_packet->getRawData();
  for (int i = 0; i < 20 && i < raw_packet->getRawDataLen(); i++) {
    std::cout << std::format("{:02x} ", data[i]);
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

  std::cout << "Using interface: " << device->getName() << "\n";

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
