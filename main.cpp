#include <iostream>
#include <pcapplusplus/PcapLiveDeviceList.h>

int main() {
  // Just list available network interfaces
  const auto &devices = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

  std::cout << "Available interfaces:\n";
  for (const auto *device : devices) {
    std::cout << "  " << device->getName();
    if (!device->getDesc().empty()) { std::cout << " (" << device->getDesc() << ")"; }
    std::cout << "\n";
  }
}
