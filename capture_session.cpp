#include "capture_session.hpp"

#include <chrono>
#include <format>
#include <iostream>
#include <thread>

#include <pcapplusplus/PcapLiveDeviceList.h>

#include "packet_parser.hpp"

namespace nab {

auto CaptureSession::run(const PacketFilter &filter, const std::string &output_file_name) -> int {
  filter_ = filter;

  // Set up pcap file writer if output file is specified
  if (!output_file_name.empty()) {
    writer_ =
        std::make_unique<pcpp::PcapFileWriterDevice>(output_file_name, pcpp::LINKTYPE_ETHERNET);

    if (!writer_->open()) {
      std::cerr << "Failed to open output file: " << output_file_name << '\n';
      return 1;
    }

    std::cout << "Writing packets to: " << output_file_name << '\n';
  }

  // Display active filters
  if (filter_.has_any_filter()) { std::cout << filter_.description() << '\n'; }

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

  // Pass "this" pointer to static callback via cookie
  device->startCapture(packet_callback, this);

  // Keep capturing until stop() is called
  while (!stop_capture_) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

  device->stopCapture();
  device->close();

  // Close pcap writer if it was opened
  if (writer_) { writer_->close(); }

  // Print statistics
  const int total{packet_count_.load()};
  const int ssh{ssh_packet_count_.load()};
  const int filtered{filtered_packet_count_.load()};
  const int displayed{total - ssh - filtered};

  std::cout << "\nTotal packets captured: " << total << '\n'
            << "  Filtered out: " << filtered << '\n'
            << "  SSH packets (excluded from display): " << ssh << '\n'
            << "  Displayed: " << displayed << '\n';

  if (!output_file_name.empty()) {
    std::cout << "Packets written to: " << output_file_name << '\n';
  }

  return 0;
}

void CaptureSession::stop() { stop_capture_ = true; }

void CaptureSession::packet_callback(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice * /*device*/,
                                     void *cookie) {
  // Cast cookie back to CaptureSession instance
  auto *session = static_cast<CaptureSession *>(cookie);
  session->handle_packet(raw_packet);
}

void CaptureSession::handle_packet(pcpp::RawPacket *raw_packet) {
  const uint8_t *data{raw_packet->getRawData()};
  const int len{raw_packet->getRawDataLen()};
  const int count{++packet_count_};

  // Parse Ethernet header
  auto ethertype = parse_ethernet_header(data, len);
  if (!ethertype.has_value()) {
    std::cout << std::format("#{}: Invalid ({}B)\n", count, len);
    return;
  }

  // Handle IPv4 packets
  if (ethertype.value() == 0x0800) {
    ParsedPacket parsed;
    if (!parse_ipv4_packet(data, len, parsed)) {
      std::cout << std::format("#{}: IPv4 (truncated, {}B)\n", count, len);
      return;
    }

    // Apply user filters
    if (filter_.has_any_filter() && !filter_.matches(parsed)) {
      filtered_packet_count_++;
      return;
    }

    // Write to pcap before SSH filter (we want complete captures in the file)
    if (writer_) { writer_->writePacket(*raw_packet); }

    // Filter SSH from display to prevent feedback loop
    if (is_ssh_packet(parsed)) {
      ssh_packet_count_++;
      return;
    }

    // Not filtered, safe to print
    print_packet(raw_packet, parsed, count);
  } else {
    // Non-IPv4 packets (ARP, IPv6, etc.)

    // If any filter is set, exclude non-IPv4 packets
    if (filter_.has_any_filter()) {
      filtered_packet_count_++;
      return;
    }

    // Write packet to file if writer is provided
    if (writer_) { writer_->writePacket(*raw_packet); }

    std::cout << std::format("#{}: ", count);

    switch (ethertype.value()) {
    case 0x0806: std::cout << "ARP"; break;
    case 0x86DD: std::cout << "IPv6"; break;
    default: std::cout << std::format("EtherType-0x{:04x}", ethertype.value()); break;
    }

    std::cout << std::format(" {}B\n", len);
  }
}

void CaptureSession::print_packet(const pcpp::RawPacket *raw_packet, const ParsedPacket &parsed,
                                  int count) {
  const int len{raw_packet->getRawDataLen()};

  // Print based on protocol
  if (parsed.protocol == "tcp" || parsed.protocol == "udp") {
    std::cout << std::format("#{}: {}:{} -> {}:{} ", count, parsed.src_ip.value(),
                             parsed.src_port.value(), parsed.dst_ip.value(),
                             parsed.dst_port.value());

    // Protocol name
    std::cout << (parsed.protocol == "tcp" ? "TCP" : "UDP");

    // Add service name if it's a well-known port
    const char *src_service = get_service_name(parsed.src_port.value());
    const char *dst_service = get_service_name(parsed.dst_port.value());

    // Show service name (prefer destination port for typical client->server traffic)
    if (dst_service[0] != '\0') {
      std::cout << dst_service;
    } else if (src_service[0] != '\0') {
      std::cout << src_service;
    }

    std::cout << std::format(" {}B\n", len);
  } else {
    // Non-TCP/UDP protocols (ICMP, etc.)
    std::cout << std::format("#{}: {} -> {} ", count, parsed.src_ip.value(), parsed.dst_ip.value());

    if (parsed.protocol == "icmp") {
      std::cout << "ICMP";
    } else if (parsed.protocol == "igmp") {
      std::cout << "IGMP";
    } else {
      std::cout << parsed.protocol;
    }

    std::cout << std::format(" {}B\n", len);
  }
}

} // namespace nab
