#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include "packet_filter.hpp"

namespace nab {

// Manages a packet capture session
class CaptureSession {
public:
  CaptureSession() = default;

  // Run capture session with optional filter and output file
  // Returns 0 on success, 1 on error
  auto run(const PacketFilter &filter, const std::string &output_file) -> int;

  // Stop the capture (called by signal handler)
  void stop();

private:
  // Static callback required by pcapplusplus API
  static void packet_callback(pcpp::RawPacket *raw_packet, pcpp::PcapLiveDevice *device,
                              void *cookie);

  // Instance method that handles the packet
  void handle_packet(pcpp::RawPacket *raw_packet);

  // Print packet information to stdout
  void print_packet(const pcpp::RawPacket *raw_packet, const ParsedPacket &parsed, int count);

  // State
  std::atomic<bool> stop_capture_{false};
  std::atomic<int> packet_count_{0};
  std::atomic<int> ssh_packet_count_{0};
  std::atomic<int> filtered_packet_count_{0};

  // Configuration
  PacketFilter filter_;
  std::unique_ptr<pcpp::PcapFileWriterDevice> writer_;
};

} // namespace nab
