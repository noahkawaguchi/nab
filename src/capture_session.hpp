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
  // Configure capture session with optional filter and output file
  CaptureSession(PacketFilter filter, std::string output_file_name)
      : filter_(std::move(filter)), output_file_name_(std::move(output_file_name)){};

  // Runs capture session, returning 0 on success, 1 on error
  auto run() -> int;

  // Stop the capture (called by signal handler)
  void stop();

private:
  // Static callback required by pcapplusplus API
  static void packet_callback(const pcpp::RawPacket *raw_packet, const pcpp::PcapLiveDevice *device,
                              void *cookie);

  // Instance method that handles the packet
  void handle_packet(const pcpp::RawPacket *raw_packet);

  // Print packet information to stdout
  static void print_packet(const pcpp::RawPacket *raw_packet, const ParsedPacket &parsed,
                           int count);

  // State
  std::atomic<bool> stop_capture_{false};
  std::atomic<int> packet_count_{0};
  std::atomic<int> ssh_packet_count_{0};
  std::atomic<int> filtered_packet_count_{0};

  // Configuration
  PacketFilter filter_;
  std::string output_file_name_;
  std::unique_ptr<pcpp::PcapFileWriterDevice> writer_;
};

} // namespace nab
