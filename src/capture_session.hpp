#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

#include "packet_filter.hpp"

namespace nab {

/// Manages a packet capture session.
class CaptureSession {
public:
  /// Configures capture session with optional filter and output file name.
  CaptureSession(PacketFilter filter, std::string output_file_name)
      : filter_(std::move(filter)), output_file_name_(std::move(output_file_name)){};

  /// Runs the capture session, returning 0 on success and 1 on error.
  auto run() -> int;

  /// Stops the capture session (called by signal handler).
  void stop();

private:
  /// Static callback required by pcapplusplus API.
  static void packet_callback(const pcpp::RawPacket *raw_packet, const pcpp::PcapLiveDevice *device,
                              void *cookie);

  /// Instance method that handles the packet.
  void handle_packet(const pcpp::RawPacket *raw_packet);

  /// Whether the session should stop (set by signal handler).
  std::atomic<bool> stop_capture_{false};
  /// The number of packets processed in the session.
  std::atomic<int> packet_count_{0};
  /// The number of SSH packets processed in the session.
  std::atomic<int> ssh_packet_count_{0};
  /// The number of packets filtered out in the session.
  std::atomic<int> filtered_packet_count_{0};

  /// The mutex used along with a condition variable to coordinate shutdown.
  std::mutex stop_mutex_;
  /// The condition variable used along with a mutex to coordinate shutdown.
  std::condition_variable stop_cv_;

  /// The filter to apply in the session.
  PacketFilter filter_;
  /// The name of the file to write data to in pcap format (empty for no output file).
  std::string output_file_name_;
  /// The writer for writing data to a pcap file.
  std::unique_ptr<pcpp::PcapFileWriterDevice> writer_;
};

} // namespace nab
