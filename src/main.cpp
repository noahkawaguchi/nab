#include <csignal>
#include <cstddef>
#include <iostream>
#include <optional>
#include <span>
#include <string>

#include "capture_session.hpp"
#include "packet_filter.hpp"
#include "protocol_types.hpp"

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)

/// Global pointer to the capture session for the signal handler.
nab::CaptureSession *g_session{nullptr};
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

void signal_handler(int /*signal*/) {
  if (g_session != nullptr) { g_session->stop(); }
}

auto main(int argc, char *argv[]) -> int {
  const std::span args{argv, static_cast<std::size_t>(argc)};
  std::string output_file_name{};
  std::optional<nab::Protocol> protocol{};
  std::optional<std::uint16_t> port{};
  std::optional<std::string> host{};

  // Parse command-line arguments
  for (int i = 1; i < argc; i++) {
    const std::string arg{args[i]};

    if (arg == "-o") {
      if (i + 1 >= argc) {
        std::cerr << "-o requires a value\n";
        return 1;
      }

      output_file_name = args[i + 1];
      i++; // Skip next argument
    }

    else if (arg == "--protocol") {
      if (i + 1 >= argc) {
        std::cerr << "--protocol requires a value\n";
        return 1;
      }

      std::string_view protocol_arg{args[i + 1]};
      protocol.emplace(nab::parse_protocol(protocol_arg));

      if (protocol == nab::Protocol::Unknown) {
        std::cerr << "Invalid protocol: " << protocol_arg << '\n'
                  << "Valid protocols: tcp, udp, icmp, igmp\n";
        return 1;
      }

      i++; // Skip next argument
    }

    else if (arg == "--port") {
      if (i + 1 >= argc) {
        std::cerr << "--port requires a value\n";
        return 1;
      }

      try {
        port = static_cast<std::uint16_t>(std::stoi(args[i + 1]));
      } catch (...) {
        std::cerr << "Invalid port number: " << args[i + 1] << '\n';
        return 1;
      }

      i++; // Skip next argument
    }

    else if (arg == "--host") {
      if (i + 1 >= argc) {
        std::cerr << "--host requires a value\n";
        return 1;
      }

      host.emplace(args[i + 1]);
      i++; // Skip next argument
    }

    else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: " << args[0] << " [options]\n"
                << "Options:\n"
                << "  -o <file>          Write captured packets to pcap file\n"
                << "  --protocol <proto> Filter by protocol (tcp, udp, icmp)\n"
                << "  --port <num>       Filter by port (source or destination)\n"
                << "  --host <ip>        Filter by IP address (source or destination)\n"
                << "  -h, --help         Show this help message\n";
      return 0;
    }

    else {
      std::cerr << "Unknown argument: " << arg << '\n'
                << "Use -h or --help for usage information\n";
      return 1;
    }
  }

  const nab::PacketFilter filter{protocol, port, host};
  nab::CaptureSession session{filter, output_file_name};

  // Set up signal handler for Ctrl+C
  g_session = &session;
  if (std::signal(SIGINT, signal_handler) == SIG_ERR) {
    std::cerr << "Failed to install signal handler\n";
    return 1;
  }

  // Run capture session
  return session.run();
}
