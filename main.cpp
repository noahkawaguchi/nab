#include <csignal>
#include <iostream>
#include <string>

#include "capture_session.hpp"
#include "packet_filter.hpp"

// Global session pointer for signal handler
nab::CaptureSession *g_session{nullptr};

void signal_handler(int /*signal*/) {
  if (g_session != nullptr) { g_session->stop(); }
}

auto main(int argc, char *argv[]) -> int {
  std::string output_file_name{};
  nab::PacketFilter filter{};

  // Parse command-line arguments
  for (int i = 1; i < argc; i++) {
    std::string arg{argv[i]};

    if (arg == "-o" && i + 1 < argc) {
      output_file_name = argv[i + 1];
      i++; // Skip next argument
    }

    else if (arg == "--protocol" && i + 1 < argc) {
      std::string protocol{argv[i + 1]};

      // Validate protocol
      if (protocol != "tcp" && protocol != "udp" && protocol != "icmp") {
        std::cerr << "Invalid protocol: " << protocol << '\n'
                  << "Valid protocols: tcp, udp, icmp\n";
        return 1;
      }

      filter.set_protocol(protocol);
      i++; // Skip next argument
    }

    else if (arg == "--port" && i + 1 < argc) {
      try {
        const auto port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
        filter.set_port(port);
      } catch (...) {
        std::cerr << "Invalid port number: " << argv[i + 1] << '\n';
        return 1;
      }

      i++; // Skip next argument
    }

    else if (arg == "--host" && i + 1 < argc) {
      filter.set_host(argv[i + 1]);
      i++; // Skip next argument
    }

    else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: " << argv[0] << " [options]\n"
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

  // Set up signal handler for Ctrl+C
  nab::CaptureSession session{};
  g_session = &session;
  std::signal(SIGINT, signal_handler);

  // Run capture session
  return session.run(filter, output_file_name);
}
