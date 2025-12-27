#include <charconv>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <variant>

#include "capture_session.hpp"
#include "packet_filter.hpp"
#include "protocol_types.hpp"

namespace {

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)

/// Global pointer to the capture session for the signal handler.
nab::CaptureSession *g_session{nullptr};
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

void signal_handler(int /*signal*/) {
  if (g_session != nullptr) { g_session->stop(); }
}

// NOLINTBEGIN(readability-function-cognitive-complexity)

/// Parses command line arguments to configure a `CaptureSession`, or returns a status code to exit
/// early without executing the session.
auto parse_args(std::span<char *> args) -> std::variant<std::unique_ptr<nab::CaptureSession>, int> {
  std::string output_file_name{};
  std::optional<nab::Protocol> protocol{};
  std::optional<std::uint16_t> port{};
  std::optional<std::string> host{};

  for (std::size_t i{1}, args_len{args.size()}; i < args_len; i++) {
    const std::string_view arg{args[i]};

    if (arg == "-o") {
      if (i + 1 >= args_len) {
        std::println(stderr, "-o requires a value");
        return 1;
      }
      output_file_name = args[++i];
    }

    else if (arg == "--protocol") {
      if (i + 1 >= args_len) {
        std::println(stderr, "--protocol requires a value");
        return 1;
      }

      // Attempt to parse the following arg as one of the valid protocols
      const std::string_view protocol_arg{args[++i]};
      protocol.emplace(nab::parse_protocol(protocol_arg));

      if (protocol == nab::Protocol::Unknown) {
        std::println(stderr, "Invalid protocol: {}\nValid protocols: tcp, udp, icmp, igmp",
                     protocol_arg);
        return 0;
      }
    }

    else if (arg == "--port") {
      if (i + 1 >= args_len) {
        std::println(stderr, "--port requires a value");
        return 1;
      }

      // Attempt to parse the following arg as a port number
      const std::string_view port_arg{args[++i]};
      std::uint16_t port_num{};

      const auto [_, ec] =
          std::from_chars(port_arg.data(), port_arg.data() + port_arg.size(), port_num);

      if (ec != std::errc{}) {
        std::println(stderr, "Invalid port number: {}", port_arg);
        return 1;
      }

      port = port_num;
    }

    else if (arg == "--host") {
      if (i + 1 >= args_len) {
        std::println(stderr, "--host requires a value");
        return 1;
      }
      host.emplace(args[++i]);
    }

    else if (arg == "--help" || arg == "-h") {
      std::println("Usage: {} [options]", args[0]);
      std::print("Options:\n"
                 "  -o <file>          Write captured packets to pcap file\n"
                 "  --protocol <proto> Filter by protocol (tcp, udp, icmp)\n"
                 "  --port <num>       Filter by port (source or destination)\n"
                 "  --host <ip>        Filter by IP address (source or destination)\n"
                 "  -h, --help         Show this help message\n");
      return 0;
    }

    else {
      std::println(stderr, "Unknown argument: {}\nUse -h or --help for usage information", arg);
      return 1;
    }
  }

  return std::make_unique<nab::CaptureSession>(nab::PacketFilter{protocol, port, host},
                                               output_file_name);
}
// NOLINTEND(readability-function-cognitive-complexity)

} // namespace

auto main(int argc, char *argv[]) -> int {
  // Parse command line args into session config or exit
  const auto arg_result = parse_args(std::span{argv, static_cast<std::size_t>(argc)});
  if (const int *status_code = std::get_if<int>(&arg_result)) { return *status_code; }
  const auto &session = std::get<std::unique_ptr<nab::CaptureSession>>(arg_result);

  // Set up signal handler for Ctrl+C
  g_session = session.get();
  if (std::signal(SIGINT, signal_handler) == SIG_ERR) {
    std::println(stderr, "Failed to install signal handler");
    return 1;
  }

  // Run the capture session
  return session->run();
}
