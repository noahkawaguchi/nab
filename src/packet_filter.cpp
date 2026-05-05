#include "packet_filter.hpp"

#include <format>

#include "protocol_types.hpp"

namespace {

/// Returns `true` if @p opt is `nullopt` or has a value that is equal to @p rhs.
/// Returns `false` if  @p opt has a value and that value is not equal to @p rhs.
template <typename T> auto nullopt_or_eq(const std::optional<T> &opt, const T &rhs) -> bool {
  return !opt.has_value() || *opt == rhs;
}

} // namespace

namespace nab {

auto PacketFilter::matches(const ParsedPacket &packet) const -> bool {
  // Check protocol filter
  return nullopt_or_eq(protocol_, packet.protocol)
         // Check port filter (matches source OR destination)
         && (!port_.has_value() || nullopt_or_eq(packet.src_port, *port_)
             || nullopt_or_eq(packet.dst_port, *port_))
         // Check host filter (matches source OR destination)
         && (!host_.has_value() || nullopt_or_eq(packet.src_ip, *host_)
             || nullopt_or_eq(packet.dst_ip, *host_));
}

auto PacketFilter::description() const -> std::string {
  return std::format(
      "Active filter(s):{}{}{}",
      protocol_.has_value() ? std::format(" protocol={}", protocol_to_string(*protocol_)) : "",
      port_.has_value() ? std::format(" port={}", *port_) : "",
      host_.has_value() ? std::format(" host={}", *host_) : "");
}

} // namespace nab
