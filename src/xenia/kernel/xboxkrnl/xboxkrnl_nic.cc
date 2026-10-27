/**
 ******************************************************************************
 * Wharf: OpenPak Xbox 360 emulator, a fork of Xenia Edge                     *
 ******************************************************************************
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef XE_HAVE_SLIRP
#include <arpa/inet.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <libslirp.h>
#endif

#include "xenia/base/cvar.h"
#include "xenia/base/logging.h"
#include "xenia/cpu/processor.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"
#include "xenia/kernel/xthread.h"
#include "xenia/xbox.h"

DEFINE_string(nic_dns_hosts, "",
              "Virtual NIC: guest DNS names answered locally instead of by the\n"
              "host resolver, 'name=a.b.c.d;*.suffix=a.b.c.d'. Stand-in for the\n"
              "OpenPak redirect list.",
              "Network");

DEFINE_string(nic_tcp_port_map, "",
              "Virtual NIC (dev): guest TCP connections to the slirp host\n"
              "alias 10.0.2.2:<port> reach host 127.0.0.1:<mapped port>\n"
              "instead, '443=8443;80=8080'. Lets an unprivileged listener\n"
              "stand in for privileged ports.",
              "Network");

DEFINE_string(nic_udp_port_map, "",
              "Virtual NIC (dev): guest UDP datagrams to the slirp host alias\n"
              "10.0.2.2:<port> reach host 127.0.0.1:<mapped port> instead,\n"
              "'88=18088;3074=13074'; replies get their source port restored.\n"
              "Lets an unprivileged listener stand in for privileged ports.",
              "Network");

// The network card as the real xam.xex sees it. XAM runs its own XNet stack
// (ARP, DHCP, DNS, TCP/UDP) and talks to the kernel's NIC driver through the
// Nic* exports:
//   NicAttach(config, &handle): config = {flags, mask, context, rx callback,
//     tx-done callback, link/status callback, 0}, all guest addresses.
//   NicXmit(handle, vlan, frame, length, packet): an Ethernet frame goes out;
//     the tx-done callback(context, packet) must follow.
//   the rx callback(context, frame, length, ?, kind) takes a received frame;
//     kind 1 = unicast to us, 3 = multicast, 4 = broadcast (XAM sets flags
//     0x08000000 / 0x02000000 from them and its IP input checks them).
//   NicGetLinkState(handle): bit 0 link up, 0x8 full duplex, 0x2 gigabit,
//     0x20 wireless (XAM then asks the 802.11 options); neither = 100 Mbit.
//   NicGetOpt/NicSetOpt: 0x2733 (receive filter) and 0x2731 are the only ones
//     XAM's own stack uses; the rest of its range is the XNetGetOpt
//     pass-through and answers STATUS_NOT_IMPLEMENTED, which it handles.
//
// The cable plugs into libslirp (user-mode NAT, no root): it answers DHCP
// (guest 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3), ARP, ICMP echo, TCP/UDP
// through host sockets and DNS through the host resolver. A host thread
// ("NIC") polls slirp and runs the guest's rx and tx-done callbacks.
//
// OpenPak seam: every guest DNS query passes ResolveOverride() before it
// reaches slirp; an answer there goes straight back to the guest and the
// query never leaves the machine. That is where the Xbox Live names will be
// redirected to OpenPak (today from the nic_dns_hosts cvar).

namespace xe {
namespace kernel {
namespace xboxkrnl {

namespace {

constexpr uint32_t kLinkUp = 0x1;
constexpr uint32_t kFullDuplex = 0x8;
// A cable is plugged in at 100 Mbit full duplex.
// Bit 16: XAM's link state machine (8175F834) does nothing while it is clear.
constexpr uint32_t kLinkState = 0x10000 | kLinkUp | kFullDuplex;

constexpr uint32_t kNicHandle = 1;

constexpr uint32_t kStatusNotImplemented = 0xC0000002;
constexpr uint32_t kOptReceiveFilter = 0x2733;
constexpr uint32_t kOptTxFlow = 0x2731;

constexpr uint32_t kRxSlots = 128;
constexpr uint32_t kRxSlotSize = 2048;

struct NicState {
  std::mutex mutex;
  uint32_t context = 0;
  uint32_t rx_callback = 0;
  uint32_t link_callback = 0;
  uint32_t tx_done_callback = 0;
  bool attached = false;
  std::unordered_map<uint32_t, uint32_t> options;

#ifdef XE_HAVE_SLIRP
  Slirp* slirp = nullptr;
  std::mutex slirp_mutex;  // slirp is single-threaded
  int wake_fd = -1;
  std::atomic<bool> running{false};
  object_ref<XHostThread> thread;
  uint32_t rx_ring = 0;
  uint32_t rx_next = 0;
  std::vector<pollfd> fds;
  std::mutex queue_mutex;
  std::deque<std::vector<uint8_t>> rx_queue;  // frames for the guest
  std::deque<uint32_t> tx_done_queue;         // packets to complete
  std::atomic<bool> link_changed{false};  // tell XAM about the link once
  std::set<uint64_t> seen_udp;
  std::vector<std::pair<std::string, uint32_t>> dns_hosts;  // name, ipv4 (net)
  // nic_tcp_port_map: guest-visible port -> host port. tcp_port_back maps
  // (guest source port << 16 | host port) -> guest-visible port so replies
  // from slirp get their source port restored.
  std::map<uint16_t, uint16_t> tcp_port_map;
  std::map<uint32_t, uint16_t> tcp_port_back;
  // nic_udp_port_map: same idea for UDP. udp_port_back is keyed (guest source
  // port << 16 | host port) -> guest-visible destination port.
  std::map<uint16_t, uint16_t> udp_port_map;
  std::map<uint32_t, uint16_t> udp_port_back;
  std::mutex port_mutex;
#endif
};

NicState& nic() {
  static NicState state;
  return state;
}

#ifdef XE_HAVE_SLIRP

uint16_t Be16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
void PutBe16(uint8_t* p, uint16_t v) {
  p[0] = uint8_t(v >> 8);
  p[1] = uint8_t(v);
}

uint16_t IpChecksum(const uint8_t* p, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < length; i += 2) {
    sum += Be16(p + i);
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return uint16_t(~sum);
}

std::string FormatIp(const uint8_t* p) {
  return fmt::format("{}.{}.{}.{}", p[0], p[1], p[2], p[3]);
}

void WakeNic(NicState& n) {
  uint64_t one = 1;
  [[maybe_unused]] auto ignored = write(n.wake_fd, &one, sizeof(one));
}

void QueueRx(NicState& n, const uint8_t* frame, size_t length) {
  {
    std::lock_guard<std::mutex> lock(n.queue_mutex);
    n.rx_queue.emplace_back(frame, frame + length);
  }
  WakeNic(n);
}

// TCP checksum of the segment of the IPv4 packet at ip (header length ihl,
// total length total), pseudo header included; the checksum field is skipped.
uint16_t TcpChecksum(const uint8_t* ip, size_t ihl, size_t total) {
  const uint8_t* seg = ip + ihl;
  const size_t seg_len = total - ihl;
  uint32_t sum = 0;
  for (int i = 12; i < 20; i += 2) sum += Be16(ip + i);
  sum += 6 + uint32_t(seg_len);
  for (size_t i = 0; i < seg_len; i += 2) {
    if (i == 16) continue;
    sum += i + 1 < seg_len ? Be16(seg + i) : uint32_t(seg[i] << 8);
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return uint16_t(~sum);
}

// A plain (unfragmented) IPv4/TCP frame: returns the IP header, else null.
uint8_t* TcpFrame(uint8_t* f, size_t length, size_t* ihl, size_t* total) {
  if (length < 14 + 20 + 20 || Be16(f + 12) != 0x0800 || (f[14] >> 4) != 4 ||
      f[14 + 9] != 6) {
    return nullptr;
  }
  uint8_t* ip = f + 14;
  *ihl = (ip[0] & 15) * 4;
  *total = Be16(ip + 2);
  if (*ihl < 20 || *total < *ihl + 20 || 14 + *total > length ||
      (Be16(ip + 6) & 0x3FFF) != 0) {
    return nullptr;
  }
  return ip;
}

constexpr uint8_t kHostAlias[4] = {10, 0, 2, 2};

// nic_tcp_port_map, guest -> slirp: a connection to 10.0.2.2:<port> gets the
// mapped destination port. Every segment of the connection (SYN, data,
// retransmits) is rewritten the same way and the checksum recomputed.
void MapTcpToHost(NicState& n, uint8_t* f, size_t length) {
  size_t ihl, total;
  uint8_t* ip = TcpFrame(f, length, &ihl, &total);
  if (!ip || memcmp(ip + 16, kHostAlias, 4) != 0) return;
  uint8_t* tcp = ip + ihl;
  const uint16_t sport = Be16(tcp), dport = Be16(tcp + 2);
  const bool syn = (tcp[13] & 0x12) == 0x02;
  std::lock_guard<std::mutex> lock(n.port_mutex);
  const auto it = n.tcp_port_map.find(dport);
  if (it == n.tcp_port_map.end()) {
    // A direct connection must not inherit a stale reverse mapping.
    if (syn) n.tcp_port_back.erase(uint32_t(sport) << 16 | dport);
    return;
  }
  n.tcp_port_back[uint32_t(sport) << 16 | it->second] = dport;
  if (syn) {
    XELOGI("NIC tcp map 10.0.2.2:{} -> 127.0.0.1:{} (guest port {})", dport,
           it->second, sport);
  }
  PutBe16(tcp + 2, it->second);
  PutBe16(tcp + 16, TcpChecksum(ip, ihl, total));
}

// slirp -> guest: restores the source port the guest connected to.
void UnmapTcpFromHost(NicState& n, uint8_t* f, size_t length) {
  size_t ihl, total;
  uint8_t* ip = TcpFrame(f, length, &ihl, &total);
  if (!ip || memcmp(ip + 12, kHostAlias, 4) != 0) return;
  uint8_t* tcp = ip + ihl;
  std::lock_guard<std::mutex> lock(n.port_mutex);
  const auto it = n.tcp_port_back.find(uint32_t(Be16(tcp + 2)) << 16 |
                                       Be16(tcp));
  if (it == n.tcp_port_back.end()) return;
  PutBe16(tcp, it->second);
  PutBe16(tcp + 16, TcpChecksum(ip, ihl, total));
}

// UDP checksum of the IPv4 packet at ip, pseudo header included. The field at
// +6 of the UDP header is skipped; a computed 0 is sent as 0xFFFF.
uint16_t UdpChecksum(const uint8_t* ip, size_t ihl, size_t total) {
  const uint8_t* seg = ip + ihl;
  const size_t seg_len = total - ihl;
  uint32_t sum = 0;
  for (int i = 12; i < 20; i += 2) sum += Be16(ip + i);
  sum += 17 + uint32_t(seg_len);
  for (size_t i = 0; i < seg_len; i += 2) {
    if (i == 6) continue;
    sum += i + 1 < seg_len ? Be16(seg + i) : uint32_t(seg[i] << 8);
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  const uint16_t c = uint16_t(~sum);
  return c ? c : 0xFFFF;
}

// A plain (unfragmented) IPv4/UDP frame: returns the IP header, else null.
uint8_t* UdpFrame(uint8_t* f, size_t length, size_t* ihl, size_t* total) {
  if (length < 14 + 20 + 8 || Be16(f + 12) != 0x0800 || (f[14] >> 4) != 4 ||
      f[14 + 9] != 17) {
    return nullptr;
  }
  uint8_t* ip = f + 14;
  *ihl = (ip[0] & 15) * 4;
  *total = Be16(ip + 2);
  if (*ihl < 20 || *total < *ihl + 8 || 14 + *total > length ||
      (Be16(ip + 6) & 0x3FFF) != 0) {
    return nullptr;
  }
  return ip;
}

// nic_udp_port_map, guest -> slirp: a datagram to 10.0.2.2:<port> gets the
// mapped destination port. A UDP checksum of 0 (none) stays 0.
void MapUdpToHost(NicState& n, uint8_t* f, size_t length) {
  size_t ihl, total;
  uint8_t* ip = UdpFrame(f, length, &ihl, &total);
  if (!ip || memcmp(ip + 16, kHostAlias, 4) != 0) return;
  uint8_t* udp = ip + ihl;
  const uint16_t sport = Be16(udp), dport = Be16(udp + 2);
  std::lock_guard<std::mutex> lock(n.port_mutex);
  const auto it = n.udp_port_map.find(dport);
  if (it == n.udp_port_map.end()) {
    // A direct flow must not inherit a stale reverse mapping.
    n.udp_port_back.erase(uint32_t(sport) << 16 | dport);
    return;
  }
  if (n.udp_port_back.insert_or_assign(uint32_t(sport) << 16 | it->second,
                                       dport).second) {
    XELOGI("NIC udp map 10.0.2.2:{} -> 127.0.0.1:{} (guest port {})", dport,
           it->second, sport);
  }
  PutBe16(udp + 2, it->second);
  if (Be16(udp + 6) != 0) PutBe16(udp + 6, UdpChecksum(ip, ihl, total));
}

// slirp -> guest: restores the source port the guest sent to.
void UnmapUdpFromHost(NicState& n, uint8_t* f, size_t length) {
  size_t ihl, total;
  uint8_t* ip = UdpFrame(f, length, &ihl, &total);
  if (!ip || memcmp(ip + 12, kHostAlias, 4) != 0) return;
  uint8_t* udp = ip + ihl;
  std::lock_guard<std::mutex> lock(n.port_mutex);
  const auto it = n.udp_port_back.find(uint32_t(Be16(udp + 2)) << 16 |
                                       Be16(udp));
  if (it == n.udp_port_back.end()) return;
  PutBe16(udp, it->second);
  if (Be16(udp + 6) != 0) PutBe16(udp + 6, UdpChecksum(ip, ihl, total));
}

// OpenPak seam, see the header comment.
bool ResolveOverride(NicState& n, const std::string& name, uint32_t* ip) {
  for (const auto& [pattern, address] : n.dns_hosts) {
    bool match = pattern == name;
    if (!match && pattern.size() > 2 && pattern[0] == '*' &&
        pattern[1] == '.') {
      const std::string suffix = pattern.substr(1);
      match = name.size() > suffix.size() &&
              name.compare(name.size() - suffix.size(), suffix.size(),
                           suffix) == 0;
    }
    if (match) {
      *ip = address;
      return true;
    }
  }
  return false;
}

// Looks at one frame the guest sent: logs what it is asking the network for
// (the first thing to read when mapping a XAM feature to OpenPak) and answers
// DNS queries that ResolveOverride() owns. True if the frame was consumed.
bool InspectGuestFrame(NicState& n, const uint8_t* f, size_t length) {
  if (length < 14 + 20 || Be16(f + 12) != 0x0800 || (f[14] >> 4) != 4) {
    return false;
  }
  const uint8_t* ip = f + 14;
  const size_t ihl = (ip[0] & 15) * 4;
  if (ihl < 20 || length < 14 + ihl + 8) {
    return false;
  }
  const uint8_t* l4 = ip + ihl;
  const uint8_t proto = ip[9];
  if (proto == 6) {
    if (length >= 14 + ihl + 14 && (l4[13] & 0x12) == 0x02) {
      XELOGI("NIC tcp connect {}:{}", FormatIp(ip + 16), Be16(l4 + 2));
    }
    return false;
  }
  if (proto != 17) {
    return false;
  }
  const uint16_t dport = Be16(l4 + 2);
  if (dport != 53) {
    if (dport != 67) {
      const uint64_t key = uint64_t(*reinterpret_cast<const uint32_t*>(ip + 16))
                               << 16 |
                           dport;
      if (n.seen_udp.insert(key).second) {
        XELOGI("NIC udp to {}:{}", FormatIp(ip + 16), dport);
      }
    }
    return false;
  }

  // DNS query: header 12 bytes, one question.
  const uint8_t* dns = l4 + 8;
  const uint8_t* end = f + length;
  if (end - dns < 12 + 5 || (dns[2] & 0x80) || Be16(dns + 4) != 1) {
    return false;
  }
  std::string name;
  const uint8_t* q = dns + 12;
  while (q < end && *q) {
    const size_t label = *q++;
    if (label > 63 || size_t(end - q) < label + 1) {
      return false;
    }
    for (size_t i = 0; i < label; ++i) {
      name += char(std::tolower(q[i]));
    }
    name += '.';
    q += label;
  }
  if (q >= end || end - q < 5) {
    return false;
  }
  if (!name.empty()) {
    name.pop_back();
  }
  const uint16_t qtype = Be16(q + 1);
  const uint16_t qclass = Be16(q + 3);
  const uint8_t* question_end = q + 5;
  XELOGI("NIC dns query {} type {}", name, qtype);

  uint32_t address = 0;
  if (qtype != 1 || qclass != 1 || !ResolveOverride(n, name, &address)) {
    return false;
  }
  XELOGI("NIC dns {} -> {} (override)", name, FormatIp(
      reinterpret_cast<const uint8_t*>(&address)));

  const size_t question_length = question_end - (dns + 12);
  const size_t dns_length = 12 + question_length + 16;
  std::vector<uint8_t> r(14 + 20 + 8 + dns_length, 0);
  uint8_t* re = r.data();
  std::memcpy(re, f + 6, 6);      // to the guest
  std::memcpy(re + 6, f, 6);      // from whoever it addressed
  PutBe16(re + 12, 0x0800);
  uint8_t* rip = re + 14;
  rip[0] = 0x45;
  PutBe16(rip + 2, uint16_t(20 + 8 + dns_length));
  rip[6] = 0x40;  // don't fragment
  rip[8] = 64;
  rip[9] = 17;
  std::memcpy(rip + 12, ip + 16, 4);
  std::memcpy(rip + 16, ip + 12, 4);
  PutBe16(rip + 10, IpChecksum(rip, 20));
  uint8_t* ru = rip + 20;
  PutBe16(ru, 53);
  std::memcpy(ru + 2, l4, 2);
  PutBe16(ru + 4, uint16_t(8 + dns_length));  // checksum 0 = none, legal
  uint8_t* rd = ru + 8;
  std::memcpy(rd, dns, 2);
  PutBe16(rd + 2, 0x8180);
  PutBe16(rd + 4, 1);
  PutBe16(rd + 6, 1);
  std::memcpy(rd + 12, dns + 12, question_length);
  uint8_t* a = rd + 12 + question_length;
  const uint8_t answer[12] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0x3C, 0, 4};
  std::memcpy(a, answer, 12);
  std::memcpy(a + 12, &address, 4);
  QueueRx(n, r.data(), r.size());
  return true;
}

slirp_ssize_t SlirpSend(const void* buf, size_t len, void* opaque) {
  auto& n = *static_cast<NicState*>(opaque);
  if ((!n.tcp_port_map.empty() || !n.udp_port_map.empty()) &&
      len <= kRxSlotSize) {
    std::vector<uint8_t> frame(static_cast<const uint8_t*>(buf),
                               static_cast<const uint8_t*>(buf) + len);
    UnmapTcpFromHost(n, frame.data(), frame.size());
    UnmapUdpFromHost(n, frame.data(), frame.size());
    QueueRx(n, frame.data(), frame.size());
    return slirp_ssize_t(len);
  }
  QueueRx(n, static_cast<const uint8_t*>(buf), len);
  return slirp_ssize_t(len);
}
void SlirpGuestError(const char* msg, void*) { XELOGW("NIC slirp: {}", msg); }
int64_t SlirpClockNs(void*) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
// ponytail: slirp only uses timers for the IPv6 router advertisement, and IPv6
// is off; give it inert handles.
void* SlirpTimerNew(SlirpTimerId, void*, void*) { return new int(0); }
void SlirpTimerFree(void* timer, void*) { delete static_cast<int*>(timer); }
void SlirpTimerMod(void*, int64_t, void*) {}
void SlirpPollSocket(slirp_os_socket, void*) {}
void SlirpNotify(void* opaque) { WakeNic(*static_cast<NicState*>(opaque)); }

int SlirpAddPoll(slirp_os_socket fd, int events, void* opaque) {
  auto& n = *static_cast<NicState*>(opaque);
  short e = 0;
  if (events & SLIRP_POLL_IN) e |= POLLIN;
  if (events & SLIRP_POLL_OUT) e |= POLLOUT;
  if (events & SLIRP_POLL_PRI) e |= POLLPRI;
  n.fds.push_back({fd, e, 0});
  return int(n.fds.size() - 1);
}
int SlirpGetRevents(int idx, void* opaque) {
  auto& n = *static_cast<NicState*>(opaque);
  const short r = n.fds[idx].revents;
  int e = 0;
  if (r & POLLIN) e |= SLIRP_POLL_IN;
  if (r & POLLOUT) e |= SLIRP_POLL_OUT;
  if (r & POLLPRI) e |= SLIRP_POLL_PRI;
  if (r & POLLERR) e |= SLIRP_POLL_ERR;
  if (r & POLLHUP) e |= SLIRP_POLL_HUP;
  return e;
}

// Runs the guest's tx-done and rx callbacks for everything queued.
void DeliverToGuest(NicState& n, cpu::ThreadState* thread_state) {
  auto* processor = kernel_state()->processor();
  auto* memory = kernel_state()->memory();
  uint32_t context, rx_callback, tx_done_callback, link_callback;
  {
    std::lock_guard<std::mutex> lock(n.mutex);
    context = n.context;
    rx_callback = n.rx_callback;
    tx_done_callback = n.tx_done_callback;
    link_callback = n.link_callback;
  }
  // XAM compares NicGetLinkState with what it last saw when this runs, and
  // applies its network configuration (DHCP) on a change.
  if (n.link_changed.exchange(false) && link_callback) {
    uint64_t args[] = {context};
    XELOGI("NIC link callback {:08X} ctx {:08X}", link_callback, context);
    processor->Execute(thread_state, link_callback, args, 1);
  }
  for (;;) {
    uint32_t packet = 0;
    std::vector<uint8_t> frame;
    {
      std::lock_guard<std::mutex> lock(n.queue_mutex);
      if (!n.tx_done_queue.empty()) {
        packet = n.tx_done_queue.front();
        n.tx_done_queue.pop_front();
      } else if (!n.rx_queue.empty()) {
        frame = std::move(n.rx_queue.front());
        n.rx_queue.pop_front();
      } else {
        return;
      }
    }
    if (packet) {
      uint64_t args[] = {context, packet};
      processor->Execute(thread_state, tx_done_callback, args, 2);
      continue;
    }
    if (frame.size() < 14 || frame.size() > kRxSlotSize) {
      continue;
    }
    // The ring outlives XAM's use of a frame: it handles each one inside the
    // callback, and 128 slots is far more than it can hold on to.
    const uint32_t guest_frame = n.rx_ring + (n.rx_next++ % kRxSlots) * kRxSlotSize;
    std::memcpy(memory->TranslateVirtual<uint8_t*>(guest_frame), frame.data(),
                frame.size());
    uint32_t kind = 1;
    if (frame[0] & 1) {
      static const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      kind = std::memcmp(frame.data(), kBroadcast, 6) == 0 ? 4 : 3;
    }
    uint64_t args[] = {context, guest_frame, frame.size(), 0, kind};
    processor->Execute(thread_state, rx_callback, args, 5);
  }
}

int NicThreadMain() {
  auto& n = nic();
  auto* thread_state = XThread::GetCurrentThread()->thread_state();
  while (n.running) {
    uint32_t timeout = 500;
    n.fds.clear();
    n.fds.push_back({n.wake_fd, POLLIN, 0});
    {
      std::lock_guard<std::mutex> lock(n.slirp_mutex);
      slirp_pollfds_fill_socket(n.slirp, &timeout, SlirpAddPoll, &n);
    }
    const int ready = poll(n.fds.data(), n.fds.size(), int(timeout));
    if (n.fds[0].revents & POLLIN) {
      uint64_t counter;
      [[maybe_unused]] auto ignored = read(n.wake_fd, &counter, sizeof(counter));
    }
    {
      std::lock_guard<std::mutex> lock(n.slirp_mutex);
      slirp_pollfds_poll(n.slirp, ready < 0, SlirpGetRevents, &n);
    }
    DeliverToGuest(n, thread_state);
  }
  return 0;
}

void StartBackend(NicState& n) {
  if (n.slirp) {
    return;
  }
  SlirpConfig config = {};
  config.version = 6;  // >= 6 selects register_poll_socket; older reads a null register_poll_fd
  config.in_enabled = true;
  inet_pton(AF_INET, "10.0.2.0", &config.vnetwork);
  inet_pton(AF_INET, "255.255.255.0", &config.vnetmask);
  inet_pton(AF_INET, "10.0.2.2", &config.vhost);
  inet_pton(AF_INET, "10.0.2.15", &config.vdhcp_start);
  inet_pton(AF_INET, "10.0.2.3", &config.vnameserver);
  config.vhostname = "xbox360";
  config.if_mtu = 1500;
  config.if_mru = 1500;
  static const SlirpCb callbacks = {
      .send_packet = SlirpSend,
      .guest_error = SlirpGuestError,
      .clock_get_ns = SlirpClockNs,
      .timer_free = SlirpTimerFree,
      .timer_mod = SlirpTimerMod,
      .notify = SlirpNotify,
      .timer_new_opaque = SlirpTimerNew,
      .register_poll_socket = SlirpPollSocket,
      .unregister_poll_socket = SlirpPollSocket,
  };
  n.wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  n.slirp = slirp_new(&config, &callbacks, &n);
  if (!n.slirp || n.wake_fd < 0) {
    XELOGE("NIC: slirp failed to start, the cable stays unplugged in effect");
    n.slirp = nullptr;
    return;
  }
  n.rx_ring = kernel_state()->memory()->SystemHeapAlloc(kRxSlots * kRxSlotSize);

  // nic_dns_hosts: name=ip;name=ip
  const std::string hosts = cvars::nic_dns_hosts;
  for (size_t pos = 0; pos < hosts.size();) {
    size_t next = hosts.find_first_of(";,", pos);
    if (next == std::string::npos) next = hosts.size();
    const std::string entry = hosts.substr(pos, next - pos);
    const size_t eq = entry.find('=');
    in_addr address;
    if (eq != std::string::npos &&
        inet_pton(AF_INET, entry.c_str() + eq + 1, &address) == 1) {
      std::string name = entry.substr(0, eq);
      std::transform(name.begin(), name.end(), name.begin(), ::tolower);
      n.dns_hosts.emplace_back(name, address.s_addr);
    }
    pos = next + 1;
  }

  // nic_tcp_port_map: guest=host;guest=host
  const std::string ports = cvars::nic_tcp_port_map;
  for (size_t pos = 0; pos < ports.size();) {
    size_t next = ports.find_first_of(";,", pos);
    if (next == std::string::npos) next = ports.size();
    const std::string entry = ports.substr(pos, next - pos);
    const size_t eq = entry.find('=');
    const int from = eq == std::string::npos ? 0 : atoi(entry.c_str());
    const int to = eq == std::string::npos ? 0 : atoi(entry.c_str() + eq + 1);
    if (from > 0 && from < 65536 && to > 0 && to < 65536) {
      n.tcp_port_map[uint16_t(from)] = uint16_t(to);
      XELOGI("NIC tcp port map 10.0.2.2:{} -> 127.0.0.1:{}", from, to);
    }
    pos = next + 1;
  }

  // nic_udp_port_map: guest=host;guest=host
  const std::string uports = cvars::nic_udp_port_map;
  for (size_t pos = 0; pos < uports.size();) {
    size_t next = uports.find_first_of(";,", pos);
    if (next == std::string::npos) next = uports.size();
    const std::string entry = uports.substr(pos, next - pos);
    const size_t eq = entry.find('=');
    const int from = eq == std::string::npos ? 0 : atoi(entry.c_str());
    const int to = eq == std::string::npos ? 0 : atoi(entry.c_str() + eq + 1);
    if (from > 0 && from < 65536 && to > 0 && to < 65536) {
      n.udp_port_map[uint16_t(from)] = uint16_t(to);
      XELOGI("NIC udp port map 10.0.2.2:{} -> 127.0.0.1:{}", from, to);
    }
    pos = next + 1;
  }

  n.link_changed = true;
  n.running = true;
  n.thread = object_ref<XHostThread>(new XHostThread(
      kernel_state(), 128 * 1024, 0, []() { return NicThreadMain(); },
      kernel_state()->GetSystemProcess()));
  n.thread->set_can_debugger_suspend(true);
  n.thread->set_name("NIC");
  n.thread->Create();
  XELOGI("NIC: libslirp {} up, guest gets 10.0.2.15 gw 10.0.2.2 dns 10.0.2.3",
         slirp_version_string());
}

#endif  // XE_HAVE_SLIRP

}  // namespace

dword_result_t NicAttach_entry(dword_t config_ptr, dword_t handle_out) {
  const auto* c = kernel_state()->memory()->TranslateVirtual<
      const xe::be<uint32_t>*>(config_ptr);
  auto& n = nic();
  {
    std::lock_guard<std::mutex> lock(n.mutex);
    n.context = c[2];
    n.rx_callback = c[3];
    n.tx_done_callback = c[4];
    n.link_callback = c[5];
    n.attached = true;
    n.options[kOptReceiveFilter] = c[0];
  }
  XELOGI("NIC attach: filter {:08X} ctx {:08X} rx {:08X} link {:08X} txdone "
         "{:08X}",
         static_cast<uint32_t>(c[0]), n.context, n.rx_callback,
         n.link_callback, n.tx_done_callback);
#ifdef XE_HAVE_SLIRP
  StartBackend(n);
#endif
  if (handle_out) {
    xe::store_and_swap<uint32_t>(
        kernel_state()->memory()->TranslateVirtual(handle_out), kNicHandle);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicAttach, kNone, kImplemented);

dword_result_t NicDetach_entry(dword_t handle) {
  std::lock_guard<std::mutex> lock(nic().mutex);
  nic().attached = false;
  XELOGI("NIC detach");
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicDetach, kNone, kImplemented);

dword_result_t NicGetLinkState_entry(dword_t handle) {
  return kLinkState;
}
DECLARE_XBOXKRNL_EXPORT2(NicGetLinkState, kNone, kImplemented, kHighFrequency);

dword_result_t NicXmit_entry(dword_t handle, dword_t vlan, dword_t frame_ptr,
                             dword_t length, dword_t packet) {
#ifdef XE_HAVE_SLIRP
  auto& n = nic();
  if (n.slirp && length >= 14 && length <= kRxSlotSize) {
    // Copied: the guest reuses the buffer once tx-done fires, and the DNS
    // interception queues an answer built from it.
    std::vector<uint8_t> frame(
        kernel_state()->memory()->TranslateVirtual<const uint8_t*>(frame_ptr),
        kernel_state()->memory()->TranslateVirtual<const uint8_t*>(frame_ptr) +
            length);
    if (!InspectGuestFrame(n, frame.data(), frame.size())) {
      if (!n.tcp_port_map.empty()) {
        MapTcpToHost(n, frame.data(), frame.size());
      }
      if (!n.udp_port_map.empty()) {
        MapUdpToHost(n, frame.data(), frame.size());
      }
      std::lock_guard<std::mutex> lock(n.slirp_mutex);
      slirp_input(n.slirp, frame.data(), int(frame.size()));
    }
  }
  if (n.slirp && packet) {
    {
      std::lock_guard<std::mutex> lock(n.queue_mutex);
      n.tx_done_queue.push_back(packet);
    }
    WakeNic(n);
  }
#endif
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicXmit, kNone, kImplemented);

dword_result_t NicFlushXmitQueue_entry(dword_t handle) { return 0; }
DECLARE_XBOXKRNL_EXPORT1(NicFlushXmitQueue, kNone, kImplemented);

dword_result_t NicGetOpt_entry(dword_t handle, dword_t option, dword_t buffer,
                               dword_t length_ptr) {
  auto& n = nic();
  std::lock_guard<std::mutex> lock(n.mutex);
  auto it = n.options.find(option);
  if (it == n.options.end() || !buffer || !length_ptr) {
    XELOGD("NIC getopt {:08X}: not implemented", option.value());
    return kStatusNotImplemented;
  }
  auto* memory = kernel_state()->memory();
  xe::store_and_swap<uint32_t>(memory->TranslateVirtual(buffer), it->second);
  xe::store_and_swap<uint32_t>(memory->TranslateVirtual(length_ptr), 4);
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicGetOpt, kNone, kImplemented);

dword_result_t NicSetOpt_entry(dword_t handle, dword_t option, dword_t buffer,
                               dword_t length) {
  if ((option == kOptReceiveFilter || option == kOptTxFlow) && buffer &&
      length >= 4) {
    auto& n = nic();
    std::lock_guard<std::mutex> lock(n.mutex);
    n.options[option] = xe::load_and_swap<uint32_t>(
        kernel_state()->memory()->TranslateVirtual(buffer));
  } else {
    XELOGD("NIC setopt {:08X} length {}: ignored", option.value(),
           length.value());
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicSetOpt, kNone, kImplemented);

dword_result_t NicSetUnicastAddress_entry(dword_t handle, dword_t mac_ptr) {
  if (mac_ptr) {
    const uint8_t* m =
        kernel_state()->memory()->TranslateVirtual<const uint8_t*>(mac_ptr);
    XELOGI("NIC unicast address {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
           m[0], m[1], m[2], m[3], m[4], m[5]);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicSetUnicastAddress, kNone, kImplemented);

dword_result_t NicUpdateMcastMembership_entry(dword_t handle) { return 0; }
DECLARE_XBOXKRNL_EXPORT1(NicUpdateMcastMembership, kNone, kImplemented);

// Counters XAM only reports as link statistics; the record is 0x5C bytes
// (XAM clears 0x5C bytes for it), all zero.
dword_result_t NicGetStats_entry(dword_t handle, dword_t buffer) {
  if (buffer) {
    std::memset(kernel_state()->memory()->TranslateVirtual(buffer), 0, 0x5C);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicGetStats, kNone, kImplemented);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Nic);
