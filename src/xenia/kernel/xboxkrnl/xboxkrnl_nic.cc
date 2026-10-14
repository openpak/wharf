/**
 ******************************************************************************
 * Wharf: OpenPak Xbox 360 emulator, a fork of Xenia Edge                     *
 ******************************************************************************
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <algorithm>
#include <cstring>

#include "xenia/base/logging.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"
#include "xenia/xbox.h"

// The network card as the real xam.xex sees it. XAM runs its own XNet stack
// (ARP, DHCP, DNS, TCP/UDP) and talks to the kernel's NIC driver through the
// Nic* exports:
//   NicAttach(config, &handle): config = {flags, mask, context, rx callback,
//     tx-done callback, link/status callback, 0}, all guest addresses.
//   NicXmit(handle, vlan, frame, length, packet): an Ethernet frame goes out;
//     the tx-done callback(context, packet) must follow.
//   the rx callback(context, frame, length, ?, kind) takes a received frame;
//     kind 1 = unicast to us, 3 = broadcast, 4 = multicast.
//   NicGetLinkState(handle): bit 0 link up, 0x8 full duplex, 0x2 gigabit,
//     0x20 10 Mbit (neither = 100 Mbit).

namespace xe {
namespace kernel {
namespace xboxkrnl {

namespace {

constexpr uint32_t kLinkUp = 0x1;
constexpr uint32_t kFullDuplex = 0x8;
// A cable is plugged in at 100 Mbit full duplex.
constexpr uint32_t kLinkState = kLinkUp | kFullDuplex;

constexpr uint32_t kNicHandle = 1;

struct NicState {
  uint32_t context = 0;
  uint32_t rx_callback = 0;
  uint32_t link_callback = 0;
  uint32_t tx_done_callback = 0;
  bool attached = false;
};

NicState& nic() {
  static NicState state;
  return state;
}

constexpr uint32_t kStatusNotSupported = 0xC00000BB;

}  // namespace

dword_result_t NicAttach_entry(dword_t config_ptr, dword_t handle_out) {
  const auto* c = kernel_state()->memory()->TranslateVirtual<
      const xe::be<uint32_t>*>(config_ptr);
  auto& n = nic();
  n.context = c[2];
  n.rx_callback = c[3];
  n.tx_done_callback = c[4];
  n.link_callback = c[5];
  n.attached = true;
  XELOGW("NIC attach: flags {:08X} mask {:08X} ctx {:08X} rx {:08X} link {:08X} txdone {:08X}",
         static_cast<uint32_t>(c[0]), static_cast<uint32_t>(c[1]), n.context,
         n.rx_callback, n.link_callback, n.tx_done_callback);
  if (handle_out) {
    xe::store_and_swap<uint32_t>(
        kernel_state()->memory()->TranslateVirtual(handle_out), kNicHandle);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicAttach, kNone, kImplemented);

dword_result_t NicDetach_entry(dword_t handle) {
  nic().attached = false;
  XELOGW("NIC detach");
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicDetach, kNone, kImplemented);

dword_result_t NicGetLinkState_entry(dword_t handle) { return kLinkState; }
DECLARE_XBOXKRNL_EXPORT2(NicGetLinkState, kNone, kImplemented, kHighFrequency);

dword_result_t NicXmit_entry(dword_t handle, dword_t vlan, dword_t frame_ptr,
                             dword_t length, dword_t packet) {
  static int logged = 0;
  if (logged < 12 && length >= 14) {
    ++logged;
    const uint8_t* f = kernel_state()->memory()->TranslateVirtual<const uint8_t*>(
        frame_ptr);
    XELOGW("NIC xmit #{} len {} dst {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} "
           "src {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} type {:02X}{:02X}",
           logged, length.value(), f[0], f[1], f[2], f[3], f[4], f[5], f[6],
           f[7], f[8], f[9], f[10], f[11], f[12], f[13]);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicXmit, kNone, kImplemented);

dword_result_t NicFlushXmitQueue_entry(dword_t handle) { return 0; }
DECLARE_XBOXKRNL_EXPORT1(NicFlushXmitQueue, kNone, kImplemented);

dword_result_t NicGetOpt_entry(dword_t handle, dword_t option, dword_t buffer,
                               dword_t length_ptr) {
  uint32_t length = 0;
  if (length_ptr) {
    length = xe::load_and_swap<uint32_t>(
        kernel_state()->memory()->TranslateVirtual(length_ptr));
  }
  XELOGW("NIC getopt {:08X} length {}", option.value(), length);
  return kStatusNotSupported;
}
DECLARE_XBOXKRNL_EXPORT1(NicGetOpt, kNone, kImplemented);

dword_result_t NicSetOpt_entry(dword_t handle, dword_t option, dword_t buffer,
                               dword_t length) {
  XELOGW("NIC setopt {:08X} length {}", option.value(), length.value());
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicSetOpt, kNone, kImplemented);

dword_result_t NicSetUnicastAddress_entry(dword_t handle, dword_t mac_ptr) {
  if (mac_ptr) {
    const uint8_t* m =
        kernel_state()->memory()->TranslateVirtual<const uint8_t*>(mac_ptr);
    XELOGW("NIC unicast address {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
           m[0], m[1], m[2], m[3], m[4], m[5]);
  }
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicSetUnicastAddress, kNone, kImplemented);

dword_result_t NicUpdateMcastMembership_entry(dword_t handle) { return 0; }
DECLARE_XBOXKRNL_EXPORT1(NicUpdateMcastMembership, kNone, kImplemented);

dword_result_t NicGetStats_entry(dword_t handle, dword_t buffer) {
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(NicGetStats, kNone, kImplemented);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Nic);
