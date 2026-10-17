/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/emulator.h"
#include "xenia/hid/input_system.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"

namespace xe {
namespace kernel {
namespace xboxkrnl {

dword_result_t HidReadKeys_entry(dword_t unk1, unknown_t unk2, unknown_t unk3) {
  /* TODO(gibbed):
   * Games check for the following errors:
   *   0xC000009D - translated to 0x48F  - ERROR_DEVICE_NOT_CONNECTED
   *   0x103      - translated to 0x10D2 - ERROR_EMPTY
   * Other errors appear to be ignored?
   *
   * unk1 is 0
   * unk2 is a pointer to &unk3[2], possibly a 6-byte buffer
   * unk3 is a pointer to a 20-byte buffer
   */
  return 0xC000009D;
}
DECLARE_XBOXKRNL_EXPORT1(HidReadKeys, kInput, kStub);

// The real xam.xex reads controllers through these. A device id is 0x4000000N:
// class 4 (gamepad) in the top nibble, user slot N-1, as given to the binding
// callback on connect.
static uint32_t GamepadSlot(uint32_t device_id) {
  const uint32_t n = device_id & 0xFFFF;
  return (device_id >> 28) == 4 && n >= 1 && n <= 4 ? n - 1 : 0xFFFFFFFF;
}

dword_result_t XInputdGetCapabilities_entry(dword_t device_id,
                                            pointer_t<hid::X_INPUT_CAPABILITIES> caps,
                                            lpdword_t flags_out) {
  if (flags_out) {
    *flags_out = 0;
  }
  if (GamepadSlot(device_id) == 0xFFFFFFFF || !caps) {
    return 0xC000009D;  // device not connected
  }
  auto input_system = kernel_state()->emulator()->input_system();
  auto lock = input_system->lock();
  return input_system->GetCapabilities(
             GamepadSlot(device_id), hid::X_INPUT_FLAG::X_INPUT_FLAG_GAMEPAD, caps) ==
                 X_ERROR_SUCCESS
             ? 0
             : 0xC000009D;
}
DECLARE_XBOXKRNL_EXPORT1(XInputdGetCapabilities, kInput, kImplemented);

dword_result_t XInputdReadState_entry(dword_t device_id,
                                      pointer_t<hid::X_INPUT_STATE> state,
                                      lpvoid_t gamepad_out,
                                      lpdword_t flags_out) {
  if (flags_out) {
    *flags_out = 0;
  }
  if (GamepadSlot(device_id) == 0xFFFFFFFF || !state) {
    return 0xC000009D;
  }
  auto input_system = kernel_state()->emulator()->input_system();
  auto lock = input_system->lock();
  hid::X_INPUT_STATE read = {};
  if (input_system->GetStateForUI(GamepadSlot(device_id),
                                  hid::X_INPUT_FLAG::X_INPUT_FLAG_GAMEPAD,
                                  &read) != X_ERROR_SUCCESS) {
    return 0xC000009D;
  }
  // The pad is bound twice (port type 0, device 0x40..., and port type 3,
  // device 0x43..., see Emulator::Launch), and XAM makes keystrokes from both,
  // so one host press arrived twice. Split the host state: the type 3
  // (keystroke) device gets the digital buttons, the type 0 device the
  // shoulders, triggers and sticks. Without a type 3 device nothing changes.
  {
    static bool keystroke_device_seen = false;
    const bool keystroke_device = ((uint32_t(device_id) >> 24) & 0xF) == 3;
    keystroke_device_seen |= keystroke_device;
    constexpr uint16_t kShoulders = 0x0300;  // LB, RB
    const uint16_t buttons = read.gamepad.buttons;
    if (keystroke_device) {
      read.gamepad.buttons = uint16_t(buttons & ~kShoulders);
      read.gamepad.left_trigger = 0;
      read.gamepad.right_trigger = 0;
      read.gamepad.thumb_lx = 0;
      read.gamepad.thumb_ly = 0;
      read.gamepad.thumb_rx = 0;
      read.gamepad.thumb_ry = 0;
    } else if (keystroke_device_seen) {
      read.gamepad.buttons = uint16_t(buttons & kShoulders);
    }
  }
  *state = read;
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(XInputdReadState, kInput, kImplemented);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Hid);
