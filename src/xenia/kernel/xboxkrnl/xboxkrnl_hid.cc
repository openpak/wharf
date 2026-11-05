/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <deque>
#include <set>
#include <utility>
#include <string>
#include "xenia/base/logging.h"
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
  // Scripted test input (WHARF_PAD_FILE): write "A,DOWN,A" to the file; the
  // buttons are pressed in order and the file is deleted once read. Unset =
  // no effect. Used by the scratch/wharf w-pad.sh test scripts.
  {
    static const char* path = getenv("WHARF_PAD_FILE");
    static std::deque<std::pair<uint32_t, int>> queue;
    static uint32_t held = 0;
    static uint32_t phase = 0;
    if (path) {
      static std::set<uint32_t> seen_devices;
      if (seen_devices.insert(uint32_t(device_id)).second) {
        XELOGI("WHARF_PAD polled device {:#x}", uint32_t(device_id));
      }
      if (queue.empty() && held == 0) {
        if (FILE* f = fopen(path, "r")) {
          char line[256] = {};
          if (fgets(line, sizeof(line), f)) {
            std::string s = line;
            size_t pos = 0;
            while (pos < s.size()) {
              size_t next = s.find_first_of(",\n", pos);
              if (next == std::string::npos) next = s.size();
              std::string b = s.substr(pos, next - pos);
              pos = next + 1;
              // Optional per-press hold in polls: "RIGHT:1".
              int hold_override = 0;
              if (auto colon = b.find(':'); colon != std::string::npos) {
                hold_override = atoi(b.c_str() + colon + 1);
                b.resize(colon);
              }
              uint32_t mask = b == "A" ? 0x1000 : b == "B" ? 0x2000 : b == "X" ? 0x4000
                            : b == "Y" ? 0x8000 : b == "UP" ? 1 : b == "DOWN" ? 2
                            : b == "LEFT" ? 4 : b == "RIGHT" ? 8 : b == "START" ? 0x10
                            : b == "BACK" ? 0x20 : b == "GUIDE" ? 0x400
                            : b == "LB" ? 0x100 : b == "RB" ? 0x200
                            : b == "LT" ? 0x10000 : b == "RT" ? 0x20000 : 0;
              if (mask) queue.emplace_back(mask, hold_override);
            }
          }
          fclose(f);
          remove(path);
        }
      }
      // Timing is counted in polls, not seconds, so a loaded host cannot
      // swallow a press or stretch it into a key repeat: each press is held
      // for WHARF_PAD_HOLD polls (default 1) and followed by WHARF_PAD_GAP
      // polls (default 12) of release.
      static const int hold_polls =
          getenv("WHARF_PAD_HOLD") ? atoi(getenv("WHARF_PAD_HOLD")) : 1;
      static const int gap_polls =
          getenv("WHARF_PAD_GAP") ? atoi(getenv("WHARF_PAD_GAP")) : 12;
      static int countdown = 0;
      if (countdown > 0) {
        --countdown;
      } else if (held) {
        held = 0;
        countdown = gap_polls;
        ++phase;
      } else if (!queue.empty()) {
        held = queue.front().first;
        countdown = queue.front().second ? queue.front().second : hold_polls;
        queue.pop_front();
        XELOGI("WHARF_PAD press {:#x} device {:#x}", held, uint32_t(device_id));
        ++phase;
      }
      // Type 3 (device id 0x43...) is the keystroke path and ignores triggers
      // and shoulders; type 0 handles those. Buttons go to type 3 only,
      // LT/RT/LB/RB to type 0 only, so no press is doubled.
      const bool is_t3 = ((uint32_t(device_id) >> 24) & 0xF) == 3;
      if (held) {
        const uint32_t special = held & 0x30300;
        static bool saw_t3 = false;
        saw_t3 |= is_t3;
        if (!special && (is_t3 || !saw_t3)) {
          read.gamepad.buttons = uint16_t(uint16_t(read.gamepad.buttons) | held);
        } else if (!is_t3 && special) {
          read.gamepad.buttons =
              uint16_t(uint16_t(read.gamepad.buttons) | (held & 0x300));
          if (held & 0x10000) read.gamepad.left_trigger = 255;
          if (held & 0x20000) read.gamepad.right_trigger = 255;
        }
      }
      read.packet_number = uint32_t(read.packet_number) + phase;
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
