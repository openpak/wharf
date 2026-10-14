/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

// This is a partial file designed to be included by other files when
// constructing various tables.

// clang-format off
XE_HID_KEYBOARD_BINDING(Guide,       "GUIDE"              , keybind_guide            , "0x77")
XE_HID_KEYBOARD_BINDING(DpadLeft,    "DPAD_LEFT"          , keybind_dpad_left        , "0x25"  )
XE_HID_KEYBOARD_BINDING(DpadRight,   "DPAD_RIGHT"         , keybind_dpad_right       , "0x27"  )
XE_HID_KEYBOARD_BINDING(DpadDown,    "DPAD_DOWN"          , keybind_dpad_down        , "0x28"  )
XE_HID_KEYBOARD_BINDING(DpadUp,      "DPAD_UP"            , keybind_dpad_up          , "0x26"  )
XE_HID_KEYBOARD_BINDING(LThumbLeft,  "LEFT_THUMB_LEFT"    , keybind_left_thumb_left  , "A"  )
XE_HID_KEYBOARD_BINDING(LThumbRight, "LEFT_THUMB_RIGHT"   , keybind_left_thumb_right , "D"  )
XE_HID_KEYBOARD_BINDING(LThumbDown,  "LEFT_THUMB_DOWN"    , keybind_left_thumb_down  , "S"  )
XE_HID_KEYBOARD_BINDING(LThumbUp,    "LEFT_THUMB_UP"      , keybind_left_thumb_up    , "W"  )
XE_HID_KEYBOARD_BINDING(LThumbPress, "LEFT_THUMB_PRESSED" , keybind_left_thumb       , "F"   )
XE_HID_KEYBOARD_BINDING(RThumbUp,    "RIGHT_THUMB_UP"     , keybind_right_thumb_up   , "I")
XE_HID_KEYBOARD_BINDING(RThumbDown,  "RIGHT_THUMB_DOWN"   , keybind_right_thumb_down , "K")
XE_HID_KEYBOARD_BINDING(RThumbRight, "RIGHT_THUMB_RIGHT"  , keybind_right_thumb_right, "L")
XE_HID_KEYBOARD_BINDING(RThumbLeft,  "RIGHT_THUMB_LEFT"   , keybind_right_thumb_left , "J")
XE_HID_KEYBOARD_BINDING(RThumbPress, "RIGHT_THUMB_PRESSED", keybind_right_thumb      , "G"   )
XE_HID_KEYBOARD_BINDING(X,           "X"                  , keybind_x                , "Z"   )
XE_HID_KEYBOARD_BINDING(B,           "B"                  , keybind_b                , "C")
XE_HID_KEYBOARD_BINDING(A,           "A"                  , keybind_a                , "X")
XE_HID_KEYBOARD_BINDING(Y,           "Y"                  , keybind_y                , "V"   )
XE_HID_KEYBOARD_BINDING(LTrigger,    "LEFT_TRIGGER"       , keybind_left_trigger     , "R" )
XE_HID_KEYBOARD_BINDING(RTrigger,    "RIGHT_TRIGGER"      , keybind_right_trigger    , "T" )
XE_HID_KEYBOARD_BINDING(Back,        "BACK"               , keybind_back             , "N"   )
XE_HID_KEYBOARD_BINDING(Start,       "START"              , keybind_start            , "M"   )
XE_HID_KEYBOARD_BINDING(LShoulder,   "LEFT_SHOULDER"      , keybind_left_shoulder    , "Q"   )
XE_HID_KEYBOARD_BINDING(RShoulder,   "RIGHT_SHOULDER"     , keybind_right_shoulder   , "E"   )
// clang-format on
