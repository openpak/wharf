/**
******************************************************************************
* Xenia : Xbox 360 Emulator Research Project                                 *
******************************************************************************
* Copyright 2022 Ben Vanik. All rights reserved.                             *
* Released under the BSD license - see LICENSE in the root for more details. *
******************************************************************************
*/

#include <mutex>
#include <random>
#include <algorithm>
#include <tuple>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "third_party/mbedtls/include/mbedtls/bignum.h"
#include "third_party/mbedtls/include/mbedtls/md.h"
#include "third_party/mbedtls/include/mbedtls/sha1.h"
#include "xenia/base/cvar.h"
#include "xenia/emulator.h"
#include "xenia/base/logging.h"
#include "xenia/base/platform.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_crypt.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"

#include "xenia/kernel/xboxkrnl/xecrypt_aes.h"
#include "xenia/kernel/xboxkrnl/xecrypt_des.h"
#include "xenia/kernel/xboxkrnl/xecrypt_md5.h"
#include "xenia/kernel/xboxkrnl/xecrypt_rsa.h"
#include "xenia/kernel/xboxkrnl/xecrypt_dh.h"
#include "xenia/kernel/xboxkrnl/xecrypt_sha.h"

DEFINE_string(console_ca_key, "",
              "Wharf DEV: file with the OpenPak dev console CA private key\n"
              "(two lines, 'n=<hex>' and 'd=<hex>', 2048 bit). Only used the\n"
              "first time to issue this instance's console certificate; it is\n"
              "never copied. Without it the console has no usable certificate.",
              "Kernel");

namespace xe {
namespace kernel {
namespace xboxkrnl {

struct XECRYPT_RC4_STATE {
  uint8_t S[256];  // 0x0
  uint8_t i;       // 0x100
  uint8_t j;       // 0x101
};
static_assert_size(XECRYPT_RC4_STATE, 0x102);

// TODO: Size of this struct hasn't been confirmed yet.
struct XECRYPT_RSA {
  xe::be<uint32_t> size;  // size of modulus in 8 byte units
  xe::be<uint32_t> public_exponent;
  xe::be<uint64_t> pad_8;

  // followed by modulus, followed by any private-key data
};
static_assert_size(XECRYPT_RSA, 0x10);

struct XECRYPT_SIG {
  xe::be<uint64_t> aqwPad[0x1C];
  xe::be<uint8_t> One;
  uint8_t Salt[0xA];
  uint8_t Hash[0x14];
  xe::be<uint8_t> End;
};
static_assert_size(XECRYPT_SIG, 0x100);  // size 256

// Keys
// TODO: Array of keys we need

// Console Serial Number Key - unimplemented
static constexpr uint8_t key14[] = {'0', '1', '2', '3', '4', '5',
                                    '6', '7', '8', '9', '1', '0'};  // string

// Retail key 0x19
static constexpr uint8_t key19[] = {0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1,
                                    0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3,
                                    0xAD, 0x47, 0xEB, 0xF3};

// Pirs Public Key
struct XECRYPT_RSAPUB_2048 {
  XECRYPT_RSA Rsa;
  xe::be<uint64_t> aqwM[0x20];
};
static_assert_size(XECRYPT_RSAPUB_2048, 0x110);

static constexpr uint8_t key39[] = {                 // pirs_retail_public
    0x00, 0x00, 0x00, 0x20,                          // cqw
    0x00, 0x00, 0x00, 0x03,                          // dwPubExp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // qwReserved
    // aqwM
    0xE6, 0x3B, 0x32, 0xB2, 0x8D, 0x9E, 0x9E, 0xE7, 0x9D, 0xFC, 0x5C, 0x72,
    0x41, 0x94, 0x58, 0x47, 0xDE, 0x0D, 0x18, 0x40, 0x72, 0xD6, 0xE3, 0x46,
    0x8E, 0xBA, 0x8E, 0xBC, 0x1A, 0x90, 0xAC, 0x20, 0xBA, 0x03, 0x85, 0xB5,
    0x1A, 0x3E, 0x25, 0xF9, 0xA6, 0x58, 0xEB, 0xB6, 0xA3, 0xC4, 0xA3, 0xEE,
    0xB2, 0xB0, 0xAE, 0x97, 0x69, 0xEB, 0xFE, 0x71, 0xFC, 0x02, 0xAB, 0x77,
    0xBA, 0xC8, 0xE6, 0x74, 0xE6, 0x7C, 0x63, 0x0E, 0xAF, 0x4C, 0xF7, 0xE7,
    0x11, 0x4A, 0x80, 0x24, 0x72, 0x05, 0x7A, 0x63, 0xD0, 0xF8, 0x91, 0x02,
    0xA6, 0xE7, 0x7D, 0x77, 0xC5, 0xA7, 0x9B, 0x08, 0x11, 0x2E, 0xA0, 0x64,
    0x45, 0x60, 0x46, 0xBC, 0x36, 0xE1, 0x17, 0x71, 0xBE, 0x66, 0x49, 0x2F,
    0xAE, 0x20, 0xA4, 0x76, 0x9C, 0x27, 0x51, 0xCF, 0x4B, 0x34, 0x7A, 0x35,
    0xBC, 0xA4, 0xAA, 0x1C, 0x47, 0x4B, 0xF4, 0x97, 0x22, 0x4E, 0x13, 0x24,
    0xD3, 0xC1, 0x57, 0xDF, 0x4D, 0x84, 0xB9, 0x18, 0x97, 0x99, 0xAC, 0x00,
    0xB3, 0x3D, 0x03, 0x25, 0x60, 0xC8, 0x7A, 0x59, 0xFE, 0x48, 0xFF, 0x28,
    0x3D, 0x10, 0xBB, 0x9E, 0x09, 0x06, 0x2A, 0x61, 0x20, 0x2C, 0xF8, 0x72,
    0xEB, 0x87, 0xE6, 0xD1, 0xFB, 0xB3, 0x66, 0xFC, 0x4A, 0x02, 0xAE, 0xD4,
    0xD8, 0x37, 0xCF, 0xA6, 0x32, 0x25, 0x79, 0x36, 0x0E, 0xF4, 0xED, 0x19,
    0xA2, 0x10, 0x27, 0x96, 0x2F, 0x9F, 0xA9, 0x3D, 0xA4, 0x37, 0x30, 0x11,
    0x51, 0x83, 0xBD, 0xF7, 0xC7, 0xE5, 0xCE, 0xAA, 0xEC, 0xDE, 0x48, 0xA0,
    0x84, 0xF7, 0xB0, 0xF6, 0x4B, 0x8E, 0xF0, 0x89, 0xBD, 0x47, 0x7C, 0x90,
    0xDD, 0x88, 0x12, 0x17, 0x40, 0xD2, 0x4E, 0xA6, 0xC6, 0x11, 0x04, 0x1B,
    0x57, 0xA8, 0x68, 0xB4, 0x61, 0xF4, 0x1B, 0xC6, 0x8B, 0xE8, 0xD9, 0x20,
    0xF2, 0x05, 0xE0, 0x70};

// Wharf DEV STAND-IN for CONSTANT_XMACS_KEY (0x41). Not a symmetric key: an
// XECRYPT_RSAPUB_2048 (cqw 0x20, exponent 0x10001, modulus in the 360 limb
// layout). XAM's Kerberos client (81946308, used for the XEMACS/MACS AS-REQ at
// the start of the Live logon) fetches it with XeKeysGetKey(0x41, buf, 0x110),
// requires cqw == 0x20 and length 0x110, and RSA-encrypts the client's
// pre-authentication secret with it; the machine-account server decrypts with
// the private key. A real console holds Microsoft's constant, whose private
// half only Microsoft has, so this is the one input OpenPak's own x360 server
// cannot share with an unmodified console: the console's constant 0x41 must be
// replaced with the OpenPak public key (console-side patch) or the server must
// accept both. The matching private key is OpenPak dev material kept at
// scratch/wharf/keys/xmacs-dev-private.pem (never part of this tree).
static constexpr uint8_t key41[] = {
    0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x81, 0xC4, 0x0D, 0xAB, 0xFE, 0xA3, 0x0B, 0x19,
    0x9D, 0x93, 0x48, 0xE4, 0x14, 0x97, 0x2F, 0x51, 0x1F, 0xFF, 0x62, 0xA0,
    0x8D, 0x56, 0x30, 0x2D, 0x1D, 0xDE, 0x08, 0xEF, 0xCB, 0x6C, 0x9C, 0x8E,
    0x70, 0xEF, 0x8E, 0xD1, 0x1B, 0xDB, 0x2F, 0xA9, 0x12, 0x60, 0xE5, 0x2C,
    0x9E, 0x4B, 0x28, 0x86, 0x4C, 0xBE, 0x54, 0x19, 0x18, 0x9F, 0xCF, 0x2B,
    0x5A, 0x1E, 0xB4, 0x7A, 0x22, 0x90, 0x23, 0x62, 0x2B, 0xFF, 0x55, 0x84,
    0xCA, 0xFE, 0x34, 0x0C, 0xC7, 0x9F, 0x90, 0x7F, 0x0C, 0xA7, 0x39, 0xC8,
    0x67, 0x43, 0x58, 0xDC, 0x6A, 0xD4, 0xC0, 0x62, 0x76, 0x5E, 0xE3, 0x03,
    0x3F, 0x25, 0xCA, 0x4F, 0x50, 0x6F, 0xE9, 0xCB, 0xFB, 0x57, 0x4E, 0xCC,
    0x8B, 0xFF, 0x76, 0x2F, 0x6F, 0x61, 0xDD, 0x37, 0x9B, 0xAA, 0xCA, 0x2A,
    0x1E, 0xD9, 0x46, 0x98, 0x37, 0xBF, 0x29, 0xE7, 0xC5, 0x9F, 0x1D, 0x47,
    0xDC, 0x57, 0xCF, 0x18, 0x39, 0xA1, 0xCC, 0x51, 0x2C, 0xEF, 0xAF, 0x50,
    0xD3, 0xBF, 0xBC, 0x34, 0x75, 0x77, 0xA3, 0x8C, 0x10, 0x65, 0xC1, 0x41,
    0x0E, 0x81, 0x6F, 0xE3, 0x6B, 0x03, 0xD9, 0xFF, 0x87, 0xD0, 0xB6, 0x2E,
    0x77, 0x83, 0x2F, 0xF6, 0xC9, 0xF3, 0xCE, 0x23, 0xD3, 0x8C, 0x8F, 0xF0,
    0xDA, 0x5F, 0x34, 0x8C, 0x0E, 0xA4, 0x7F, 0x28, 0x1D, 0xEE, 0x6E, 0x03,
    0x36, 0x5C, 0x7E, 0x93, 0xCD, 0x50, 0xCB, 0x38, 0xF8, 0x5A, 0xD4, 0xC1,
    0x41, 0x0E, 0x66, 0x8B, 0x6D, 0xE4, 0xBE, 0x60, 0x87, 0x21, 0x71, 0x65,
    0x8F, 0x68, 0x19, 0xE3, 0xB5, 0x86, 0x90, 0x3F, 0xBF, 0x93, 0x93, 0x4C,
    0x36, 0x87, 0x88, 0x56, 0x2D, 0x74, 0xDA, 0x42, 0x32, 0x28, 0x4F, 0xE0,
    0xBE, 0x1B, 0x6A, 0xE2, 0xA0, 0xFA, 0xC2, 0x86, 0x27, 0xC5, 0x1F, 0xE8,
    0xAF, 0xF4, 0x07, 0x97, 0xD6, 0x30, 0xD2, 0x52};
static_assert(sizeof(key41) == 0x110);

const static std::map<uint16_t, std::span<const uint8_t>> key_vault = {
    {0x14, key14},
    {0x19, key19},
    {0x39, key39},
    {0x41, key41},
};

enum X_KEY_INDEX : uint32_t {
  MANUFACTURING_MODE = 0x0,
  ALTERNATE_KEY_VAULT = 0x1,
  RESTRICTED_PRIVILEGES_FLAGS = 0x2,
  RESERVED_BYTE3 = 0x3,
  ODD_FEATURES = 0x4,
  ODD_AUTHTYPE = 0x5,
  RESTRICTED_HVEXT_LOADER = 0x6,
  POLICY_FLASH_SIZE = 0x7,
  POLICY_BUILTIN_USBMU_SIZE = 0x8,
  RESERVED_DWORD4 = 0x9,
  RESTRICTED_PRIVILEGES = 0xA,
  RESERVED_QWORD2 = 0xB,
  RESERVED_QWORD3 = 0xC,
  RESERVED_QWORD4 = 0xD,
  RESERVED_KEY1 = 0xE,
  RESERVED_KEY2 = 0xF,
  RESERVED_KEY3 = 0x10,
  RESERVED_KEY4 = 0x11,
  RESERVED_RANDOM_KEY1 = 0x12,
  RESERVED_RANDOM_KEY2 = 0x13,
  CONSOLE_SERIAL_NUMBER = 0x14,
  MOBO_SERIAL_NUMBER = 0x15,
  GAME_REGION = 0x16,
  CONSOLE_OBFUSCATION_KEY = 0x17,
  KEY_OBFUSCATION_KEY = 0x18,
  ROAMABLE_OBFUSCATION_KEY = 0x19,
  DVD_KEY = 0x1A,
  PRIMARY_ACTIVATION_KEY = 0x1B,
  SECONDARY_ACTIVATION_KEY = 0x1C,
  GLOBAL_DEVICE_2DES_KEY1 = 0x1D,
  GLOBAL_DEVICE_2DES_KEY2 = 0x1E,
  WIRELESS_CONTROLLER_MS_2DES_KEY1 = 0x1F,
  WIRELESS_CONTROLLER_MS_2DES_KEY2 = 0x20,
  WIRED_WEBCAM_MS_2DES_KEY1 = 0x21,
  WIRED_WEBCAM_MS_2DES_KEY2 = 0x22,
  WIRED_CONTROLLER_MS_2DES_KEY1 = 0x23,
  WIRED_CONTROLLER_MS_2DES_KEY2 = 0x24,
  MEMORY_UNIT_MS_2DES_KEY1 = 0x25,
  MEMORY_UNIT_MS_2DES_KEY2 = 0x26,
  OTHER_XSM3_DEVICE_MS_2DES_KEY1 = 0x27,
  OTHER_XSM3_DEVICE_MS_2DES_KEY2 = 0x28,
  WIRELESS_CONTROLLER_3P_2DES_KEY1 = 0x29,
  WIRELESS_CONTROLLER_3P_2DES_KEY2 = 0x2A,
  WIRED_WEBCAM_3P_2DES_KEY1 = 0x2B,
  WIRED_WEBCAM_3P_2DES_KEY2 = 0x2C,
  WIRED_CONTROLLER_3P_2DES_KEY1 = 0x2D,
  WIRED_CONTROLLER_3P_2DES_KEY2 = 0x2E,
  MEMORY_UNIT_3P_2DES_KEY1 = 0x2F,
  MEMORY_UNIT_3P_2DES_KEY2 = 0x30,
  OTHER_XSM3_DEVICE_3P_2DES_KEY1 = 0x31,
  OTHER_XSM3_DEVICE_3P_2DES_KEY2 = 0x32,
  CONSOLE_PRIVATE_KEY = 0x33,
  XEIKA_PRIVATE_KEY = 0x34,
  CARDEA_PRIVATE_KEY = 0x35,
  CONSOLE_CERTIFICATE = 0x36,
  XEIKA_CERTIFICATE = 0x37,
  CARDEA_CERTIFICATE = 0x38,
  MAX_KEY_INDEX = 0x39,
  // constant keys
  CONSTANT_PIRS_KEY = 0x39,
  CONSTANT_ALT_MASTER_KEY = 0x3A,
  CONSTANT_ALT_LIVE_KEY = 0x3B,
  CONSTANT_MASTER_KEY = 0x3C,
  CONSTANT_LIVE_KEY = 0x3D,
  CONSTANT_XB1_GREEN_KEY = 0x3E,
  CONSTANT_SATA_DISK_SECURITY_KEY = 0x3F,
  CONSTANT_DEVICE_REVOCATION_KEY = 0x40,
  CONSTANT_XMACS_KEY = 0x41,
  CONSTANT_REVOCATION_LIST_NONCE = 0x42,
  CONSTANT_CROSS_PLATFORM_SYSLINK_KEY = 0x43,
  // special keys
  SPECIAL_KEY_VAULT_SIGNATURE = 0x44,
  SPECIAL_SECROM_DIGEST = 0x45,
  SPECIAL_SECDATA = 0x46,
  SPECIAL_DVD_FIRMWARE_KEY = 0x47,
  SPECIAL_DEBUG_UNLOCK = 0x48,
  MAX_CONSTANT_INDEX = 0x49,
  // title keys
  TITLE_KEYS_BASE = 0xE0,
  TITLE_KEYS_LIMIT = 0xE8,
  TITLE_KEYS_RESET = 0xF0,
  // secured keys
  SECURED_DATA_BASE = 0x1000,
  SECURED_DATA_LIMIT = 0x2000,
};

// https://github.com/emoose/ExCrypt/blob/master/src/exkeys.cpp#L7
std::map<uint32_t, std::tuple<uint32_t, uint32_t>> X_Key_Properties = {
    {MANUFACTURING_MODE, {0x8, 0x1}},
    {ALTERNATE_KEY_VAULT, {0x9, 0x1}},
    {RESTRICTED_PRIVILEGES_FLAGS, {0xA, 0x1}},
    {RESERVED_BYTE3, {0xB, 0x1}},
    {ODD_FEATURES, {0xC, 0x2}},
    {ODD_AUTHTYPE, {0xE, 0x2}},
    {RESTRICTED_HVEXT_LOADER, {0x10, 0x4}},
    {POLICY_FLASH_SIZE, {0x14, 0x4}},
    {POLICY_BUILTIN_USBMU_SIZE, {0x18, 0x4}},
    {RESERVED_DWORD4, {0x1C, 0x4}},
    {RESTRICTED_PRIVILEGES, {0x20, 0x8}},
    {RESERVED_QWORD2, {0x28, 0x8}},
    {RESERVED_QWORD3, {0x30, 0x8}},
    {RESERVED_QWORD4, {0x38, 0x8}},
    {RESERVED_KEY1, {0x40, 0x10}},
    {RESERVED_KEY2, {0x50, 0x10}},
    {RESERVED_KEY3, {0x60, 0x10}},
    {RESERVED_KEY4, {0x70, 0x10}},
    {RESERVED_RANDOM_KEY1, {0x80, 0x10}},
    {RESERVED_RANDOM_KEY2, {0x90, 0x10}},
    {CONSOLE_SERIAL_NUMBER, {0xA0, 0xC}},
    {MOBO_SERIAL_NUMBER, {0xAC, 0xC}},
    {GAME_REGION, {0xB8, 0x2}},
    // 6 bytes padding
    {CONSOLE_OBFUSCATION_KEY, {0xC0, 0x10}},
    {KEY_OBFUSCATION_KEY, {0xD0, 0x10}},
    {ROAMABLE_OBFUSCATION_KEY, {0xE0, 0x10}},
    {DVD_KEY, {0xF0, 0x10}},
    {PRIMARY_ACTIVATION_KEY, {0x100, 0x18}},
    {SECONDARY_ACTIVATION_KEY, {0x118, 0x10}},
    {GLOBAL_DEVICE_2DES_KEY1, {0x128, 0x10}},
    {GLOBAL_DEVICE_2DES_KEY2, {0x138, 0x10}},
    {WIRELESS_CONTROLLER_MS_2DES_KEY1, {0x148, 0x10}},
    {WIRELESS_CONTROLLER_MS_2DES_KEY2, {0x158, 0x10}},
    {WIRED_WEBCAM_MS_2DES_KEY1, {0x168, 0x10}},
    {WIRED_WEBCAM_MS_2DES_KEY2, {0x178, 0x10}},
    {WIRED_CONTROLLER_MS_2DES_KEY1, {0x188, 0x10}},
    {WIRED_CONTROLLER_MS_2DES_KEY2, {0x198, 0x10}},
    {MEMORY_UNIT_MS_2DES_KEY1, {0x1A8, 0x10}},
    {MEMORY_UNIT_MS_2DES_KEY2, {0x1B8, 0x10}},
    {OTHER_XSM3_DEVICE_MS_2DES_KEY1, {0x1C8, 0x10}},
    {OTHER_XSM3_DEVICE_MS_2DES_KEY2, {0x1D8, 0x10}},
    {WIRELESS_CONTROLLER_3P_2DES_KEY1, {0x1E8, 0x10}},
    {WIRELESS_CONTROLLER_3P_2DES_KEY2, {0x1F8, 0x10}},
    {WIRED_WEBCAM_3P_2DES_KEY1, {0x208, 0x10}},
    {WIRED_WEBCAM_3P_2DES_KEY2, {0x218, 0x10}},
    {WIRED_CONTROLLER_3P_2DES_KEY1, {0x228, 0x10}},
    {WIRED_CONTROLLER_3P_2DES_KEY2, {0x238, 0x10}},
    {MEMORY_UNIT_3P_2DES_KEY1, {0x248, 0x10}},
    {MEMORY_UNIT_3P_2DES_KEY2, {0x258, 0x10}},
    {OTHER_XSM3_DEVICE_3P_2DES_KEY1, {0x268, 0x10}},
    {OTHER_XSM3_DEVICE_3P_2DES_KEY2, {0x278, 0x10}},
    {CONSOLE_PRIVATE_KEY, {0x288, 0x1D0}},
    {XEIKA_PRIVATE_KEY, {0x458, 0x390}},
    {CARDEA_PRIVATE_KEY, {0x7E8, 0x1D0}},
    {CONSOLE_CERTIFICATE, {0x9B8, 0x1A8}},
    {XEIKA_CERTIFICATE, {0xB60, 0x1288}},
    {SPECIAL_KEY_VAULT_SIGNATURE, {0x1DF8, 0x100}},
    {CARDEA_CERTIFICATE, {0x1EE8, 0x2108}},
    {CONSTANT_XMACS_KEY, {0x0, 0x110}},
};

static const uint8_t xe_key_obfuscation_key[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#pragma pack(push, 1)
struct XE_CONSOLE_ID {
  union {
    struct {
      uint8_t RefurbBits : 4;
      uint8_t ManufactureMonth : 4;
      uint32_t ManufactureYear : 4;
      uint32_t MacIndex3 : 8;
      uint32_t MacIndex4 : 8;
      uint32_t MacIndex5 : 8;
      uint32_t Crc : 4;
    };
    uint8_t Data[5];
  };
};
#pragma pack(pop)

struct X_CONSOLE_PUBLIC_KEY {
  uint8_t public_exponent[0x4];  // 0x0 sz:0x4
  uint8_t modulus[0x80];         // 0x4 sz:0x80
};  // size 132
static_assert_size(X_CONSOLE_PUBLIC_KEY, 0x84);

enum XConsoleType : uint32_t {
  Invalid = 0,
  Devkit = 1,
  Retail = 2,
  Testkit = 0x40000001,
  RecoveredDevkit = 0x80000001,
  Pre1888Devkit = 0x80000002
};

struct XE_CONSOLE_CERTIFICATE {
  xe::be<uint16_t> cert_size;               // 0x0 sz:0x2
  XE_CONSOLE_ID console_id;                 // 0x2 sz:0x5
  uint8_t console_part_number[11];          // 0x7 sz:0xB
  uint8_t reserved[4];                      // 0x12 sz:0x4
  xe::be<uint16_t> privileges;              // 0x16 sz:0x2
  xe::be<XConsoleType> console_type;        // 0x18 sz:0x4
  uint8_t manufacture_date[8];              // 0x1C sz:0x8
  X_CONSOLE_PUBLIC_KEY console_public_key;  // 0x24 sz:0x84
  XECRYPT_SIG signature;                    // 0xA8 sz:0x100
};  // size 424
static_assert_size(XE_CONSOLE_CERTIFICATE, 0x1A8);

struct XE_CONSOLE_SIGNATURE {
  XE_CONSOLE_CERTIFICATE console_certificate;
  uint8_t signature[0x80];
};
static_assert_size(XE_CONSOLE_SIGNATURE, 0x228);

void XeCryptRc4Key_entry(pointer_t<XECRYPT_RC4_STATE> rc4_ctx, lpvoid_t key,
                         dword_t key_size) {
  // Setup RC4 state
  rc4_ctx->i = rc4_ctx->j = 0;
  for (uint32_t x = 0; x < 0x100; x++) {
    rc4_ctx->S[x] = (uint8_t)x;
  }

  // A key of no bytes has nothing to schedule and would divide by zero.
  if (!key_size) {
    return;
  }
  uint32_t idx = 0;
  for (uint32_t x = 0; x < 0x100; x++) {
    idx = (idx + rc4_ctx->S[x] + key[x % key_size]) % 0x100;
    uint8_t temp = rc4_ctx->S[idx];
    rc4_ctx->S[idx] = rc4_ctx->S[x];
    rc4_ctx->S[x] = temp;
  }
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptRc4Key, kNone, kImplemented);

void XeCryptRc4Ecb_entry(pointer_t<XECRYPT_RC4_STATE> rc4_ctx, lpvoid_t data,
                         dword_t size) {
  // Crypt data
  for (uint32_t idx = 0; idx < size; idx++) {
    rc4_ctx->i = (rc4_ctx->i + 1) % 0x100;
    rc4_ctx->j = (rc4_ctx->j + rc4_ctx->S[rc4_ctx->i]) % 0x100;
    uint8_t temp = rc4_ctx->S[rc4_ctx->i];
    rc4_ctx->S[rc4_ctx->i] = rc4_ctx->S[rc4_ctx->j];
    rc4_ctx->S[rc4_ctx->j] = temp;

    uint8_t a = data[idx];
    uint8_t b =
        rc4_ctx->S[(rc4_ctx->S[rc4_ctx->i] + rc4_ctx->S[rc4_ctx->j]) % 0x100];
    data[idx] = (uint8_t)(a ^ b);
  }
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptRc4Ecb, kNone, kImplemented);

void XeCryptRc4_entry(lpvoid_t key, dword_t key_size, lpvoid_t data,
                      dword_t size) {
  XECRYPT_RC4_STATE rc4_ctx;
  XeCryptRc4Key_entry(&rc4_ctx, key, key_size);
  XeCryptRc4Ecb_entry(&rc4_ctx, data, size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptRc4, kNone, kImplemented);

void XeCryptShaInit_entry(pointer_t<XECRYPT_SHA_STATE> sha_state) {
  XeCryptShaInit(sha_state);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptShaInit, kNone, kImplemented);

void XeCryptShaUpdate_entry(pointer_t<XECRYPT_SHA_STATE> sha_state,
                            lpvoid_t input, dword_t input_size) {
  XeCryptShaUpdate(sha_state, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptShaUpdate, kNone, kImplemented);

void XeCryptShaFinal_entry(pointer_t<XECRYPT_SHA_STATE> sha_state,
                           pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptShaFinal(sha_state, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptShaFinal, kNone, kImplemented);

void XeCryptSha_entry(lpvoid_t input_1, dword_t input_1_size, lpvoid_t input_2,
                      dword_t input_2_size, lpvoid_t input_3,
                      dword_t input_3_size, lpvoid_t output,
                      dword_t output_size) {
  XeCryptSha(input_1.as<uint8_t*>(), input_1_size, input_2.as<uint8_t*>(),
             input_2_size, input_3.as<uint8_t*>(), input_3_size,
             output.as<uint8_t*>(), output_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha, kNone, kImplemented);

void XeCryptHmacShaInit_entry(pointer_t<XECRYPT_HMACSHA_STATE> sha_state_ptr,
                              lpvoid_t key_ptr, dword_t key_size) {
  XeCryptHmacShaInit(sha_state_ptr, key_ptr.as<uint8_t*>(), key_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacShaInit, kNone, kImplemented);

void XeCryptHmacShaUpdate_entry(pointer_t<XECRYPT_HMACSHA_STATE> sha_state_ptr,
                                lpvoid_t input, dword_t input_size) {
  XeCryptHmacShaUpdate(sha_state_ptr, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacShaUpdate, kNone, kImplemented);

void XeCryptHmacShaFinal_entry(pointer_t<XECRYPT_HMACSHA_STATE> sha_state_ptr,
                               pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptHmacShaFinal(sha_state_ptr, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacShaFinal, kNone, kImplemented);

void XeCryptMd5_entry(lpvoid_t input_1, dword_t input_1_size, lpvoid_t input_2,
                      dword_t input_2_size, lpvoid_t input_3,
                      dword_t input_3_size, lpvoid_t output,
                      dword_t output_size) {
  XeCryptMd5(input_1.as<uint8_t*>(), input_1_size, input_2.as<uint8_t*>(),
             input_2_size, input_3.as<uint8_t*>(), input_3_size,
             output.as<uint8_t*>(), output_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptMd5, kNone, kImplemented);

void XeCryptSha256Init_entry(pointer_t<XECRYPT_SHA256_STATE> sha_state) {
  XeCryptSha256Init(sha_state);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha256Init, kNone, kImplemented);

void XeCryptSha256Update_entry(pointer_t<XECRYPT_SHA256_STATE> sha_state,
                               lpvoid_t input, dword_t input_size) {
  XeCryptSha256Update(sha_state, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha256Update, kNone, kImplemented);

void XeCryptSha256Final_entry(pointer_t<XECRYPT_SHA256_STATE> sha_state,
                              pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptSha256Final(sha_state, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha256Final, kNone, kImplemented);

void XeCryptSha512Init_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state) {
  XeCryptSha512Init(sha_state);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha512Init, kNone, kImplemented);

void XeCryptSha512Update_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state,
                               lpvoid_t input, dword_t input_size) {
  XeCryptSha512Update(sha_state, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha512Update, kNone, kImplemented);

void XeCryptSha512Final_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state,
                              pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptSha512Final(sha_state, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha512Final, kNone, kImplemented);

void XeCryptSha384Init_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state) {
  XeCryptSha384Init(sha_state);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha384Init, kNone, kImplemented);

// Update is the SHA-512 block function on the same state.
void XeCryptSha384Update_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state,
                               lpvoid_t input, dword_t input_size) {
  XeCryptSha512Update(sha_state, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha384Update, kNone, kImplemented);

void XeCryptSha384Final_entry(pointer_t<XECRYPT_SHA512_STATE> sha_state,
                              pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptSha384Final(sha_state, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptSha384Final, kNone, kImplemented);

void XeCryptMd5Init_entry(pointer_t<XECRYPT_MD5_STATE> md5_state) {
  XeCryptMd5Init(md5_state);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptMd5Init, kNone, kImplemented);

void XeCryptMd5Update_entry(pointer_t<XECRYPT_MD5_STATE> md5_state,
                            lpvoid_t input, dword_t input_size) {
  XeCryptMd5Update(md5_state, input.as<uint8_t*>(), input_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptMd5Update, kNone, kImplemented);

void XeCryptMd5Final_entry(pointer_t<XECRYPT_MD5_STATE> md5_state,
                           pointer_t<uint8_t> out, dword_t out_size) {
  XeCryptMd5Final(md5_state, out, out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptMd5Final, kNone, kImplemented);

// Byteswaps each 8 bytes
void XeCryptBnQw_SwapDwQwLeBe_entry(pointer_t<uint64_t> qw_inp,
                                    pointer_t<uint64_t> qw_out, dword_t size) {
  xe::copy_and_swap<uint64_t>(qw_out, qw_inp, size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnQw_SwapDwQwLeBe, kNone, kImplemented);

dword_result_t XeCryptBnQwNeRsaPubCrypt_entry(pointer_t<uint64_t> qw_a,
                                              pointer_t<uint64_t> qw_b,
                                              pointer_t<XECRYPT_RSA> rsa) {
  uint32_t num_qwords = rsa->size;
  uint32_t exponent = rsa->public_exponent;
  const uint8_t* input_bytes = reinterpret_cast<const uint8_t*>(&qw_a[0]);
  uint8_t* output_bytes = reinterpret_cast<uint8_t*>(&qw_b[0]);
  const uint8_t* mod_bytes =
      reinterpret_cast<const uint8_t*>(&rsa[1]);  // modulus follows header

  return XeCryptBnQwNeRsaPubCrypt(input_bytes, output_bytes, mod_bytes,
                                  num_qwords, exponent);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnQwNeRsaPubCrypt, kNone, kImplemented);

dword_result_t XeCryptBnQwBeSigVerify_entry(pointer_t<XECRYPT_SIG> sig,
                                            lpvoid_t hash, lpstring_t salt,
                                            pointer_t<XECRYPT_RSA> rsa) {
  // hash from XeCryptRotSumSha
  // known salts are "XBOX360SVC", "XBOX360XTT", "TDBXBOX36O"
  return true;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnQwBeSigVerify, kNone, kStub);

// The null group is the console's 768-bit Live group. Custom group
// descriptors are separate from the fixed group used by XAM's network stack.
dword_result_t XeCryptBnDwLeDhModExp_entry(lpvoid_t base, lpvoid_t exponent,
                                           lpvoid_t output, lpvoid_t group) {
  if (group) {
    XELOGW("XeCryptBnDwLeDhModExp: custom group is not implemented");
    return 0;
  }
  return LiveDhModExp(base ? base.as<uint8_t*>() : nullptr,
                      exponent ? exponent.as<uint8_t*>() : nullptr,
                      output ? output.as<uint8_t*>() : nullptr);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnDwLeDhModExp, kNone, kSketchy);

dword_result_t XeCryptBnDwLeDhInvalBase_entry(lpvoid_t base, lpvoid_t group) {
  if (group) return 1;
  return LiveDhInvalidBase(base.as<uint8_t*>()) ? 1 : 0;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnDwLeDhInvalBase, kNone, kSketchy);

dword_result_t XeCryptBnDwLeDhEqualBase_entry(lpvoid_t base, lpvoid_t group) {
  if (group) return 0;
  if (!base) return 1;
  const auto* bytes = base.as<uint8_t*>();
  if (bytes[0] != 2) return 0;
  for (size_t i = 1; i < 96; ++i) if (bytes[i]) return 0;
  return 1;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnDwLeDhEqualBase, kNone, kSketchy);

dword_result_t XeCryptBnDwLePkcs1Verify_entry(lpvoid_t hash, lpvoid_t sig,
                                              dword_t size) {
  // BOOL return value
  return 1;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptBnDwLePkcs1Verify, kNone, kStub);

// Real random bytes: XAM draws values until one is not taken (ports, ids) and
// spins forever on a constant.
void XeCryptRandom_entry(lpvoid_t buf, dword_t buf_size) {
  static std::mutex mutex;
  static std::mt19937 rng{std::random_device{}()};
  std::lock_guard<std::mutex> lock(mutex);
  auto* out = buf.as<uint8_t*>();
  for (uint32_t i = 0; i < buf_size; ++i) {
    out[i] = static_cast<uint8_t>(rng());
  }
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptRandom, kNone, kStub);

void XeCryptDesKey_entry(pointer_t<XECRYPT_DES_STATE> state_ptr, lpvoid_t key) {
  XeCryptDesKey(state_ptr, key.as<uint8_t*>());
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDesKey, kNone, kImplemented);

void XeCryptDesEcb_entry(pointer_t<XECRYPT_DES_STATE> state_ptr, lpvoid_t inp,
                         lpvoid_t out, dword_t encrypt) {
  XeCryptDesEcb(state_ptr, inp.as<uint8_t*>(), out.as<uint8_t*>(),
                encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDesEcb, kNone, kImplemented);

void XeCryptDesCbc_entry(pointer_t<XECRYPT_DES_STATE> state_ptr, lpvoid_t inp,
                         dword_t inp_size, lpvoid_t out, lpvoid_t feed,
                         dword_t encrypt) {
  XeCryptDesCbc(state_ptr, inp.as<uint8_t*>(), inp_size, out.as<uint8_t*>(),
                feed.as<uint8_t*>(), encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDesCbc, kNone, kImplemented);

// Sets bit 0 to make the parity odd
void XeCryptDesParity_entry(lpvoid_t inp, dword_t inp_size, lpvoid_t out_ptr) {
  XeCryptDesParity(inp.as<uint8_t*>(), inp_size, out_ptr.as<uint8_t*>());
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDesParity, kNone, kImplemented);

void XeCryptDes3Key_entry(pointer_t<XECRYPT_DES3_STATE> state_ptr,
                          lpvoid_t key) {
  XeCryptDes3Key(state_ptr, key.as<uint8_t*>());
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDes3Key, kNone, kImplemented);

void XeCryptDes3Ecb_entry(pointer_t<XECRYPT_DES3_STATE> state_ptr, lpvoid_t inp,
                          lpvoid_t out, dword_t encrypt) {
  XeCryptDes3Ecb(state_ptr, inp.as<uint8_t*>(), out.as<uint8_t*>(),
                 encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDes3Ecb, kNone, kImplemented);

void XeCryptDes3Cbc_entry(pointer_t<XECRYPT_DES3_STATE> state_ptr, lpvoid_t inp,
                          dword_t inp_size, lpvoid_t out, lpvoid_t feed,
                          dword_t encrypt) {
  // DES can only do 8-byte chunks at a time!
  assert_true(inp_size % 8 == 0);

  XeCryptDes3Cbc(state_ptr, inp.as<uint8_t*>(), inp_size, out.as<uint8_t*>(),
                 feed.as<uint8_t*>(), encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptDes3Cbc, kNone, kImplemented);

void XeCryptAesKey_entry(pointer_t<XECRYPT_AES_STATE> state_ptr, lpvoid_t key) {
  XeCryptAesKey(state_ptr, key.as<uint8_t*>());
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesKey, kNone, kImplemented);

void XeCryptAesEcb_entry(pointer_t<XECRYPT_AES_STATE> state_ptr,
                         lpvoid_t inp_ptr, lpvoid_t out_ptr, dword_t encrypt) {
  XeCryptAesEcb(state_ptr, inp_ptr.as<uint8_t*>(), out_ptr.as<uint8_t*>(),
                encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesEcb, kNone, kImplemented);

void XeCryptAesCbc_entry(pointer_t<XECRYPT_AES_STATE> state_ptr,
                         lpvoid_t inp_ptr, dword_t inp_size, lpvoid_t out_ptr,
                         lpvoid_t feed_ptr, dword_t encrypt) {
  XeCryptAesCbc(state_ptr, inp_ptr.as<uint8_t*>(), inp_size,
                out_ptr.as<uint8_t*>(), feed_ptr.as<uint8_t*>(), encrypt != 0);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesCbc, kNone, kImplemented);

// The 17559 kernel's variable-key-size AES (128/192/256): XAM's TLS provider
// encrypts and decrypts its records with these. The schedule is opaque to the
// guest (XAM only passes it back), so Wharf keeps the raw key in it and
// expands it per call: u32 key size in bytes, then the key.
struct X_AES_SCHEDULE {
  xe::be<uint32_t> key_size;
  uint8_t key[32];
};

dword_result_t XeCryptAesCreateKeySchedule_entry(lpvoid_t key,
                                                 dword_t key_size,
                                                 pointer_t<X_AES_SCHEDULE> sched) {
  if (!sched || !key ||
      (key_size != 16 && key_size != 24 && key_size != 32)) {
    return X_STATUS_INVALID_PARAMETER;
  }
  sched->key_size = static_cast<uint32_t>(key_size);
  std::memset(sched->key, 0, sizeof(sched->key));
  std::memcpy(sched->key, key.as<uint8_t*>(), key_size);
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesCreateKeySchedule, kNone, kImplemented);

static bool AesScheduleContext(const X_AES_SCHEDULE* sched, bool encrypt,
                               mbedtls_aes_context* ctx) {
  uint32_t n = sched->key_size;
  if (n != 16 && n != 24 && n != 32) {
    XELOGE("XeCryptAes: schedule with key size {}", n);
    return false;
  }
  mbedtls_aes_init(ctx);
  return (encrypt ? mbedtls_aes_setkey_enc(ctx, sched->key, n * 8)
                  : mbedtls_aes_setkey_dec(ctx, sched->key, n * 8)) == 0;
}

static void AesScheduleOne(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                           lpvoid_t out, bool encrypt) {
  mbedtls_aes_context ctx;
  if (!AesScheduleContext(sched, encrypt, &ctx)) return;
  mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                        inp.as<uint8_t*>(), out.as<uint8_t*>());
  mbedtls_aes_free(&ctx);
}

void XeCryptAesEncryptOne_entry(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                                lpvoid_t out) {
  AesScheduleOne(sched, inp, out, true);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesEncryptOne, kNone, kImplemented);

void XeCryptAesDecryptOne_entry(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                                lpvoid_t out) {
  AesScheduleOne(sched, inp, out, false);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesDecryptOne, kNone, kImplemented);

// CBC over whole blocks; feed is the IV in and the last ciphertext block out,
// as with XeCryptAesCbc.
static void AesScheduleCbc(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                           dword_t inp_size, lpvoid_t out, lpvoid_t feed,
                           bool encrypt) {
  mbedtls_aes_context ctx;
  if (!AesScheduleContext(sched, encrypt, &ctx)) return;
  uint32_t n = inp_size & ~15u;
  if (n) {
    mbedtls_aes_crypt_cbc(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                          n, feed.as<uint8_t*>(), inp.as<uint8_t*>(),
                          out.as<uint8_t*>());
  }
  mbedtls_aes_free(&ctx);
}

void XeCryptAesCbcEncrypt_entry(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                                dword_t inp_size, lpvoid_t out, lpvoid_t feed) {
  AesScheduleCbc(sched, inp, inp_size, out, feed, true);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesCbcEncrypt, kNone, kImplemented);

void XeCryptAesCbcDecrypt_entry(pointer_t<X_AES_SCHEDULE> sched, lpvoid_t inp,
                                dword_t inp_size, lpvoid_t out, lpvoid_t feed) {
  AesScheduleCbc(sched, inp, inp_size, out, feed, false);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptAesCbcDecrypt, kNone, kImplemented);

void XeCryptHmacSha_entry(lpvoid_t key, dword_t key_size_in, lpvoid_t inp_1,
                          dword_t inp_1_size, lpvoid_t inp_2,
                          dword_t inp_2_size, lpvoid_t inp_3,
                          dword_t inp_3_size, lpvoid_t out, dword_t out_size) {
  XeCryptHmacSha(key.as<uint8_t*>(), key_size_in, inp_1.as<uint8_t*>(),
                 inp_1_size, inp_2.as<uint8_t*>(), inp_2_size,
                 inp_3.as<uint8_t*>(), inp_3_size, out.as<uint8_t*>(),
                 out_size);
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacSha, kNone, kImplemented);

dword_result_t XeCryptHmacShaVerify_entry(
    lpvoid_t key, dword_t key_size, lpvoid_t inp_1, dword_t inp_1_size,
    lpvoid_t inp_2, dword_t inp_2_size, lpvoid_t inp_3, dword_t inp_3_size,
    lpvoid_t expected, dword_t expected_size) {
  if (!expected || !expected_size || expected_size > 20) return 0;
  uint8_t digest[20];
  XeCryptHmacSha(key.as<uint8_t*>(), key_size, inp_1.as<uint8_t*>(),
                inp_1_size, inp_2.as<uint8_t*>(), inp_2_size,
                inp_3.as<uint8_t*>(), inp_3_size, digest, sizeof(digest));
  uint8_t difference = 0;
  for (uint32_t i = 0; i < expected_size; ++i) {
    difference |= digest[i] ^ expected.as<uint8_t*>()[i];
  }
  return difference == 0;
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacShaVerify, kNone, kImplemented);


// HMAC-MD5 over the three optional inputs concatenated, same argument layout
// as XeCryptHmacSha. XAM's XNet uses it right after a DNS answer.
void XeCryptHmacMd5_entry(lpvoid_t key, dword_t key_size, lpvoid_t inp_1,
                          dword_t inp_1_size, lpvoid_t inp_2,
                          dword_t inp_2_size, lpvoid_t inp_3,
                          dword_t inp_3_size, lpvoid_t out, dword_t out_size) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const auto* info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
  uint8_t digest[16] = {};
  if (mbedtls_md_setup(&ctx, info, 1) == 0 &&
      mbedtls_md_hmac_starts(&ctx, key.as<uint8_t*>(), key_size) == 0) {
    if (inp_1 && inp_1_size) {
      mbedtls_md_hmac_update(&ctx, inp_1.as<uint8_t*>(), inp_1_size);
    }
    if (inp_2 && inp_2_size) {
      mbedtls_md_hmac_update(&ctx, inp_2.as<uint8_t*>(), inp_2_size);
    }
    if (inp_3 && inp_3_size) {
      mbedtls_md_hmac_update(&ctx, inp_3.as<uint8_t*>(), inp_3_size);
    }
    mbedtls_md_hmac_finish(&ctx, digest);
  }
  mbedtls_md_free(&ctx);
  if (out) {
    std::memcpy(out.as<uint8_t*>(), digest, std::min<uint32_t>(out_size, 16));
  }
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptHmacMd5, kNone, kImplemented);


// ---------------------------------------------------------------------------
// Wharf DEV console identity. A real console owns an RSA-1024 console key
// (keyvault 0x33), a Microsoft-signed console certificate (0x36, 0x1A8 bytes),
// a console id/serial and the console obfuscation key (0x17). The OpenPak
// console patch gives real consoles the same material signed by the OpenPak
// console CA. Wharf creates its own on first start, in
// <storage_root>/wharf-console/identity.txt: a fresh RSA-1024 key, a random id,
// serial and 0x17 key, and a certificate issued by the dev CA named by
// --console_ca_key (OpenPak dev material, never part of this tree). XAM sends
// the certificate and a signature made with the console key in the MACS AS-REQ
// (XeKeysConsolePrivateKeySign), the KDC verifies the chain to the OpenPak CA.
//
// Formats (all big-endian byte strings; DEV choices, the real Microsoft ones
// differ in the hash function only):
//   certificate (0x1A8): the XE_CONSOLE_CERTIFICATE above; cert_size 0x1A8,
//     public key = exponent[4] + modulus[0x80], signature[0x100] =
//     RSASSA-PSS (SHA-1, MGF1-SHA-1, salt 10 bytes, 2048-bit CA key) over
//     bytes [0, 0xA8) of the certificate (Microsoft: RotSumSha + the same
//     PSS-like 'XECRYPT_SIG' layout).
//   console signature (0x80): RSASSA-PKCS1-v1_5 with SHA-1 over the 20-byte
//     hash XAM passes (the digest is not hashed again).
// ---------------------------------------------------------------------------
namespace console_identity {

struct Mpi {
  mbedtls_mpi v;
  Mpi() { mbedtls_mpi_init(&v); }
  ~Mpi() { mbedtls_mpi_free(&v); }
  Mpi(const Mpi&) = delete;
  Mpi& operator=(const Mpi&) = delete;
};

using Bytes = std::vector<uint8_t>;

int RandomBytes(void*, unsigned char* out, size_t len) {
  static std::random_device rd;
  for (size_t i = 0; i < len; i++) out[i] = uint8_t(rd());
  return 0;
}

std::string ToHex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < n; i++) {
    out += d[p[i] >> 4];
    out += d[p[i] & 15];
  }
  return out;
}

Bytes FromHex(const std::string& s) {
  Bytes out;
  auto nib = [](char c) -> int {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
  };
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    const int a = nib(s[i]), b = nib(s[i + 1]);
    if (a < 0 || b < 0) return {};
    out.push_back(uint8_t(a << 4 | b));
  }
  return out;
}

bool IsProbablePrime(const mbedtls_mpi& n) {
  static const int kSmall[] = {2,  3,  5,  7,  11, 13, 17, 19, 23, 29, 31,
                               37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
                               83, 89, 97, 101, 103, 107, 109, 113};
  for (int sp : kSmall) {
    mbedtls_mpi_uint r;
    if (mbedtls_mpi_mod_int(&r, &n, sp) != 0) return false;
    if (r == 0) return mbedtls_mpi_cmp_int(&n, sp) == 0;
  }
  Mpi n1, d, a, x, two;
  mbedtls_mpi_sub_int(&n1.v, &n, 1);
  mbedtls_mpi_copy(&d.v, &n1.v);
  const size_t s = mbedtls_mpi_lsb(&d.v);
  mbedtls_mpi_shift_r(&d.v, s);
  mbedtls_mpi_lset(&two.v, 2);
  const size_t nbytes = mbedtls_mpi_size(&n);
  for (int round = 0; round < 24; round++) {
    mbedtls_mpi_fill_random(&a.v, nbytes, RandomBytes, nullptr);
    mbedtls_mpi_mod_mpi(&a.v, &a.v, &n1.v);
    if (mbedtls_mpi_cmp_int(&a.v, 2) < 0) mbedtls_mpi_lset(&a.v, 2);
    mbedtls_mpi_exp_mod(&x.v, &a.v, &d.v, &n, nullptr);
    if (mbedtls_mpi_cmp_int(&x.v, 1) == 0 ||
        mbedtls_mpi_cmp_mpi(&x.v, &n1.v) == 0) {
      continue;
    }
    bool composite = true;
    for (size_t i = 1; i < s; i++) {
      mbedtls_mpi_exp_mod(&x.v, &x.v, &two.v, &n, nullptr);
      if (mbedtls_mpi_cmp_mpi(&x.v, &n1.v) == 0) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

// A prime of exactly |bits| bits with gcd(p - 1, 65537) == 1.
void GenPrime(Mpi& p, size_t bits) {
  for (;;) {
    mbedtls_mpi_fill_random(&p.v, bits / 8, RandomBytes, nullptr);
    mbedtls_mpi_set_bit(&p.v, bits - 1, 1);
    mbedtls_mpi_set_bit(&p.v, bits - 2, 1);
    mbedtls_mpi_set_bit(&p.v, 0, 1);
    mbedtls_mpi_uint r;
    mbedtls_mpi_mod_int(&r, &p.v, 65537);
    if (r == 1) continue;
    if (IsProbablePrime(p.v)) return;
  }
}

struct RsaKey {
  Bytes n, d;  // big-endian, equal length
};

RsaKey GenerateRsa(size_t bits) {
  Mpi p, q, n, phi, e, d, p1, q1;
  mbedtls_mpi_lset(&e.v, 65537);
  for (;;) {
    GenPrime(p, bits / 2);
    GenPrime(q, bits / 2);
    if (mbedtls_mpi_cmp_mpi(&p.v, &q.v) == 0) continue;
    mbedtls_mpi_mul_mpi(&n.v, &p.v, &q.v);
    if (mbedtls_mpi_bitlen(&n.v) != bits) continue;
    mbedtls_mpi_sub_int(&p1.v, &p.v, 1);
    mbedtls_mpi_sub_int(&q1.v, &q.v, 1);
    mbedtls_mpi_mul_mpi(&phi.v, &p1.v, &q1.v);
    if (mbedtls_mpi_inv_mod(&d.v, &e.v, &phi.v) != 0) continue;
    break;
  }
  RsaKey k;
  k.n.resize(bits / 8);
  k.d.resize(bits / 8);
  mbedtls_mpi_write_binary(&n.v, k.n.data(), k.n.size());
  mbedtls_mpi_write_binary(&d.v, k.d.data(), k.d.size());
  return k;
}

// m^d mod n, big-endian in and out, |n| bytes.
Bytes RsaPrivate(const RsaKey& k, const Bytes& in) {
  Mpi n, d, m, r;
  Bytes out(k.n.size());
  if (mbedtls_mpi_read_binary(&n.v, k.n.data(), k.n.size()) ||
      mbedtls_mpi_read_binary(&d.v, k.d.data(), k.d.size()) ||
      mbedtls_mpi_read_binary(&m.v, in.data(), in.size()) ||
      mbedtls_mpi_exp_mod(&r.v, &m.v, &d.v, &n.v, nullptr) ||
      mbedtls_mpi_write_binary(&r.v, out.data(), out.size())) {
    return {};
  }
  return out;
}

void Sha1(const uint8_t* p, size_t n, uint8_t out[20]) {
  mbedtls_sha1(p, n, out);
}

Bytes Mgf1(const uint8_t* seed, size_t seed_len, size_t len) {
  Bytes out;
  for (uint32_t i = 0; out.size() < len; i++) {
    Bytes in(seed, seed + seed_len);
    for (int s = 24; s >= 0; s -= 8) in.push_back(uint8_t(i >> s));
    uint8_t h[20];
    Sha1(in.data(), in.size(), h);
    out.insert(out.end(), h, h + 20);
  }
  out.resize(len);
  return out;
}

// RSASSA-PSS, SHA-1, MGF1-SHA-1, 10-byte salt, emBits = modulus bits - 1.
Bytes PssSign(const RsaKey& ca, const uint8_t* msg, size_t msg_len) {
  const size_t em_len = ca.n.size();
  uint8_t mhash[20], salt[10], h[20];
  Sha1(msg, msg_len, mhash);
  RandomBytes(nullptr, salt, sizeof(salt));
  Bytes mp(8, 0);
  mp.insert(mp.end(), mhash, mhash + 20);
  mp.insert(mp.end(), salt, salt + 10);
  Sha1(mp.data(), mp.size(), h);
  Bytes db(em_len - 21, 0);
  db[db.size() - 11] = 1;
  std::memcpy(&db[db.size() - 10], salt, 10);
  const Bytes mask = Mgf1(h, 20, db.size());
  for (size_t i = 0; i < db.size(); i++) db[i] ^= mask[i];
  db[0] &= 0x7F;  // emBits = 8 * em_len - 1
  Bytes em = db;
  em.insert(em.end(), h, h + 20);
  em.push_back(0xBC);
  return RsaPrivate(ca, em);
}

// RSASSA-PKCS1-v1_5 over an existing SHA-1 digest.
Bytes Pkcs1Sign(const RsaKey& k, const uint8_t* digest20) {
  static const uint8_t kInfo[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                  0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
  const size_t len = k.n.size();
  Bytes em(len, 0xFF);
  em[0] = 0x00;
  em[1] = 0x01;
  const size_t t = sizeof(kInfo) + 20;
  em[len - t - 1] = 0x00;
  std::memcpy(&em[len - t], kInfo, sizeof(kInfo));
  std::memcpy(&em[len - 20], digest20, 20);
  return RsaPrivate(k, em);
}

struct Identity {
  bool ready = false;
  RsaKey key;
  uint8_t console_id[5] = {};
  char serial[12] = {};
  char id_digits[12] = {};
  uint8_t obf_key[16] = {};
  Bytes cert;  // 0x1A8
};

std::string Field(const std::string& text, const char* name) {
  const std::string tag = std::string(name) + "=";
  size_t pos = 0;
  while (pos < text.size()) {
    size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    if (text.compare(pos, tag.size(), tag) == 0) {
      std::string v = text.substr(pos + tag.size(), eol - pos - tag.size());
      while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.pop_back();
      return v;
    }
    pos = eol + 1;
  }
  return {};
}

void DeriveDigits(Identity& id) {
  uint64_t v = 0;
  for (int i = 0; i < 5; i++) v = v << 8 | id.console_id[i];
  const std::string s = fmt::format("{:012}", v % 1000000000000ull);
  std::memcpy(id.id_digits, s.data(), 12);
}

bool BuildCert(Identity& id, const RsaKey& ca) {
  Bytes c(0x1A8, 0);
  c[0] = 0x01;
  c[1] = 0xA8;  // cert_size
  std::memcpy(&c[2], id.console_id, 5);
  std::memcpy(&c[7], "OPENPAKDEV", 10);  // console_part_number[11]
  const uint32_t type = 2;  // Retail
  c[0x18] = uint8_t(type >> 24);
  c[0x19] = uint8_t(type >> 16);
  c[0x1A] = uint8_t(type >> 8);
  c[0x1B] = uint8_t(type);
  const std::time_t t = std::time(nullptr);
  char date[16];
  std::strftime(date, sizeof(date), "%Y%m%d", std::gmtime(&t));
  std::memcpy(&c[0x1C], date, 8);
  c[0x24] = 0x00;  // public exponent 65537 (big-endian)
  c[0x25] = 0x01;
  c[0x26] = 0x00;
  c[0x27] = 0x01;
  std::memcpy(&c[0x28], id.key.n.data(), 0x80);
  const Bytes sig = PssSign(ca, c.data(), 0xA8);
  if (sig.size() != 0x100) return false;
  std::memcpy(&c[0xA8], sig.data(), 0x100);
  id.cert = c;
  return true;
}

Identity& Get() {
  static Identity id;
  static std::once_flag once;
  std::call_once(once, [] {
    const std::filesystem::path dir =
        kernel_state()->emulator()->storage_root() / "wharf-console";
    const std::filesystem::path file = dir / "identity.txt";
    std::string text;
    {
      std::ifstream in(file);
      std::stringstream ss;
      ss << in.rdbuf();
      text = ss.str();
    }
    bool dirty = false;
    const Bytes n = FromHex(Field(text, "n")), d = FromHex(Field(text, "d"));
    const Bytes cid = FromHex(Field(text, "id"));
    const Bytes ser = FromHex(Field(text, "serial"));
    const Bytes obf = FromHex(Field(text, "obf"));
    if (n.size() == 128 && d.size() == 128 && cid.size() == 5 &&
        ser.size() == 12 && obf.size() == 16) {
      id.key.n = n;
      id.key.d = d;
      std::memcpy(id.console_id, cid.data(), 5);
      std::memcpy(id.serial, ser.data(), 12);
      std::memcpy(id.obf_key, obf.data(), 16);
      id.cert = FromHex(Field(text, "cert"));
    } else {
      XELOGW("wharf console: creating a new dev console identity in {}", file);
      id.key = GenerateRsa(1024);
      RandomBytes(nullptr, id.console_id, 5);
      uint8_t r[12];
      RandomBytes(nullptr, r, 12);
      for (int i = 0; i < 12; i++) id.serial[i] = char('0' + r[i] % 10);
      RandomBytes(nullptr, id.obf_key, 16);
      id.cert.clear();
      dirty = true;
    }
    DeriveDigits(id);
    if (id.cert.size() != 0x1A8) {
      id.cert.clear();
      const std::string ca_path = cvars::console_ca_key;
      RsaKey ca;
      if (!ca_path.empty()) {
        std::ifstream in(ca_path);
        std::stringstream ss;
        ss << in.rdbuf();
        ca.n = FromHex(Field(ss.str(), "n"));
        ca.d = FromHex(Field(ss.str(), "d"));
      }
      if (ca.n.size() == 256 && ca.d.size() == 256 && BuildCert(id, ca)) {
        XELOGW("wharf console: certificate issued by the dev CA {}", ca_path);
        dirty = true;
      } else {
        // Header only, no valid signature: no server will accept this.
        id.cert.assign(0x1A8, 0);
        std::memcpy(&id.cert[2], id.console_id, 5);
        XELOGE(
            "wharf console: NO CERTIFICATE (set --console_ca_key to the dev "
            "console CA key file); the MACS logon will be refused");
      }
    }
    if (dirty) {
      std::error_code ec;
      std::filesystem::create_directories(dir, ec);
      std::ofstream out(file, std::ios::trunc);
      out << "# Wharf DEV console identity, per instance. Private key: keep out of any repo.\n"
          << "n=" << ToHex(id.key.n.data(), 128) << "\n"
          << "d=" << ToHex(id.key.d.data(), 128) << "\n"
          << "id=" << ToHex(id.console_id, 5) << "\n"
          << "serial=" << ToHex(reinterpret_cast<uint8_t*>(id.serial), 12)
          << "\n"
          << "obf=" << ToHex(id.obf_key, 16) << "\n";
      if (id.cert.size() == 0x1A8 && id.cert[0] == 0x01) {
        out << "cert=" << ToHex(id.cert.data(), 0x1A8) << "\n";
      }
      std::filesystem::permissions(file,
                                   std::filesystem::perms::owner_read |
                                       std::filesystem::perms::owner_write,
                                   ec);
    }
    id.ready = true;
    XELOGI("wharf console: id {} serial {:.12} cert {}", ToHex(id.console_id, 5),
           std::string(id.serial, 12),
           id.cert.size() == 0x1A8 && id.cert[0] == 0x01 ? "signed"
                                                           : "MISSING");
  });
  return id;
}

}  // namespace console_identity

dword_result_t XeKeysGetKeyProperties_entry(dword_t key) {
  if (X_Key_Properties.contains(key)) {
    auto& key_info = X_Key_Properties.at(key);
    return std::get<1>(key_info);
  }
  XELOGW("Key 0x{:04X} not implemented", static_cast<uint16_t>(key));
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysGetKeyProperties, kNone, kImplemented);

dword_result_t XeKeysGetKey_entry(word_t key, lpvoid_t key_buffer,
                                  lpdword_t key_length) {
  // Wharf DEV: per-instance console keyvault entries (see console_identity).
  if (key == CONSOLE_CERTIFICATE || key == CONSOLE_SERIAL_NUMBER) {
    auto& id = console_identity::Get();
    const uint8_t* data = key == CONSOLE_CERTIFICATE
                              ? id.cert.data()
                              : reinterpret_cast<const uint8_t*>(id.serial);
    const uint32_t size = key == CONSOLE_CERTIFICATE ? 0x1A8 : 12;
    std::memcpy(key_buffer, data, std::min<uint32_t>(*key_length, size));
    *key_length = size;
    return X_STATUS_SUCCESS;
  }
  if (key_vault.contains(key)) {
    std::span<const uint8_t> key_needed = key_vault.at(key);
    // The length is in/out: the caller's buffer size in, the key size out
    // (XAM checks the returned 0x110 of key 0x41). Never copy past the key.
    const uint32_t copy =
        std::min<uint32_t>(*key_length, uint32_t(key_needed.size()));
    std::memcpy(key_buffer, key_needed.data(), copy);
    *key_length = uint32_t(key_needed.size());
  } else {
    XELOGW("Key 0x{:04X} not implemented", static_cast<uint16_t>(key));
  }

  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysGetKey, kNone, kSketchy);

bool XeKeysHmacSha(uint32_t key_num, const uint8_t* inp_1, uint32_t inp_1_size,
                   const uint8_t* inp_2, uint32_t inp_2_size,
                   const uint8_t* inp_3, uint32_t inp_3_size, uint8_t* out,
                   uint32_t out_size) {
  if (key_num == CONSOLE_OBFUSCATION_KEY) {
    // Wharf DEV: the per-instance console obfuscation key (XAM caches the
    // logon ticket in XConfig under it).
    XeCryptHmacSha(console_identity::Get().obf_key, 16, inp_1, inp_1_size,
                   inp_2, inp_2_size, inp_3, inp_3_size, out, out_size);
    return true;
  }
  if (key_num != 0x19) {
    return false;
  }
  XeCryptHmacSha(key19, sizeof(key19), inp_1, inp_1_size, inp_2, inp_2_size,
                 inp_3, inp_3_size, out, out_size);
  return true;
}

dword_result_t XeKeysHmacSha_entry(dword_t key_num, lpvoid_t inp_1,
                                   dword_t inp_1_size, lpvoid_t inp_2,
                                   dword_t inp_2_size, lpvoid_t inp_3,
                                   dword_t inp_3_size, lpvoid_t out,
                                   dword_t out_size) {
  return XeKeysHmacSha(key_num, inp_1.as<uint8_t*>(), inp_1_size,
                       inp_2.as<uint8_t*>(), inp_2_size, inp_3.as<uint8_t*>(),
                       inp_3_size, out.as<uint8_t*>(), out_size)
             ? X_STATUS_SUCCESS
             : X_STATUS_UNSUCCESSFUL;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysHmacSha, kNone, kImplemented);

void XeCryptRotSumSha_entry(lpvoid_t inp_1, dword_t inp_1_size, lpvoid_t inp_2,
                            dword_t inp_2_size, lpvoid_t out,
                            dword_t out_size) {
  // out used by XeCryptBnQwBeSigVerify
}
DECLARE_XBOXKRNL_EXPORT1(XeCryptRotSumSha, kNone, kStub);

dword_result_t XeKeysAesCbcUsingKey_entry(lpvoid_t obscured_key,
                                          lpvoid_t inp_ptr, dword_t inp_size,
                                          lpvoid_t out_ptr, lpvoid_t feed_ptr,
                                          dword_t encrypt) {
  uint8_t key[16];

  // Deobscure key
  XECRYPT_AES_STATE aes;
  XeCryptAesKey_entry(&aes, (uint8_t*)xe_key_obfuscation_key);
  XeCryptAesEcb_entry(&aes, obscured_key, key, 0);

  // Run CBC using deobscured key
  XeCryptAesKey_entry(&aes, key);
  XeCryptAesCbc_entry(&aes, inp_ptr, inp_size, out_ptr, feed_ptr, encrypt);

  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysAesCbcUsingKey, kNone, kImplemented);

dword_result_t XeKeysObscureKey_entry(lpvoid_t input, lpvoid_t output) {
  // Based on HvxKeysObscureKey
  // Seems to encrypt input with per-console KEY_OBFUSCATION_KEY (key 0x18)

  XECRYPT_AES_STATE aes;
  XeCryptAesKey_entry(&aes, (uint8_t*)xe_key_obfuscation_key);
  XeCryptAesEcb_entry(&aes, input, output, 1);

  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysObscureKey, kNone, kImplemented);

dword_result_t XeKeysHmacShaUsingKey_entry(lpvoid_t obscured_key,
                                           lpvoid_t inp_1, dword_t inp_1_size,
                                           lpvoid_t inp_2, dword_t inp_2_size,
                                           lpvoid_t inp_3, dword_t inp_3_size,
                                           lpvoid_t out, dword_t out_size) {
  if (!obscured_key) {
    return X_STATUS_INVALID_PARAMETER;
  }

  uint8_t key[16];

  // Deobscure key
  XECRYPT_AES_STATE aes;
  XeCryptAesKey_entry(&aes, (uint8_t*)xe_key_obfuscation_key);
  XeCryptAesEcb_entry(&aes, obscured_key, key, 0);

  XeCryptHmacSha_entry(key, 0x10, inp_1, inp_1_size, inp_2, inp_2_size, inp_3,
                       inp_3_size, out, out_size);
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysHmacShaUsingKey, kNone, kImplemented);

dword_result_t XeKeysGetConsoleType_entry(lpdword_t type_out) {
  *type_out = Retail;
  return 0;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysGetConsoleType, kNone, kImplemented);

dword_result_t XeKeysGetConsoleID_entry(pointer_t<XE_CONSOLE_ID> raw_bytes,
                                        lpstring_t hex_string) {
  // Wharf DEV: the per-instance id (also inside the console certificate).
  const auto& id = console_identity::Get();
  if (raw_bytes) {
    std::memcpy(raw_bytes->Data, id.console_id, 5);
  }
  if (hex_string) {
    std::memcpy(hex_string, id.id_digits, 0xC);
  }
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysGetConsoleID, kNone, kImplemented);

// XeKeysVerifyRSASignature(key_index, hash, signature): the kernel verifies a
// signature made with one of its built-in public keys (index 0 signs the
// system.manifest XAM reads at start-up; it rejects the manifest and the Live
// logon's revision check fails when this returns 0). Wharf DEV STAND-IN: the
// manifest's SHA-1 is still checked by XAM; the RSA step is accepted for key 0
// because the matching public key is not in this tree.
dword_result_t XeKeysVerifyRSASignature_entry(dword_t key_index, lpvoid_t hash,
                                              lpvoid_t signature) {
  if (!hash || !signature) {
    return 0;
  }
  if (key_index != 0) {
    XELOGW("XeKeysVerifyRSASignature: key {} is not implemented",
           uint32_t(key_index));
    return 0;
  }
  return 1;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysVerifyRSASignature, kNone, kSketchy);

// XAM wrapper 81737F18 translates (hash, 20, out) to (hash, out).
// The kernel receives (hash, XE_CONSOLE_SIGNATURE* out) from the MACS AS-REQ
// builder (81946C70 -> 81737F18): out receives the console certificate (0x1A8)
// and an RSA-1024 PKCS#1 v1.5 signature (0x80) over the SHA-1 digest. Wharf
// DEV: signed with the per-instance console key, see console_identity.
dword_result_t XeKeysConsolePrivateKeySign_entry(
    lpvoid_t hash, pointer_t<XE_CONSOLE_SIGNATURE> output) {
  if (!hash || !output) {
    return false;
  }
  const auto& id = console_identity::Get();
  const auto sig = console_identity::Pkcs1Sign(id.key, hash.as<uint8_t*>());
  if (sig.size() != 0x80 || id.cert.size() != 0x1A8) {
    return false;
  }
  std::memcpy(reinterpret_cast<void*>(output.host_address()), id.cert.data(),
              0x1A8);
  std::memcpy(output->signature, sig.data(), 0x80);
  return true;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysConsolePrivateKeySign, kNone, kSketchy);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Crypt);
