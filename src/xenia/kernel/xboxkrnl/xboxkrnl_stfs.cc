/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

// STFS device mounting for the real XAM. XAM writes a content package (for
// example a new profile, XamProfileCreate) and calls StfsCreateDevice to mount
// it as \Device\Package_<hash>; the kernel's STFS file system then serves the
// files inside. Wharf has no STFS writer, so the package's files live in a host
// directory next to the package file ("<package>.stfs"), mounted read-write at
// the device name. The package file keeps the header XAM wrote.

#include <cstring>
#include <random>
#include <vector>
#include <filesystem>

#include "third_party/mbedtls/include/mbedtls/md.h"
#include "xenia/base/filesystem.h"
#include "xenia/base/logging.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"
#include "xenia/kernel/xfile.h"
#include "xenia/vfs/devices/host_path_device.h"
#include "xenia/vfs/devices/host_path_entry.h"
#include "xenia/xbox.h"

namespace xe {
namespace kernel {
namespace xboxkrnl {

namespace {

// StfsCreateDevice parameter block (0x58 bytes, XAM 17559 FUN_81686DA0).
constexpr uint32_t kParamName = 0x00;           // ANSI_STRING device name
constexpr uint32_t kParamFileHandle = 0x18;     // package file handle
constexpr uint32_t kParamExtensionSize = 0x44;  // device extension size
constexpr uint32_t kParamDeviceOut = 0x48;      // out: device object
constexpr uint32_t kParamExtensionOut = 0x4C;   // out: device extension

constexpr uint32_t kDeviceObjectSize = 0x50;  // X_DEVICE_OBJECT
// XAM keeps a copy of the package header at extension +0x38; the 0x24-byte
// STFS volume descriptor sits at header +0x379.
constexpr uint32_t kExtensionVolumeDescriptor = 0x38 + 0x379;
constexpr uint32_t kVolumeDescriptorSize = 0x24;

}  // namespace

dword_result_t StfsCreateDevice_entry(dword_t params_ptr, dword_t params_size) {
  auto* memory = kernel_memory();
  if (!params_ptr || params_size < 0x50) {
    return X_STATUS_INVALID_PARAMETER;
  }
  auto* params = memory->TranslateVirtual<uint8_t*>(params_ptr);
  const std::string name = util::TranslateAnsiPath(
      memory, reinterpret_cast<const X_ANSI_STRING*>(params + kParamName));
  const uint32_t handle = xe::load_and_swap<uint32_t>(params + kParamFileHandle);
  const uint32_t extension_size =
      xe::load_and_swap<uint32_t>(params + kParamExtensionSize);

  auto file = kernel_state()->object_table()->LookupObject<XFile>(handle);
  auto* host_entry =
      file ? dynamic_cast<vfs::HostPathEntry*>(file->entry()) : nullptr;
  if (name.empty() || !host_entry) {
    XELOGE("StfsCreateDevice({}): package handle {:08X} is not a host file",
           name, handle);
    return X_STATUS_INVALID_PARAMETER;
  }

  auto host_dir = host_entry->host_path();
  host_dir += ".stfs";
  std::error_code ec;
  std::filesystem::create_directories(host_dir, ec);

  auto* fs = kernel_state()->file_system();
  if (fs->GetDevice(name)) {
    fs->UnregisterDevice(name);
  }
  auto device = std::make_unique<vfs::HostPathDevice>(name, host_dir, false);
  if (!device->Initialize() || !fs->RegisterDevice(std::move(device))) {
    XELOGE("StfsCreateDevice({}): cannot mount {}", name,
           xe::path_to_utf8(host_dir));
    return X_STATUS_UNSUCCESSFUL;
  }

  // A device object with the extension right behind it (as IoCreateDevice).
  const uint32_t total = kDeviceObjectSize + xe::align<uint32_t>(extension_size, 8);
  const uint32_t device_ptr = memory->SystemHeapAlloc(total);
  if (!device_ptr) {
    return X_STATUS_NO_MEMORY;
  }
  auto* device_object = memory->TranslateVirtual<uint8_t*>(device_ptr);
  std::memset(device_object, 0, total);
  xe::store_and_swap<uint16_t>(device_object + 0x00, 3);  // type
  xe::store_and_swap<uint16_t>(device_object + 0x02,
                               uint16_t(kDeviceObjectSize + extension_size));
  xe::store_and_swap<uint32_t>(device_object + 0x0C, device_ptr);
  xe::store_and_swap<uint32_t>(device_object + 0x18,
                               device_ptr + kDeviceObjectSize);
  device_object[0x1E] = 1;  // stack size

  xe::store_and_swap<uint32_t>(params + kParamDeviceOut, device_ptr);
  xe::store_and_swap<uint32_t>(params + kParamExtensionOut,
                               device_ptr + kDeviceObjectSize);
  XELOGI("StfsCreateDevice({}) -> {} (device {:08X}, extension {:X} bytes)",
         name, xe::path_to_utf8(host_dir), device_ptr, extension_size);
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(StfsCreateDevice, kFileSystem, kImplemented);

// Codes seen in XAM 17559: 0 lock, 1 unlock, 2 flush, 3 read the volume
// descriptor, 4 write it, 5 query. XAM creates a package with a zero volume
// descriptor and zero header hash; when code 3 returns a descriptor that
// differs from its copy, XAM finalises the header itself (FUN_8167C628:
// header hash at 0x32C, console signature, rewrite) and sends it with code 4.
// So code 3 returns XAM's copy once it is a real descriptor, else a minimal
// valid one (size 0x24, one file table block); the files themselves live in
// the host directory.
dword_result_t StfsControlDevice_entry(dword_t device_ptr, dword_t code,
                                       dword_t buffer_ptr) {
  if (code == 3 && device_ptr && buffer_ptr) {
    auto* memory = kernel_memory();
    const uint32_t extension = xe::load_and_swap<uint32_t>(
        memory->TranslateVirtual<uint8_t*>(device_ptr) + 0x18);
    auto* out = memory->TranslateVirtual<uint8_t*>(buffer_ptr);
    const uint8_t* current =
        extension ? memory->TranslateVirtual<uint8_t*>(
                        extension + kExtensionVolumeDescriptor)
                  : nullptr;
    if (current && current[0] == kVolumeDescriptorSize) {
      std::memcpy(out, current, kVolumeDescriptorSize);
    } else {
      std::memset(out, 0, kVolumeDescriptorSize);
      out[0] = kVolumeDescriptorSize;  // descriptor size
      out[3] = 1;                      // file table block count (LE u16)
    }
  }
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(StfsControlDevice, kFileSystem, kStub);

// XAM dismounts a package device before closing it. The host directory mount
// stays registered; the next StfsCreateDevice of the same name replaces it.
dword_result_t IoDismountVolume_entry(dword_t device_ptr) {
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(IoDismountVolume, kFileSystem, kStub);

// XAM verifies a CON package's console signature (header +0x04) over the SHA-1
// of header +0x22C..0x344 before it opens the package (FUN_8167..., 80070570 on
// FALSE). The third argument receives nonzero when another console signed it.
// Every package here was signed by this emulated console
// (XeKeysConsolePrivateKeySign), so accept it as our own.
dword_result_t XeKeysConsoleSignatureVerification_entry(lpvoid_t hash,
                                                        lpvoid_t signature,
                                                        lpdword_t other_console) {
  if (!hash || !signature) {
    return false;
  }
  if (other_console) {
    *other_console = 0;
  }
  return true;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysConsoleSignatureVerification, kNone, kStub);

// Profile account blocks (the Account file, 0x17C bytes -> 0x194) and other XAM
// secrets go through XeKeysObfuscate/XeKeysUnObfuscate:
//   out = HMAC-SHA1(key, confounder8 | data)[0:16]
//       | RC4(HMAC-SHA1(key, that 16-byte digest)[0:16], confounder8 | data)
// with the retail roaming key. The console-bound variant (roaming 0) uses the
// same key here: everything it protects is created by this emulated console.
namespace {
constexpr uint8_t kObfuscationKey[16] = {0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1,
                                         0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3,
                                         0xAD, 0x47, 0xEB, 0xF3};
constexpr uint32_t kObfuscationOverhead = 16 + 8;

void HmacSha1(const uint8_t* data, size_t size, uint8_t out[20]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), kObfuscationKey,
                  sizeof(kObfuscationKey), data, size, out);
}

void Rc4(const uint8_t* key, size_t key_size, uint8_t* data, size_t size) {
  uint8_t s[256];
  for (int i = 0; i < 256; ++i) s[i] = uint8_t(i);
  for (int i = 0, j = 0; i < 256; ++i) {
    j = (j + s[i] + key[i % key_size]) & 0xFF;
    std::swap(s[i], s[j]);
  }
  for (size_t n = 0, i = 0, j = 0; n < size; ++n) {
    i = (i + 1) & 0xFF;
    j = (j + s[i]) & 0xFF;
    std::swap(s[i], s[j]);
    data[n] ^= s[(s[i] + s[j]) & 0xFF];
  }
}
}  // namespace

dword_result_t XeKeysObfuscate_entry(dword_t roaming, lpvoid_t input,
                                     dword_t input_size, lpvoid_t output,
                                     lpdword_t output_size) {
  if (!input || !output || !output_size) {
    return false;
  }
  std::vector<uint8_t> plain(8 + input_size);
  std::random_device rd;
  for (size_t i = 0; i < 8; ++i) plain[i] = uint8_t(rd());
  std::memcpy(plain.data() + 8, input.as<uint8_t*>(), input_size);
  uint8_t digest[20], rc4_key[20];
  HmacSha1(plain.data(), plain.size(), digest);
  HmacSha1(digest, 16, rc4_key);
  Rc4(rc4_key, 16, plain.data(), plain.size());
  auto* out = output.as<uint8_t*>();
  std::memmove(out + 16, plain.data(), plain.size());
  std::memcpy(out, digest, 16);
  *output_size = uint32_t(input_size) + kObfuscationOverhead;
  return true;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysObfuscate, kNone, kImplemented);

dword_result_t XeKeysUnObfuscate_entry(dword_t roaming, lpvoid_t input,
                                       dword_t input_size, lpvoid_t output,
                                       lpdword_t output_size) {
  if (!input || !output || !output_size || input_size < kObfuscationOverhead) {
    return false;
  }
  const auto* in = input.as<uint8_t*>();
  std::vector<uint8_t> plain(in + 16, in + input_size);
  uint8_t rc4_key[20], digest[20];
  HmacSha1(in, 16, rc4_key);
  Rc4(rc4_key, 16, plain.data(), plain.size());
  HmacSha1(plain.data(), plain.size(), digest);
  if (std::memcmp(digest, in, 16) != 0) {
    return false;
  }
  std::memcpy(output.as<uint8_t*>(), plain.data() + 8, plain.size() - 8);
  *output_size = uint32_t(plain.size() - 8);
  return true;
}
DECLARE_XBOXKRNL_EXPORT1(XeKeysUnObfuscate, kNone, kImplemented);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Stfs);
