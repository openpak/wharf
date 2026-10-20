// Copyright 2026 OpenPak contributors. Released under the BSD license.
#ifndef XENIA_KERNEL_XBOXKRNL_XECRYPT_ROTSUM_H_
#define XENIA_KERNEL_XBOXKRNL_XECRYPT_ROTSUM_H_
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include "third_party/mbedtls/include/mbedtls/sha1.h"

namespace xe::kernel::xboxkrnl {
// RotSum consumes complete big-endian qwords from each input separately.
inline std::array<uint8_t, 20> RotSumSha(const uint8_t* first, size_t first_size,
                                      const uint8_t* second, size_t second_size) {
  uint64_t a = 0, b = 0, c = 0, d = 0;
  auto consume = [&](const uint8_t* data, size_t size) {
    for (size_t i = 0; i + 8 <= size; i += 8) {
      uint64_t x = 0;
      for (size_t j = 0; j < 8; ++j) x = (x << 8) | data[i + j];
      b += x;
      d -= x;
      a += b < x;
      b = std::rotl(b, 29);
      c -= x < d;
      d = std::rotl(d, 31);
    }
  };
  consume(first, first_size);
  consume(second, second_size);
  std::array<uint8_t, 32> state;
  const uint64_t words[] = {a, b, c, d};
  for (size_t i = 0; i < 4; ++i)
    for (size_t j = 0; j < 8; ++j)
      state[i * 8 + j] = uint8_t(words[i] >> (56 - j * 8));
  std::array<uint8_t, 20> digest;
  mbedtls_sha1_context sha;
  mbedtls_sha1_init(&sha);
  mbedtls_sha1_starts(&sha);
  mbedtls_sha1_update(&sha, state.data(), state.size());
  mbedtls_sha1_update(&sha, state.data(), state.size());
  if (first_size) mbedtls_sha1_update(&sha, first, first_size);
  if (second_size) mbedtls_sha1_update(&sha, second, second_size);
  for (auto& byte : state) byte = uint8_t(~byte);
  mbedtls_sha1_update(&sha, state.data(), state.size());
  mbedtls_sha1_update(&sha, state.data(), state.size());
  mbedtls_sha1_finish(&sha, digest.data());
  mbedtls_sha1_free(&sha);
  return digest;
}
}  // namespace xe::kernel::xboxkrnl
#endif
