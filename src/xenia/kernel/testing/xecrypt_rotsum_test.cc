// Copyright 2026 OpenPak contributors. Released under the BSD license.
#include "xenia/kernel/xboxkrnl/xecrypt_rotsum.h"
#include <array>
#include <cstdint>
#include <string>
#include "third_party/catch/include/catch.hpp"
namespace {
std::string Hex(const std::array<uint8_t, 20>& digest) {
  const char* digits = "0123456789abcdef";
  std::string out;
  for (auto byte : digest) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}
}  // namespace
TEST_CASE("RotSumSha handles empty inputs and independent partial qwords",
          "[crypto][rotsum]") {
  using xe::kernel::xboxkrnl::RotSumSha;
  REQUIRE(Hex(RotSumSha(nullptr, 0, nullptr, 0)) ==
          "c1f48a59c2629f48b955483785512db79040b3c1");
  const uint8_t first[] = {'a', 'b', 'c'}, second[] = {'d', 'e', 'f', 'g', 'h'};
  // Each buffer has fewer than eight bytes, so neither alters the accumulator.
  // All eight bytes still participate in SHA-1; concatenating them before
  // RotSum would incorrectly create a complete qword.
  REQUIRE(Hex(RotSumSha(first, 3, second, 5)) ==
          "16e5f8b33e28d4ee2543afcc528cb9e9a0925cfb");
}
