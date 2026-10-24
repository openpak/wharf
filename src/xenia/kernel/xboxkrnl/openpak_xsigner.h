// OpenPak content trust for the native XSigner envelope.
// Released under the BSD license - see LICENSE in the root for details.
#ifndef XENIA_KERNEL_XBOXKRNL_OPENPAK_XSIGNER_H_
#define XENIA_KERNEL_XBOXKRNL_OPENPAK_XSIGNER_H_

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "third_party/mbedtls/include/mbedtls/bignum.h"

namespace xe::kernel::xboxkrnl::openpak_xsigner {

// The OpenPak signer uses RSA-2048/65537 and standard big endian PKCS#1 v1.5
// SHA-1 signatures over XAM's existing digest. No digest is hashed twice.
inline bool Verify(const std::string& modulus_hex, const uint8_t* digest,
                   const uint8_t* signature) {
  if (modulus_hex.size() != 512 || !digest || !signature) {
    return false;
  }
  struct Integer {
    mbedtls_mpi value;
    Integer() { mbedtls_mpi_init(&value); }
    ~Integer() { mbedtls_mpi_free(&value); }
  } modulus, exponent, input, output;
  if (mbedtls_mpi_read_string(&modulus.value, 16, modulus_hex.c_str()) != 0 ||
      mbedtls_mpi_bitlen(&modulus.value) != 2048 ||
      mbedtls_mpi_lset(&exponent.value, 65537) != 0 ||
      mbedtls_mpi_read_binary(&input.value, signature, 256) != 0 ||
      mbedtls_mpi_cmp_mpi(&input.value, &modulus.value) >= 0 ||
      mbedtls_mpi_exp_mod(&output.value, &input.value, &exponent.value,
                          &modulus.value, nullptr) != 0) {
    return false;
  }
  std::array<uint8_t, 256> actual;
  if (mbedtls_mpi_write_binary(&output.value, actual.data(), actual.size()) !=
      0) {
    return false;
  }
  constexpr uint8_t prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
  std::array<uint8_t, 256> expected;
  expected.fill(0xff);
  expected[0] = 0;
  expected[1] = 1;
  expected[220] = 0;
  std::memcpy(expected.data() + 221, prefix, sizeof(prefix));
  std::memcpy(expected.data() + 236, digest, 20);
  uint8_t difference = 0;
  for (size_t i = 0; i < actual.size(); ++i) {
    difference |= actual[i] ^ expected[i];
  }
  return difference == 0;
}

}  // namespace xe::kernel::xboxkrnl::openpak_xsigner
#endif  // XENIA_KERNEL_XBOXKRNL_OPENPAK_XSIGNER_H_
