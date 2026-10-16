/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */
#ifndef XENIA_KERNEL_XBOXKRNL_XECRYPT_DH_H_
#define XENIA_KERNEL_XBOXKRNL_XECRYPT_DH_H_

#include <array>
#include <cstdint>
#include "third_party/mbedtls/include/mbedtls/bignum.h"

namespace xe::kernel::xboxkrnl {

// RFC 2409 section 6.1, first Oakley group (768 bits, generator 2).
// Xbox Live represents the public value and exponent as 96 little-endian bytes.
inline constexpr std::array<uint8_t, 96> kLiveDhPrime = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};

inline bool LiveDhInvalidBase(const uint8_t* base) {
  if (!base) return false;
  mbedtls_mpi p, a;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&a);
  int status = mbedtls_mpi_read_binary(&p, kLiveDhPrime.data(), kLiveDhPrime.size());
  if (!status) status = mbedtls_mpi_sub_int(&p, &p, 1);
  if (!status) status = mbedtls_mpi_read_binary_le(&a, base, 96);
  bool invalid = status || mbedtls_mpi_cmp_int(&a, 1) <= 0 ||
                 mbedtls_mpi_cmp_mpi(&a, &p) >= 0;
  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&p);
  return invalid;
}

inline bool LiveDhModExp(const uint8_t* base, const uint8_t* exponent,
                         uint8_t* output) {
  if (!exponent || !output) return false;
  mbedtls_mpi p, a, x, result;
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&a);
  mbedtls_mpi_init(&x);
  mbedtls_mpi_init(&result);
  int status = mbedtls_mpi_read_binary(&p, kLiveDhPrime.data(), kLiveDhPrime.size());
  if (!status) status = base ? mbedtls_mpi_read_binary_le(&a, base, 96)
                            : mbedtls_mpi_lset(&a, 2);
  if (!status) status = mbedtls_mpi_read_binary_le(&x, exponent, 96);
  if (!status && (mbedtls_mpi_cmp_int(&a, 1) <= 0 ||
                  mbedtls_mpi_cmp_mpi(&a, &p) >= 0)) status = -1;
  if (!status) status = mbedtls_mpi_exp_mod(&result, &a, &x, &p, nullptr);
  if (!status) status = mbedtls_mpi_write_binary_le(&result, output, 96);
  mbedtls_mpi_free(&result);
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&p);
  return status == 0;
}

}  // namespace xe::kernel::xboxkrnl
#endif  // XENIA_KERNEL_XBOXKRNL_XECRYPT_DH_H_
