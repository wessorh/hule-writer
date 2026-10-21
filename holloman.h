/* holloman.h — holloman3 fingerprint API for hscan.
 *
 * The Hilbert-curve mapping, Lanczos-3 kernel generation, and rotation are
 * implemented here in portable C; the two SIMD scaling passes are delegated to
 * libholloman3 (third_party/libholloman3). */

#ifndef HOLLOMAN_H
#define HOLLOMAN_H

#include <stddef.h>
#include <stdint.h>

/* Pre-compute the Hilbert curve for fingerprinting buffers up to `order`. */
int holloman_init(uint32_t order);

/* Free the Hilbert-curve cache. */
int holloman_cleanup(void);

/* Compute the 16-byte holloman fingerprint for `data` of `size` bytes. */
int holloman_fingerprint_buffer(const uint8_t *data, size_t size,
                                uint8_t fingerprint[16]);

/* True if the CPU supports AVX2 (with OSXSAVE enabled). */
int holloman_is_avx2_available(void);

/* Library version string. */
const char *holloman_version(void);

#endif /* HOLLOMAN_H */
