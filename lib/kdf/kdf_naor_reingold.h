// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#include <sodium.h>

#include "lib/kdf/kdf.h"

/**
 * Implementation for KDF naor reingold.
 *
 * This is a KDF inspired by the Naor-Reingold PRF. The size of primary keys are
 * relatively large (about 256 * kdf_sdhi).
 *
 * See https://research.fb.com/dit for details.
 */

void kdf_naor_reingold_init(kdf_t* /* kdf */, curve_t* /* curve */);
