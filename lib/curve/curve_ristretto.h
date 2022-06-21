// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include "lib/curve/curve.h"

/**
 * Implementation for curve ristretto.
 * Example:
 *   curve_t c;
 *   curve_ristretto_init(&c);
 *   unsigned char r[c.scalar_bytes];
 *   c.scalar_random(r, c.scalar_bytes);
 */

void curve_ristretto_init(curve_t* /* curve */);
