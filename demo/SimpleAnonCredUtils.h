// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include <string>
#include <vector>

namespace anon_cred {
namespace util {
std::string binToHex(const std::vector<unsigned char>& bin);
std::vector<unsigned char> hexToBin(
    const std::string& hex,
    size_t desiredBinSize = 0);
} // namespace util
} // namespace anon_cred
