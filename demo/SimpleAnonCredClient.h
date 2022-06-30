// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include <sodium.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <iostream>
#include <string>
#include <vector>
#include "gen-cpp/SimpleAnonCredService.h"

extern "C" {
#include "lib/curve/curve_ristretto.h"
#include "lib/kdf/kdf_sdhi.h"
#include "lib/voprf/voprf_mul_twohashdh.h"
}

namespace anon_cred {

class SimpleAnonCredClient {
 public:
  SimpleAnonCredClient(
      std::shared_ptr<::apache::thrift::protocol::TProtocol> prot);
  void getPrimaryPublicKey();
  void getPublicKey(const std::vector<std::string>& attributes);
  void getCredential(
      const std::string& cred,
      const std::vector<std::string>& attributes);
  void redeemCredential(
      const std::string& cred,
      const std::vector<std::string>& attributes);

  std::vector<unsigned char> primaryPublicKey;
  std::vector<unsigned char> publicKey;
  std::vector<unsigned char> unBlindedElement;

 private:
  curve_t curve_;
  voprf_t voprf_;
  kdf_t kdf_;
  thrift::SimpleAnonCredServiceClient thriftClient_;
};

} // namespace anon_cred
