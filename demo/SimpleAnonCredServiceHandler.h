// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include "gen-cpp/SimpleAnonCredService.h"

extern "C" {
#include "lib/curve/curve_ristretto.h"
#include "lib/kdf/kdf_sdhi.h"
#include "lib/voprf/voprf_mul_twohashdh.h"
}

namespace anon_cred {

using namespace thrift;

class SimpleAnonCredServiceHandler : virtual public SimpleAnonCredServiceIf {
 public:
  SimpleAnonCredServiceHandler();
  void getPrimaryPublicKey(GetPrimaryPublicKeyResponse& response);
  void getPublicKeyAndProof(
      GetPublicKeyResponse& response,
      const GetPublicKeyRequest& request);
  void signCredential(
      SignCredentialResponse& response,
      const SignCredentialRequest& request);
  void redeemCredential(const RedeemCredentialRequest& request);

 private:
  void deriveKeyPair(
      std::vector<unsigned char>& sk,
      std::vector<unsigned char>& pk,
      std::vector<unsigned char>& pkProof,
      const std::vector<std::string>& attributes);

  curve_t curve_;
  voprf_t voprf_;
  kdf_t kdf_;

  std::vector<unsigned char> primaryKey_;
};

} // namespace anon_cred
