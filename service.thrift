// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

/**
 * Apache Thrift interface for demo server.
 *
 * Tested with Apache Thrift v0.16.0
 */

namespace cpp anon_cred.thrift

exception AnonCredServiceException {
  1: string message;
}

exception TokenEncodingException {
  1: string message;
}

exception VoprfErrorException {
  1: i32 errorcode;
  2: string message;
}

exception CredentialMismatchException {
  1: string message;
}

struct GetPrimaryPublicKeyResponse {
  1: string primay_public_key;
}

struct GetPublicKeyRequest {
  1: list<string> attributes;
}

struct GetPublicKeyResponse {
  1: string public_key;
  2: string public_key_proof;
}

struct SignCredentialRequest {
  1: string blinded_token;
  2: list<string> attributes;
}

struct SignCredentialResponse {
  1: string evaluated_token;
  2: string proof_c;
  3: string proof_s;
}

struct RedeemCredentialRequest {
  1: string token;
  2: string shared_secret;
  3: list<string> attributes;
}

service SimpleAnonCredService {
  // Client gets a primary public key from server
  GetPrimaryPublicKeyResponse getPrimaryPublicKey();
  // Client gets a public key and pk_proof from server
  GetPublicKeyResponse getPublicKeyAndProof(1: GetPublicKeyRequest request);
  // Client sends a blinded token to server and gets a evaluated token
  SignCredentialResponse signCredential(
    1: SignCredentialRequest request,
  ) throws (
    1: TokenEncodingException tokenEncodingException,
    2: VoprfErrorException voprfErrorException,
  );
  // Client redeems token with shared_secret. Server validates the token
  void redeemCredential(1: RedeemCredentialRequest request) throws (
    1: TokenEncodingException tokenEncodingException,
    2: VoprfErrorException voprfErrorException,
    3: CredentialMismatchException credentialMismatchException,
  );
}
