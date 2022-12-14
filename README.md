# Anonymous Credential Service
Anonymous Credential Service (ACS) is a highly available, multitenant service that allows clients to authenticate in a de-identified manner. It enhances privacy and security while also being compute-conscious.

[How Meta enables de-identified authentication at scale](https://engineering.fb.com/2022/03/30/security/de-identified-authentication-at-scale)

## ACS library
The Anonymous Credential Service is built on top of VOPRFs (verifiable oblivious pseudorandom functions), blind signatures, and key derivation functions. A portable and extensible C library is provided in [`lib/`](lib/). See docstring or SimpleAnonCredService for examples.

[libsodium](https://doc.libsodium.org/) is the only dependency for ACS library.

## SimpleAnonCredService
We have implemented a SimpleAnonCredService (server + client) in C++ for demonstration. The service is built with Apache Thrift 0.16. We run a protocol as follows:
- (1) Client downloads primary public key from server. This primary public key is for validation of public key in step (2).
- (2) Client gets public key for provided "attributes". The "attributes" can be any list of strings (e.g. use case names, date) that allowed by server.
- (3) Client generates a token, blinds the token, sends the token to server. After autentication check, server signs the token and sends back to client. Client unblinds the signed token and verified with public key and proof.
- (4) Client redeems the token. Server validates the secret and proceeds to business logic if the validation successes.

Note that (1) is optional if the client does not need public key validation.

## Build
Dependencies: [libsodium](https://doc.libsodium.org/) and [Apache Thrift 0.16](https://thrift.apache.org/). To build, just run `make` in the root of repo.

## Docker
It might be easier to just try the service with Docker.

- Create an ACS docker image: `docker build -t acs . --build-arg UBUNTU_VERSION=22.04`
- Create a container with a running server: `docker run --rm --init --name acs-container acs`
- Create a client in the same container and connect to the server: `docker exec acs-container client`

## License
ACS is MIT licensed, as found in the LICENSE file.
