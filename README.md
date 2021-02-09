# Tendermint KMS Light 🔐

TEE-based Key Management System for [Tendermint] validators.

## About

This repository contains `tmkms-light`, a key management service intended to be deployed
in conjunction with [Tendermint] applications (ideally on separate physical hosts).
The code is based on the [tmkms](https://github.com/iqlusioninc/tmkms) repository with the following differences:

- **Smaller codebase** with the following limitations:
1. only one network can be configured in each `tmkms-light` process;
2. only the latest Tendermint protocol (v0.34) is supported;
3. there is no support for HSMs;
4. there is no support for transaction signing (`tx-signer` feature);
5. only `x86_64` Linux is supported.

- The code does not use conditional compilation (each signing provider has separate binaries) and dependencies on `abscissa` crates were replaced in order to fully support `tracing` for the application logging.
- **Signing in TEE (Trusted Execution Environments)**: currently, Intel(R) SGX and AWS Nitro Enclaves are supported.

## Status

Tendermint KMS Light is still in development (e.g. the SGX signing provider has not
yet been signed, so that it could be launched in the production mode).
In the future, the work developed in this repository may be upstreamed 
to the original [tmkms](https://github.com/iqlusioninc/tmkms) repository.

## Signing Providers

The following signing backend providers are presently supported:

#### Software-Only (not recommended; only for testing)

This is contained in the "providers/softsign" directory.

#### Intel(R) SGX
This is contained in the "providers/sgx" directory.
There are two crates that need to be compiled separately:
* `tmkms-light-sgx-app`: this is the enclave application that needs to be compiled for the `x86_64-fortanix-unknown-sgx` target, converted and signed as per [EDP instructions](https://edp.fortanix.com/docs/tasks/deployment/);
* `tmkms-light-sgx-runner`: this is the (host) runner application that is used to load the enclave application
and interface with the host system.

##### Installation
TODO
##### Configuration
TODO
##### Running
TODO

#### AWS Nitro Enclaves
This is contained in the "providers/nitro" directory.
There are two crates that need to be compiled separately:
* `tmkms-nitro-enclave`: this is the enclave application that needs to be compiled for the `x86_64-unknown-linux-musl` target if you are using the Alpine Linux (or equivalent) for the Docker file that gets converted to the enclave image file. The enclave application also needs to be linked against AWS Nitro Enclaves SDK etc., so make sure these libraries are present in your build environment -- see this [AWS Dockerfile](https://github.com/aws/aws-nitro-enclaves-acm/blob/main/env/enclave/Dockerfile).
* `tmkms-nitro-helper`: this is the application on the host that pushes the configuration to the enclave and provides extra vsock proxy connections to interface with the host system.
##### Installation
TODO: instructions from the early prototype are here: https://chain.crypto.com/docs/getting-started/advanced-tmkms-integration.html#setting-up-aws-nitro-enclaves-tendermint-kms-for-signing-blocks
##### Configuration
TODO
##### Running
TODO
