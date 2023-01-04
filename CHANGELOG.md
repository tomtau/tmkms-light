*January 5, 2023*

Many dependency upgrades, support for multi-arch Nitro images, and a small bug fix.

## v0.4.2
### Improvements
* [486](https://github.com/crypto-com/tmkms-light/pull/486) arm64 support in the Nitro image
### Bug Fixes
* [409](https://github.com/crypto-com/tmkms-light/pull/409) possible panics fixed in the Nitro logging

*August 9, 2022*

A bug fix for the SGX provider and a few dependency upgrades.

## v0.4.1
### Bug Fixes
* [387](https://github.com/crypto-com/tmkms-light/pull/387) SGX initialization and communication fix 

*August 4, 2022*

Many dependency upgrades.

## v0.4.0
### Breaking changes
* [356](https://github.com/crypto-com/tmkms-light/pull/356) NE production enclave file logging removed
in order to remove a vulnerable crate (you can use the default console logging and e.g. the Journald service instead)

### Improvements
* [288](https://github.com/crypto-com/tmkms-light/pull/288) switch to the official AWS Rust SDK
* [286](https://github.com/crypto-com/tmkms-light/pull/286) switch from the deprecated error-reporting crate
* [308](https://github.com/crypto-com/tmkms-light/pull/308) NE init command check if vsock-proxy is running
* [342](https://github.com/crypto-com/tmkms-light/pull/342) NE launch-all consistent exit code for errors

### Bug Fixes
* [305](https://github.com/crypto-com/tmkms-light/pull/305) NE init fixed

*October 29, 2021*

Many dependency upgrades and NE improvements.
Note that the version 0.2.0 contained a bug where production logging information from NE was sometimes lost.

## v0.3.0
### Breaking changes
* [109](https://github.com/crypto-com/tmkms-light/pull/109) "launch-all" command in the NE helper

### Improvements
* [115](https://github.com/crypto-com/tmkms-light/pull/115) graceful process shutdown in NE

### Bug Fixes
* [109](https://github.com/crypto-com/tmkms-light/pull/109) production logging in NE fix


*June 25, 2021*

Dependency upgrades, logging and backup/recovery improvements.
## v0.2.0
### Breaking changes
* [68](https://github.com/crypto-com/tmkms-light/pull/68) production logging in NE
* [87](https://github.com/crypto-com/tmkms-light/pull/87) keygen in NE
* [95](https://github.com/crypto-com/tmkms-light/pull/95) attestation for keygen in NE
* [94](https://github.com/crypto-com/tmkms-light/pull/94) logging level configurable in enclaves and hosts
* [55](https://github.com/crypto-com/tmkms-light/pull/55) SGX init and recovery commands paramater change
* [80](https://github.com/crypto-com/tmkms-light/pull/80) SGX backup and recovery in cloud environments

### Improvements
* [89](https://github.com/crypto-com/tmkms-light/pull/89) Instance Metadata Service Version 2 used in the NE host

*March 18, 2021*

Tendermint-rs and prost dependencies upgraded.
## v0.1.2

*March 16, 2021*

The same as the initial released version, but with a few dependency upgrades
## v0.1.1

*March 2, 2021*
The initial released version
## v0.1.0 
### Breaking changes
### Features
### Improvements
### Bug Fixes
