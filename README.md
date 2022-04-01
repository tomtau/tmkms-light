# Tendermint KMS Light 🔐

TEE-based Key Management System for [Tendermint](http://github.com/tendermint/tendermint/) validators.

## About

This repository contains `tmkms-light`, a key management service intended to be deployed
in conjunction with [Tendermint](http://github.com/tendermint/tendermint/) applications (ideally on separate physical hosts).
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

Tendermint KMS Light is currently *beta quality*.
In the future, the work developed in this repository may be upstreamed 
to the original [tmkms](https://github.com/iqlusioninc/tmkms) repository.

## Signing Providers

The following signing backend providers are presently supported:

### Software-Only (not recommended; only for testing)

This is contained in the "providers/softsign" directory.

### Intel(R) SGX
This is contained in the "providers/sgx" directory.
There are two crates that need to be compiled separately:
* `tmkms-light-sgx-app`: this is the enclave application that needs to be compiled for the `x86_64-fortanix-unknown-sgx` target, converted and signed as per [EDP instructions](https://edp.fortanix.com/docs/tasks/deployment/);
* `tmkms-light-sgx-runner`: this is the (host) runner application that is used to load the enclave application
and interface with the host system.

#### Installation

First, Setup your sgx machine with [EDP Installation guide](https://edp.fortanix.com/docs/installation/guide/)

Build `tmkms-light-sgx-runner`
```bash
cargo build --target x86_64-unknown-linux-gnu -p tmkms-light-sgx-runner --release
```
##### Reproducible SGX enclave application building
Build `tmkms-light-sgx-app`
```bash
docker build -f Dockerfile.sgx --target export --output type=local,dest=./ .
```

The output enclave file is `tmkms-light-sgx-app.sgxs`.
You can then follow [EDP instructions](https://edp.fortanix.com/docs/tasks/deployment/) for SGXS signing.

> :warning: For SGXS signing, the EDP instructions are shown for the "Debug" mode. For the production mode, remove the `--debug` / `-d` flags.
  
> :warning: For CPUs without the Flexible Launch Control feature (i.e. SGX v1), the enclave code needs to be signed with the RSA key previously approved by Intel in order to launch in the production mode.

##### Manual SGX enclave application building
Build `tmkms-light-sgx-app`
```bash
cargo build --target x86_64-fortanix-unknown-sgx -p tmkms-light-sgx-app --release
```

Follow [EDP instructions](https://edp.fortanix.com/docs/tasks/deployment/) for SGXS conversion and signing.
> :warning: For SGXS conversion, change `--heap-size/--stack-size` value to `0x40000`, and `--threads 2` should be enough.

> :warning: For SGXS conversion and signing, the EDP instructions are shown for the "Debug" mode. For the production mode, remove the `--debug` / `-d` flags.
  
> :warning: For CPUs without the Flexible Launch Control feature (i.e. SGX v1), the enclave code needs to be signed with the RSA key previously approved by Intel in order to launch in the production mode.

#### Configuration

- Place the generated `*.sgxs` and `*.sig` files into `tmkms/enclave` directory.
- Place the `tmkms-light-sgx-runner` binary to `tmkms` directory.

*tmkms init*

Provide your chain `bech32_prefix`
```bash
$ tmkms-light-sgx-runner init -b bech32_prefix -p "bech32"
```

> :warning: For those who are running on Azure or other cloud environments, one may want to run `init` command with a cloud backup key.
> In cloud environments such as Azure, `CPU-affinity` may not be guaranteed, so SGX “sealing” (a way to encrypt the validator key that only a particular CPU can decrypt the validator key) may not be fully relied on. Please follow `With cloud backup key` if you intend to deploy in those settings.

<details>
  <summary>With cloud backup key</summary>

TODO: these instructions are to be enhanced later on.
One may provide flag `-e backup_key_path` which is to encrypt and decrypt `consensus-key.backup` in directory specified in `-k backup_data_path`. Before `init`, you will need to run `tmkms-light-sgx-runner cloud-wrap -s wrap_key_path -d`

### Recover
```bash
$ tmkms-light-sgx-runner recover -b bech32_prefix -p "bech32" -e backup_key_path -k backup_data_path -r
```
Or follow the example python script to run [recover](script/tmkms-sgx/recover.py)
</details>

Lastly, edit the generated `tmkms.toml` to fit the target chain config, i.e chain_id and enclave_path
#### Running

*tmkms start*

```bash
tmkms-light-sgx-runner start
```
### AWS Nitro Enclaves
This is contained in the "providers/nitro" directory.
There are two crates that need to be compiled separately:
* `tmkms-nitro-enclave`: this is the enclave application that needs to be compiled for the `x86_64-unknown-linux-musl` target if you are using the Alpine Linux (or equivalent) for the Docker file that gets converted to the enclave image file. The enclave application also needs to be linked against AWS Nitro Enclaves SDK etc., so make sure these libraries are present in your build environment -- see this [AWS Dockerfile](https://github.com/aws/aws-nitro-enclaves-acm/blob/main/env/enclave/Dockerfile).
* `tmkms-nitro-helper`: this is the application on the host that pushes the configuration to the enclave and provides extra vsock proxy connections to interface with the host system.
#### Installation
#### 1. Set up AWS nitro enclaves
Follow the step 1 and step 4 [here](https://chain.crypto.com/docs/getting-started/advanced-tmkms-integration.html#setting-up-aws-nitro-enclaves-tendermint-kms-for-signing-blocks)

##### 2. build tmkms-nitro-enclave and tmkms-nitro-helper

###### 2.1. build docker image in which build the tmkms-nitro-enclave
```shell
$ cd tmkms-light
$ docker build -t aws-ne-build \
       --build-arg USER=$(whoami) \
       --build-arg USER_ID=$(id -u) \
       --build-arg GROUP_ID=$(id -g) \
       --build-arg RUST_TOOLCHAIN="1.56.1" \
       --build-arg CTR_HOME="$CTR_HOME" \
       -f Dockerfile.nitro .
```

#####2.2. build tmkms-nitro-helper
```shell
$ cd tmkms-light
$ cargo build --target x86_64-unknown-linux-gnu -p tmkms-nitro-helper --release
```
After build process finished, move the binary `tmkms-nitro-helper` to one of your `PATH` directories.

#####2.3. create eli file

Use the docker image `aws-ne-build` which built in step 2.1 or just pull the docker image from dockerhub by using `docker pull cryptocom/nitro-enclave-tmkms:latest`
```shell
$ mkdir ~/.tmkms
$ nitro-cli build-enclave \
  --docker-uri aws-ne-build \
  --output-file ~/.tmkms/tmkms.eif
```

#### Configuration
First, you need to start nitro enclave and generate the encrypted validator key and config files:

```shell
$ tmkms-nitro-helper enclave run --cpu-count 2
```

In another shell, you can check the enclave status:

```shell
$ tmkms-nitro-helper enclave info
```
the output should be:
```json
[
  {
    "EnclaveID": "i-xxx-xxx",
    "ProcessID": 31388,
    "EnclaveCID": 1,
    "NumberOfCPUs": 2,
    "CPUIDs": [
      1,
      3
    ],
    "MemoryMiB": 512,
    "State": "RUNNING",
    "Flags": "NONE"
  }
]
```

create the encrypted validator key and config files:

```shell
$ mkdir ~/.tmkms && cd ~/.tmkms
$ tmkms-nitro-helper init \
    -a $KMS_REGIN \
    -k $KMS_KEY_ID \
    -p bech32 \
    -b crocnclconspub \
    --cid $EnclaveCID
```
where:
* `KMS_REGIN`: where your AWS ec2 located like `ap-southeast-1`, see more [here](https://docs.aws.amazon.com/general/latest/gr/rande.html)
* `KMS_KEY_ID`: [AWS Key Management Service](https://aws.amazon.com/kms/?nc1=h_ls) key id
* `EnclaveCID`: can get from command `tmkms-nitro-helper enclave info`

It should encrypted validator signing key `secrets/secret.key`, tmkms config file `tmkms.toml` and enclave config file `enclave.toml`, the output looks like:

```json
public key: crocnclconspub1zcjduep..........tq48jchd
Nitro Enclave attestation:
hEShATgioFkRZKlpb.......................3L2Z28yKrDMTR
```

#### Running
##### Running step by step
You need to start three components to make it work:
1. start nitro enclave:
```shell
$ tmkms-nitro-helper enclave run --cpu-count 2 -v
```
2. start vsock proxy:
```shell
$ tmkms-nitro-helper enclave vsock-proxy --remote-addr kms.ap-southeast-1.amazonaws.com
```
do remember to change the value of `remote-addr` associated with your AWS region.

3. start tmkms helper:

```shell
$ tmkms-nitro-helper start -c ./tmkms.toml -v
```

You can use `-h` or `--help` to see more options to start the three components

##### Running all in one
There is a handy command to start all the three components all in one:

```shell
$ cd ~/.tmkms
$ tmkms-nitro-helper launch-all -v
```