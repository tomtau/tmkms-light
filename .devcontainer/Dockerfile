# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.217.1/containers/rust/.devcontainer/base.Dockerfile

# [Choice] Debian OS version (use bullseye on local arm64/Apple Silicon): buster, bullseye
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/rust:0-${VARIANT}
RUN rustup default nightly-2022-02-07 && rustup target add x86_64-fortanix-unknown-sgx && rustup target add x86_64-fortanix-unknown-sgx && rustup target add x86_64-unknown-linux-musl && rustup component add rust-src rustfmt clippy
# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
     && apt-get -y install --no-install-recommends protobuf-compiler
