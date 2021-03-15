#! /usr/bin/env nix-shell
#!nix-shell -i bash 

cp ../target/debug/tmkms-softsign .
chmod +x tmkms-softsign
./tmkms-softsign init
wget https://github.com/tendermint/tendermint/releases/download/v0.34.8/tendermint_0.34.8_linux_amd64.tar.gz
tar xvfz tendermint_0.34.8_linux_amd64.tar.gz
chmod +x tendermint
python integration_test/bot.py prepare --tendermint tendermint --tmhome .tendermint --tmkms tmkms-softsign --kmsconfig tmkms.toml
pytest -v