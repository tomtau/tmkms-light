#! /usr/bin/env nix-shell
#!nix-shell -i bash 

./tmkms-softsign init
wget https://github.com/tendermint/tendermint/releases/download/v0.34.8/tendermint_0.34.8_linux_amd64.tar.gz
tar xvfz tendermint_0.34.8_linux_amd64.tar.gz
chmod +x tendermint
export TENDERMINT=tendermint
export TMHOME=.tendermint
export TMKMS=tmkms-softsign
export TMKMSCONFIG=tmkms.toml
python integration_test/bot.py prepare --tendermint tendermint --tmhome .tendermint --tmkms tmkms-softsign --kmsconfig tmkms.toml
pytest -v