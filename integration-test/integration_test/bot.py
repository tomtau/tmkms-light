#!/usr/bin/env python3
import fire
import tomlkit
import os
from pathlib import Path
import subprocess
import json

class CLI:
    def prepare(self, tendermint=None, tmkms=None, tmhome=None, kmsconfig=None):
        '''Prepare tendermint node with tmkms executable
        :param tendermint: Path of tendermint, [default: tendermint]
        :param tmkms: Path of tmkms-light, [default: tmkms-softsign]
        :param tmhome: Path of tendermint home path, [default: .tendermint]
        :param kmsconfig: Path of tmkms.toml, [default: tmkms.toml]

        '''
        tendermint = tendermint if tendermint else "tendermint"
        tmkms = tmkms if tmkms else "tmkms-softsign"
        tmhome = tmhome if tmhome else ".tendermint"
        kmsconfig = kmsconfig if kmsconfig else "tmkms.toml"
        chainid = "testchain-1"
        privsock = "unix:///tmp/test.socket"
        tm_config = tmhome + "/config/config.toml"
        genesis_path = tmhome + "/config/genesis.json"

        os.system(tendermint + " init --home " + tmhome)
        node0 = tomlkit.parse(Path(tm_config).read_text())
        node0["proxy_app"] = "counter"
        node0["priv_validator_laddr"] = privsock
        open(tm_config, "w").write(tomlkit.dumps(node0))
        os.system(tmkms + " init -c " + kmsconfig)
        node0 = tomlkit.parse(Path(kmsconfig).read_text())
        node0["address"] = privsock
        node0["chain_id"] = chainid
        open(kmsconfig, "w").write(tomlkit.dumps(node0))
        process = subprocess.Popen([tmkms, "pubkey", "-c",  kmsconfig], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _stderr = process.communicate()
        parts = stdout.split()
        encoding = "utf-8"
        address = parts[4].decode(encoding)
        pubkey = parts[2].decode(encoding)
        genesis = json.loads(Path(genesis_path).read_text())
        genesis["validators"][0]["address"] = address
        genesis["validators"][0]["pub_key"]["value"] = pubkey
        genesis["chain_id"] = chainid
        open(genesis_path, "w").write(json.dumps(genesis))





if __name__ == '__main__':
    fire.Fire(CLI())