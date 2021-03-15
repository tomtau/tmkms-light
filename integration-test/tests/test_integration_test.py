from integration_test import __version__
import os
import subprocess
import urllib.request
import json
import time
from pathlib import Path

def test_basic():
    tm = os.getenv('TENDERMINT')
    tmhome = os.getenv('TMHOME')
    tmkms = os.getenv('TMKMS')
    kmsconfig = os.getenv('TMKMSCONFIG')
    tmkms_proc = subprocess.Popen([tmkms, "start", "-c",  kmsconfig], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tm_proc = subprocess.Popen([tm, "node", "--home",  tmhome], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    contents = None
    start_time = time.perf_counter()
    timeout = 30
    rpc_base = "http://127.0.0.1:26657"
    status_url = rpc_base + "/status"
    block_url = rpc_base + "/block"
    while True:
        try:
            contents = urllib.request.urlopen(status_url).read()
            break
        except Exception as e:
            time.sleep(1)
            if time.perf_counter() - start_time >= timeout:
                tm_output = tm_proc.stdout.readlines()
                tmkms_output = tmkms_proc.stdout.readlines()
                tmkms_err = tmkms_proc.stderr.readlines()
                raise TimeoutError('Waited too long for the RPC port. tm: {}, tmkms: {} {}'.format(tm_output, tmkms_output, tmkms_err)) from e
    time.sleep(5)
    contents = urllib.request.urlopen(status_url).read()
    status = json.loads(contents)
    block_height = int(status["result"]["sync_info"]["latest_block_height"])
    assert block_height >= 1
    contents = urllib.request.urlopen(block_url).read()
    block = json.loads(contents)
    validator_address = block['result']['block']['last_commit']['signatures'][0]['validator_address']
    genesis_path = tmhome + "/config/genesis.json"
    genesis = json.loads(Path(genesis_path).read_text())
    assert validator_address == genesis["validators"][0]["address"] 
