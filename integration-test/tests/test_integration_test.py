from integration_test import __version__
import os
import subprocess
import urllib.request
import json
import time

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
    while True:
        try:
            contents = urllib.request.urlopen("http://127.0.0.1:26657/status").read()
            break
        except Exception as e:
            time.sleep(1)
            if time.perf_counter() - start_time >= timeout:
                tm_output = tm_proc.stdout.readlines()
                tmkms_output = tmkms_proc.stdout.readlines()
                raise TimeoutError('Waited too long for the RPC port. tm: {}, tmkms: {}'.format(tm_output, tmkms_output)) from e
    status = json.loads(contents)
    block_height = int(status["result"]["sync_info"]["latest_block_height"])
    # TODO: verify validator address / key matches tmkms one
    assert block_height >= 1
