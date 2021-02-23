from integration_test import __version__
import os
import subprocess
import urllib.request
import json

def test_basic():
    tm = os.getenv('TENDERMINT')
    tmhome = os.getenv('TMHOME')
    tmkms = os.getenv('TMKMS')
    kmsconfig = os.getenv('TMKMSCONFIG')
    tmkms_proc = subprocess.Popen([tmkms, "start", "-c",  kmsconfig], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tm_proc = subprocess.Popen([tm, "node", "--home",  tmhome], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    contents = urllib.request.urlopen("http://localhost:26657/status").read()
    status = json.loads(contents)
    block_height = int(status["result"]["sync_info"]["latest_block_height"])
    # TODO: verify validator address / key matches tmkms one
    assert block_height >= 1
