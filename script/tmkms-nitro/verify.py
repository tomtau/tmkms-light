# bech32 Copyright (c) 2017, Pieter Wuille (licensed under the MIT License)
# attestation verifier Copyright (c) 2020, Richard Fan (licensed under the Apache License, Version 2.0)
# Modifications Copyright (c) 2021-present, Crypto.com (licensed under the Apache License, Version 2.0)
import base64
import json
import sys
from datetime import datetime

import cbor2
from cose.keys.curves import P384
from cose.keys.ec2 import EC2
from cose.messages import Sign1Message
from Crypto.Util.number import long_to_bytes
from OpenSSL import crypto

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    # with amino prefix
    data = [0x16, 0x24, 0xDE, 0x64, 0x20] + data
    bdata = convertbits(data, 8, 5)
    combined = bdata + bech32_create_checksum(hrp, bdata)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def verify_attestation_doc(attestation_doc, root_cert_pem = None, bech32hrp = "crocnclconspub"):
    """
    Verify the attestation document
    If invalid, raise an exception
    """
    # Decode CBOR attestation document
    data = cbor2.loads(attestation_doc)

    # Load and decode document payload
    doc = data[2]
    doc_obj = cbor2.loads(doc)

    # https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
    # 3.2
    if 'module_id' not in doc_obj or len(doc_obj["module_id"]) == 0:
        raise Exception("module_id error")
    if 'digest' not in doc_obj or doc_obj["digest"] != "SHA384":
        raise Exception("digest error")
    if 'timestamp' not in doc_obj or doc_obj["timestamp"] == 0:
        raise Exception("timestamp error")
    time = datetime.fromtimestamp(doc_obj["timestamp"] / 1000)
    print(f"timestamp: {time}")
    # PCRs are printed for verification below
    if 'pcrs' not in doc_obj or len(doc_obj["pcrs"]) > 32 or len(doc_obj["pcrs"]) == 0:
        raise Exception("pcrs error")
    if 'certificate' not in doc_obj:
        raise Exception("certificate error")
    if 'cabundle' not in doc_obj or len(doc_obj["cabundle"]) == 0:
        raise Exception("cabundle error")
    # we also expect user data
    if 'user_data' not in doc_obj:
        raise Exception("user_data error")
    user_data = json.loads(doc_obj['user_data'])
    if 'pubkey' not in user_data or 'key_id' not in user_data:
        raise Exception("user_data error")
    key_id = base64.b64decode(user_data["key_id"])
    pubkey = base64.b64decode(user_data["pubkey"])
    pubkeyb64 = user_data["pubkey"]
    pubkeyb32 = bech32_encode(bech32hrp, list(pubkey))
    print("*** VERIFY user_data below (used AWS KMS key and generated pubkey) ***")
    print(f"AWS KMS key id: {key_id}")
    print(f"validator pubkey (base64): {pubkeyb64}")
    print(f"validator pubkey (bech32): {pubkeyb32}")

    # Get PCRs from attestation document
    document_pcrs_arr = doc_obj['pcrs']

    ###########################
    # Part 1: Validating PCRs #
    ###########################
    print("*** VERIFY PCRs below are complete and correct ***")
    for index in document_pcrs_arr.keys():

        # Get PCR hexcode
        doc_pcr = document_pcrs_arr[index].hex()

        print(f"PCR{index}: {doc_pcr}")


    ################################
    # Part 2: Validating signature #
    ################################

    # Get signing certificate from attestation document
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, doc_obj['certificate'])
    # Get the key parameters from the cert public key
    cert_public_numbers = cert.get_pubkey().to_cryptography_key().public_numbers()
    x = cert_public_numbers.x
    y = cert_public_numbers.y
    curve = cert_public_numbers.curve
    if curve != P384:
        Exception("Incorrect curve")
    x = long_to_bytes(x)
    y = long_to_bytes(y)

    # Create the EC2 key from public key parameters
    key = EC2(x = x, y = y, crv = P384)


    # Get the protected header from attestation document
    phdr = cbor2.loads(data[0])

    # Construct the Sign1 message
    msg = Sign1Message(phdr = phdr, uhdr = data[1], payload = doc, key = key)
    msg._signature = data[3]
    # Verify the signature using the EC2 key
    if not msg.verify_signature():
        raise Exception("Wrong signature")


    ##############################################
    # Part 3: Validating signing certificate PKI #
    ##############################################
    if root_cert_pem is not None:
        # Create an X509Store object for the CA bundles
        store = crypto.X509Store()

        # Create the CA cert object from PEM string, and store into X509Store
        _cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_pem)
        store.add_cert(_cert)

        # Get the CA bundle from attestation document and store into X509Store
        # Except the first certificate, which is the root certificate
        for _cert_binary in doc_obj['cabundle'][1:]:
            _cert = crypto.load_certificate(crypto.FILETYPE_ASN1, _cert_binary)
            store.add_cert(_cert)

        # add 10 seconds buffer to the current time if the cert expires
        if cert.has_expired():
            print(f"Certificate has expired at {cert.get_notAfter().decode('UTF-8')}, adding 10 seconds buffer for verification")
            cert.gmtime_adj_notAfter(10)

        # Get the X509Store context
        store_ctx = crypto.X509StoreContext(store, cert)
        
        # Validate the certificate
        # If the cert is invalid, it will raise exception
        # assuming this checks all items specified in 3.2.3.1. Certificates validity
        store_ctx.verify_certificate()
    return
if len(sys.argv) < 3:
    print("Usage: python verify.py <path to txt file with attestation payload in base64> <bech32 hrp for the public key>")
else:
    f = open(sys.argv[1], "r")
    # from: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
    r = """-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"""
    verify_attestation_doc(base64.b64decode(f.read()), r, sys.argv[2])
    f.close()
