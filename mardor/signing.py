#!/usr/bin/env python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

from construct import Int64ub, Int32ub

from mardor.format import sigs_header
from mardor.utils import file_iter


def calculate_signatures(fileobj, filesize, hashers):
    # Read everything except the signature entries
    # The first 8 bytes are covered, as is everything from the beginning
    # of the additional section to the end of the file. The signature
    # algorithm id and size fields are also covered.

    # MAR header
    fileobj.seek(0)
    block = fileobj.read(8)
    [h.update(block) for h in hashers]

    # Signatures header
    sigs = sigs_header.parse_stream(fileobj)
    block = Int64ub.build(filesize) + Int32ub.build(sigs.count)
    [h.update(block) for h in hashers]

    # Signature algorithm id and size per entry
    for sig in sigs.sigs:
        block = Int32ub.build(sig.algorithm_id) + Int32ub.build(sig.size)
        [h.update(block) for h in hashers]

    # Everything else in the file is covered
    for block in file_iter(fileobj):
        [h.update(block) for h in hashers]


def make_verifier_v1(public_key, signature):
    key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend(),
    )
    verifier = key.verifier(
        signature,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    return verifier


def make_signer_v1(private_key):
    key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend(),
    )
    signer = key.signer(
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    return signer


def make_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem
