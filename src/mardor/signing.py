# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Signing, verification and key support for MAR files."""
from enum import IntEnum

from construct import Int32ub
from construct import Int64ub
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

from mardor.format import sigs_header
from mardor.utils import file_iter


class SigningAlgo(IntEnum):
    """
    Enum representing supported signing algorithms.

    SHA1: RSA-PKCS1-SHA1 using 2048 bit key
    SHA384: RSA-PKCS1-SHA384 using 4096 bit key
    """
    SHA1 = 1
    SHA384 = 2


def get_publickey(keydata):
    try:
        key = serialization.load_pem_public_key(
            keydata,
            backend=default_backend(),
        )
        return key
    except ValueError:
        key = serialization.load_pem_private_key(
            keydata,
            password=None,
            backend=default_backend(),
        )
        key = key.public_key()
        return key


def get_keysize(keydata):
    key = get_publickey(keydata)
    return key.key_size


def get_signature_data(fileobj, filesize):
    """Read data from MAR file that is required for MAR signatures.

    Args:
        fileboj (file-like object): file-like object to read the MAR data from
        filesize (int): the total size of the file

    Yields:
        blocks of bytes representing the data required to generate or validate
        signatures.
    """
    # Read everything except the signature entries
    # The first 8 bytes are covered, as is everything from the beginning
    # of the additional section to the end of the file. The signature
    # algorithm id and size fields are also covered.

    # MAR header
    fileobj.seek(0)
    block = fileobj.read(8)
    yield block

    # Signatures header
    sigs = sigs_header.parse_stream(fileobj)
    block = Int64ub.build(filesize) + Int32ub.build(sigs.count)
    yield block

    # Signature algorithm id and size per entry
    for sig in sigs.sigs:
        block = Int32ub.build(sig.algorithm_id) + Int32ub.build(sig.size)
        yield block

    # Everything else in the file is covered
    for block in file_iter(fileobj):
        yield block


def make_verifier_v1(public_key, signature):
    """Create verifier object to verify a `signature`.

    Args:
        public_key (str): PEM formatted public key
        signature (bytes): signature to verify

    Returns:
        A cryptography key verifier object
    """
    key = get_publickey(public_key)
    if key.key_size != 2048:
        raise ValueError('2048 bit RSA key required')

    verifier = key.verifier(
        signature,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    return verifier


def make_verifier_v2(public_key, signature):
    """Create verifier object to verify a `signature`.

    Args:
        public_key (str): PEM formatted public key
        signature (bytes): signature to verify

    Returns:
        A cryptography key verifier object
    """
    key = get_publickey(public_key)
    if key.key_size != 4096:
        raise ValueError('2048 bit RSA key required')
    verifier = key.verifier(
        signature,
        padding.PKCS1v15(),
        hashes.SHA384(),
    )
    return verifier


def make_signer_v1(private_key):
    """Create a signer object that signs using `private_key`.

    Args:
        private_key (str): PEM formatted private key

    Returns:
        A cryptography key signer object
    """
    key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend(),
    )
    if key.key_size != 2048:
        raise ValueError('2048 bit RSA key required')
    signer = key.signer(
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    return signer


def make_signer_v2(private_key):
    """Create a signer object that signs using `private_key`.

    Args:
        private_key (str): PEM formatted private key

    Returns:
        A cryptography key signer object
    """
    key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend(),
    )
    if key.key_size != 4096:
        raise ValueError('2048 bit RSA key required')
    signer = key.signer(
        padding.PKCS1v15(),
        hashes.SHA384(),
    )
    return signer


def make_rsa_keypair(bits):
    """Generate an RSA keypair.

    Args:
        bits (int): number of bits to use for the key.

    Returns:
        (private_key, public_key) - both as PEM encoded strings
    """
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
