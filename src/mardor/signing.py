# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Signing, verification and key support for MAR files."""
from construct import Int32ub
from construct import Int64ub
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils

from mardor.format import mar
from mardor.format import sigs_header
from mardor.utils import file_iter

_hash_algorithms = {
    'sha1': hashes.SHA1(),
    'sha384': hashes.SHA384(),
}


def get_publickey(keydata):
    """Load the public key from a PEM encoded string."""
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


def get_privatekey(keydata):
    """Load the private key from a PEM encoded string."""
    key = serialization.load_pem_private_key(
        keydata,
        password=None,
        backend=default_backend(),
    )
    return key


def get_keysize(keydata):
    """Return the key size of a public key."""
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

    fileobj.seek(0)
    marfile = mar.parse_stream(fileobj)
    if not marfile.signatures:
        raise IOError("Can't generate signature data for file without signature blocks")

    # MAR header
    fileobj.seek(0)
    block = fileobj.read(8)
    yield block

    # Signatures header
    sigs = sigs_header.parse_stream(fileobj)

    sig_types = [(sig.algorithm_id, sig.size) for sig in sigs.sigs]

    block = Int64ub.build(filesize) + Int32ub.build(sigs.count)
    yield block

    # Signature algorithm id and size per entry
    for algorithm_id, size in sig_types:
        block = Int32ub.build(algorithm_id) + Int32ub.build(size)
        yield block

    # Everything else in the file is covered
    for block in file_iter(fileobj):
        yield block


def make_hasher(algorithm_id):
    """Create a hashing object for the given signing algorithm."""
    if algorithm_id == 1:
        return hashes.Hash(hashes.SHA1(), default_backend())
    elif algorithm_id == 2:
        return hashes.Hash(hashes.SHA384(), default_backend())
    else:
        raise ValueError("Unsupported signing algorithm: %s" % algorithm_id)


def sign_hash(private_key, hash, hash_algo):
    """Sign the given hash with the given private key.

    Args:
        private_key (str): PEM enoded private key
        hash (byte str): hash to sign
        hash_algo (str): name of hash algorithm used

    Returns:
        byte string representing the signature

    """
    hash_algo = _hash_algorithms[hash_algo]
    return get_privatekey(private_key).sign(
        hash,
        padding.PKCS1v15(),
        utils.Prehashed(hash_algo),
    )


def verify_signature(public_key, signature, hash, hash_algo):
    """Verify the given signature is correct for the given hash and public key.

    Args:
        public_key (str): PEM encoded public key
        signature (bytes): signature to verify
        hash (bytes): hash of data
        hash_algo (str): hash algorithm used

    Returns:
        True if the signature is valid, False otherwise

    """
    hash_algo = _hash_algorithms[hash_algo]
    try:
        return get_publickey(public_key).verify(
            signature,
            hash,
            padding.PKCS1v15(),
            utils.Prehashed(hash_algo),
        ) is None
    except InvalidSignature:
        return False


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
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def make_dummy_signature(algorithm_id):
    """Return dummy signatures of the appropriate length.

    Args:
        algorithm_id (int): algorithm id for signatures. 1 is for 'sha1', 2 is
                            for 'sha384'

    Returns:
        a byte string

    """
    if algorithm_id == 1:
        return b'\x00' * 256
    elif algorithm_id == 2:
        return b'\x00' * 512
    else:
        raise ValueError("Invalid algorithm id: %s" % algorithm_id)


def format_hash(digest, hash_algo):
    """Format a hash as an ASN1 DigestInfo byte string.

    Args:
        digest (bytes): hash digest
        hash_algo (str): hash algorithm used, e.g. 'sha384'

    Returns:
        Byte string of ASN1 encoded digest info

    """
    prefixes = {
        'sha1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
        'sha384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    }
    return prefixes[hash_algo] + digest
