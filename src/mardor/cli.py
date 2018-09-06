#!/usr/bin/env python
"""Utility for managing mar files."""
from __future__ import print_function

import logging
import os
import sys
import tempfile
from argparse import REMAINDER
from argparse import ArgumentParser

import mardor.mozilla
from mardor.reader import MarReader
from mardor.signing import format_hash
from mardor.signing import get_keysize
from mardor.writer import MarWriter
from mardor.writer import add_signature_block

log = logging.getLogger(__name__)


def build_argparser():
    """Build argument parser for the CLI."""
    parser = ArgumentParser('Utility for managing MAR files')
    create_group = parser.add_argument_group("Create a MAR file")
    create_group.add_argument("-c", "--create", metavar="MARFILE", help="create MAR")
    create_group.add_argument("-V", "--productversion", dest="productversion",
                              help="product/version string")
    create_group.add_argument("-H", "--channel", dest="channel",
                              help="channel this MAR file is applicable to")
    create_group.add_argument("files", nargs=REMAINDER,
                              help="files to add to the MAR file")

    extract_group = parser.add_argument_group("Extract a MAR file")
    extract_group.add_argument("-x", "--extract", help="extract MAR", metavar="MARFILE")

    list_group = parser.add_argument_group("Print information on a MAR file")
    list_group.add_argument("-t", "--list", help="print out MAR contents",
                            metavar="MARFILE")
    list_group.add_argument("-T", "--list-detailed", metavar="MARFILE",
                            help="print out MAR contents including signatures")

    verify_group = parser.add_argument_group("Verify a MAR file")
    verify_group.add_argument("-v", "--verify", metavar="MARFILE",
                              help="verify the marfile")

    parser.add_argument("-j", "--bzip2", action="store_const", dest="compression",
                        const="bz2", help="compress/decompress members with BZ2")
    parser.add_argument("-J", "--xz", action="store_const", dest="compression",
                        const="xz", help="compress/decompress archive with XZ")
    parser.add_argument("--auto", action="store_const", dest="compression",
                        const="auto", help="automatically decompress contents")

    parser.add_argument("-k", "--keyfiles", dest="keyfiles", action='append',
                        help="sign/verify with given key(s)")
    parser.add_argument("-C", "--chdir", dest="chdir",
                        help="chdir to this directory before creating or "
                        "extracing; location of marfile isn't affected by "
                        "this option.")
    parser.add_argument("--verbose", dest="loglevel", action="store_const",
                        const=logging.DEBUG, default=logging.WARN,
                        help="increase logging verbosity")
    parser.add_argument('--version', action='version', version='mar version {}'.format(mardor.version_str))

    signing_group = parser.add_argument_group('Sign a MAR file')
    signing_group.add_argument('--hash', help='output hash for signing', choices=('sha1', 'sha384'))
    signing_group.add_argument('--asn1', help='format hash as an ASN1 DigestInfo block',
                               default=False, action='store_true')
    signing_group.add_argument('--add-signature', help='inject signature', nargs=3,
                               metavar=('input', 'output', 'signature'))

    return parser


def do_extract(marfile, destdir, decompress):
    """Extract the MAR file to the destdir."""
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            m.extract(str(destdir), decompress=decompress)


def get_keys(keyfiles, signature_type):
    """Get public keys for the given keyfiles.

    Args:
        keyfiles: List of filenames with public keys, or :mozilla- prefixed key
                  names
        signature_type: one of 'sha1' or 'sha384'

    Returns:
        List of public keys as strings

    """
    builtin_keys = {
        ('release', 'sha1'): [mardor.mozilla.release1_sha1, mardor.mozilla.release2_sha1],
        ('release', 'sha384'): [mardor.mozilla.release1_sha384, mardor.mozilla.release2_sha384],
        ('nightly', 'sha1'): [mardor.mozilla.nightly1_sha1, mardor.mozilla.nightly2_sha1],
        ('nightly', 'sha384'): [mardor.mozilla.nightly1_sha384, mardor.mozilla.nightly2_sha384],
        ('dep', 'sha1'): [mardor.mozilla.dep1_sha1, mardor.mozilla.dep2_sha1],
        ('dep', 'sha384'): [mardor.mozilla.dep1_sha384, mardor.mozilla.dep2_sha384],
    }
    keys = []
    for keyfile in keyfiles:
        if keyfile.startswith(':mozilla-'):
            name = keyfile.split(':mozilla-')[1]
            try:
                keys.extend(builtin_keys[name, signature_type])
            except KeyError:
                raise ValueError('Invalid internal key name: {}'
                                 .format(keyfile))
        else:
            key = open(keyfile, 'rb').read()
            keys.append(key)
    return keys


def do_verify(marfile, keyfiles):
    """Verify the MAR file."""
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            keys = get_keys(keyfiles, m.signature_type)
            if any(m.verify(key) for key in keys):
                print("Verification OK")
                return True
            else:
                print("Verification failed")
                sys.exit(1)


def do_list(marfile, detailed=False):
    """
    List the MAR file.

    Yields lines of text to output
    """
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            if detailed:
                if m.compression_type:
                    yield "Compression type: {}".format(m.compression_type)
                if m.signature_type:
                    yield "Signature type: {}".format(m.signature_type)
                if m.mardata.signatures:
                    plural = "s" if (m.mardata.signatures.count == 0 or m.mardata.signatures.count > 1) else ""
                    yield "Signature block found with {} signature{}".format(m.mardata.signatures.count, plural)
                    for s in m.mardata.signatures.sigs:
                        yield "- Signature {} size {}".format(s.algorithm_id, s.size)
                    yield ""
                if m.mardata.additional:
                    yield "{} additional block found:".format(len(m.mardata.additional.sections))
                    for s in m.mardata.additional.sections:
                        if s.id == 1:
                            yield ("  - Product Information Block:")
                            yield ("    - MAR channel name: {}".format(s.channel))
                            yield ("    - Product version: {}".format(s.productversion))
                            yield ""
                        else:
                            yield ("Unknown additional data")
            yield ("{:7s} {:7s} {:7s}".format("SIZE", "MODE", "NAME"))
            for e in m.mardata.index.entries:
                yield ("{:<7d} {:04o}    {}".format(e.size, e.flags, e.name))


def do_create(marfile, files, compress, productversion=None, channel=None,
              signing_key=None, signing_algorithm=None):
    """Create a new MAR file."""
    with open(marfile, 'w+b') as f:
        with MarWriter(f, productversion=productversion, channel=channel,
                       signing_key=signing_key,
                       signing_algorithm=signing_algorithm,
                       ) as m:
            for f in files:
                m.add(f, compress=compress)


def do_hash(hash_algo, marfile, asn1=False):
    """Output the hash for this MAR file."""
    # Add a dummy signature into a temporary file
    dst = tempfile.TemporaryFile()
    with open(marfile, 'rb') as f:
        add_signature_block(f, dst, hash_algo)

    dst.seek(0)

    with MarReader(dst) as m:
        hashes = m.calculate_hashes()
        h = hashes[0][1]
        if asn1:
            h = format_hash(h, hash_algo)
        print(h, end='')


def do_add_signature(input_file, output_file, signature_file):
    """Add a signature to the MAR file."""
    signature = open(signature_file, 'rb').read()
    if len(signature) == 256:
        hash_algo = 'sha1'
    elif len(signature) == 512:
        hash_algo = 'sha384'
    else:
        raise ValueError()

    with open(output_file, 'w+b') as dst:
        with open(input_file, 'rb') as src:
            add_signature_block(src, dst, hash_algo, signature)


def check_args(parser, args):
    """Validate commandline arguments."""
    # Make sure only one action has been specified
    if len([a for a in [args.create, args.extract, args.verify, args.list,
                        args.list_detailed, args.hash, args.add_signature] if a
            is not None]) != 1:
        parser.error("Must specify something to do (one of -c, -x, -t, -T, -v, --hash, --add-signature)")

    if args.create and not args.files:
        parser.error("Must specify at least one file to add to marfile")

    if args.verify and not args.keyfiles:
        parser.error("Must specify a key file when verifying")

    if args.extract and args.compression not in (None, 'bz2', 'xz', 'auto'):
        parser.error('Unsupported compression type')

    if args.create and args.compression not in (None, 'bz2', 'xz'):
        parser.error('Unsupported compression type')

    if args.hash and len(args.files) != 1:
        parser.error("Must specify a file to output the hash for")


def get_key_from_cmdline(parser, args):
    """Return the signing key and signing algoritm from the commandline."""
    if args.keyfiles:
        signing_key = open(args.keyfiles[0], 'rb').read()
        bits = get_keysize(signing_key)
        if bits == 2048:
            signing_algorithm = 'sha1'
        elif bits == 4096:
            signing_algorithm = 'sha384'
        else:
            parser.error("Unsupported key size {} from key {}".format(bits, args.keyfiles[0]))

        print("Using {} to sign using algorithm {!s}".format(args.keyfiles[0], signing_algorithm))
    else:
        signing_key = None
        signing_algorithm = None

    return signing_key, signing_algorithm


def main(argv=None):
    """Run the main CLI entry point."""
    parser = build_argparser()

    args = parser.parse_args(argv)

    logging.basicConfig(level=args.loglevel, format="%(message)s")

    check_args(parser, args)

    if args.extract:
        marfile = os.path.abspath(args.extract)
        if args.chdir:
            os.chdir(args.chdir)
        do_extract(marfile, os.getcwd(), args.compression)

    elif args.verify:
        do_verify(args.verify, args.keyfiles)

    elif args.list:
        print("\n".join(do_list(args.list)))

    elif args.list_detailed:
        print("\n".join(do_list(args.list_detailed, detailed=True)))

    elif args.create:
        marfile = os.path.abspath(args.create)
        signing_key, signing_algorithm = get_key_from_cmdline(parser, args)

        if args.chdir:
            os.chdir(args.chdir)
        do_create(marfile, args.files, args.compression,
                  productversion=args.productversion, channel=args.channel,
                  signing_key=signing_key, signing_algorithm=signing_algorithm)

    elif args.hash:
        do_hash(args.hash, args.files[0], args.asn1)

    elif args.add_signature:
        do_add_signature(args.add_signature[0], args.add_signature[1], args.add_signature[2])

    # sanity check; should never happen
    else:  # pragma: no cover
        parser.error("Unsupported action")
