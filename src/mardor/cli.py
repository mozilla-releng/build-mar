#!/usr/bin/env python
"""Utility for managing mar files."""

# The MAR format is documented at
# https://wiki.mozilla.org/Software_Update:MAR

import logging
import os
import sys
from argparse import REMAINDER
from argparse import ArgumentParser

import mardor.mozilla
from mardor.reader import MarReader
from mardor.signing import SigningAlgo
from mardor.signing import get_keysize
from mardor.writer import MarWriter

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

    parser.add_argument("-j", "--bzip2", action="store_true", dest="bz2",
                        help="compress/decompress members with BZ2")

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

    return parser


def do_extract(marfile, destdir, decompress):
    """Extract the MAR file to the destdir."""
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            m.extract(str(destdir), decompress=decompress)


def do_verify(marfile, keyfiles):
    """Verify the MAR file."""
    keys = []
    for keyfile in keyfiles:
        if keyfile.startswith(':mozilla-'):
            name = keyfile.split(':mozilla-')[1]
            if name == 'release':
                keys.append(mardor.mozilla.release1)
                keys.append(mardor.mozilla.release2)
            elif name == 'nightly':
                keys.append(mardor.mozilla.nightly1)
                keys.append(mardor.mozilla.nightly2)
            elif name == 'dep':
                keys.append(mardor.mozilla.dep1)
                keys.append(mardor.mozilla.dep2)
            else:
                raise ValueError('Invalid internal key name: {}'
                                 .format(keyfile))
        else:
            key = open(keyfile, 'rb').read()
            keys.append(key)

    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            return any(m.verify(key) for key in keys)


def do_list(marfile, detailed=False):
    """
    List the MAR file.

    Yields lines of text to output
    """
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            if detailed:
                if m.mardata.signatures:
                    yield "Signature block found with {} signature".format(m.mardata.signatures.count)
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
                       signing_algorithm=signing_algorithm) as m:
            for f in files:
                m.add(f, compress=compress)


def main(argv=None):
    """Main CLI entry point."""
    parser = build_argparser()

    args = parser.parse_args(argv)

    logging.basicConfig(level=args.loglevel, format="%(message)s")

    # Make sure only one action has been specified
    if len([a for a in [args.create, args.extract, args.verify, args.list, args.list_detailed] if a is not None]) != 1:
        parser.error("Must specify something to do (one of -c, -x, -t, -T, -v)")

    if args.create and not args.files:
        parser.error("Must specify at least one file to add to marfile")

    if args.verify and not args.keyfiles:
        parser.error("Must specify a key file when verifying")

    if args.extract:
        marfile = os.path.abspath(args.extract)
        decompress = mardor.reader.Decompression.bz2 if args.bz2 else None
        if args.chdir:
            os.chdir(args.chdir)
        do_extract(marfile, os.getcwd(), decompress)

    elif args.verify:
        if do_verify(args.verify, args.keyfiles):
            print("Verification OK")
            return
        else:
            print("Verification failed")
            sys.exit(1)

    elif args.list:
        print("\n".join(do_list(args.list)))

    elif args.list_detailed:
        print("\n".join(do_list(args.list_detailed, detailed=True)))

    elif args.create:
        compress = mardor.writer.Compression.bz2 if args.bz2 else None
        marfile = os.path.abspath(args.create)
        if args.keyfiles:
            signing_key = open(args.keyfiles[0], 'rb').read()
            bits = get_keysize(signing_key)
            if bits == 2048:
                signing_algorithm = SigningAlgo.SHA1
            elif bits == 4096:
                signing_algorithm = SigningAlgo.SHA384
            else:
                parser.error("Unsupported key size {} from key {}".format(bits, args.keyfiles[0]))

            print("Using {} to sign using algorithm {!s}".format(args.keyfiles[0], signing_algorithm))
        else:
            signing_key = None
            signing_algorithm = None

        if args.chdir:
            os.chdir(args.chdir)
        do_create(marfile, args.files, compress,
                  productversion=args.productversion, channel=args.channel,
                  signing_key=signing_key, signing_algorithm=signing_algorithm)

    # sanity check; should never happen
    else:  # pragma: no cover
        parser.error("Unsupported action")
