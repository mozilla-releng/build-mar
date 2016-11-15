#!/usr/bin/env python
"""Utility for managing mar files."""

# The MAR format is documented at
# https://wiki.mozilla.org/Software_Update:MAR

import os
import sys
from argparse import ArgumentParser, REMAINDER

from mardor.reader import MarReader
from mardor.writer import MarWriter
import mardor.mozilla

import logging
log = logging.getLogger(__name__)


def build_argparser():
    """Build argument parser for the CLI."""
    parser = ArgumentParser('Utility for managing MAR files')
    parser.add_argument("-x", "--extract", action="store_const",
                        const="extract", dest="action", help="extract MAR")
    parser.add_argument("-t", "--list", action="store_const", const="list",
                        dest="action", help="print out MAR contents")
    parser.add_argument("-c", "--create", action="store_const", const="create",
                        dest="action", help="create MAR")
    parser.add_argument("-j", "--bzip2", action="store_true", dest="bz2",
                        help="compress/decompress members with BZ2")
    parser.add_argument("-k", "--keyfiles", dest="keyfiles", action='append',
                        help="sign/verify with given key(s)")
    parser.add_argument("-v", "--verify", dest="verify", action="store_true",
                        help="verify the marfile", default=False)
    parser.add_argument("-C", "--chdir", dest="chdir",
                        help="chdir to this directory before creating or "
                        "extracing; location of marfile isn't affected by "
                        "this option.")
    parser.add_argument("--verbose", dest="loglevel", action="store_const",
                        const=logging.DEBUG, default=logging.WARN)

    parser.add_argument("marfile")
    parser.add_argument("files", nargs=REMAINDER)

    return parser


def do_extract(marfile, decompress, destdir):
    """Extract the MAR file to the destdir."""
    with open(marfile, 'rb') as f:
        with MarReader(f, decompress=decompress) as m:
            m.extract(destdir)


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


def do_list(marfile):
    """List the MAR file."""
    # TODO: keep the prints?
    with open(marfile, 'rb') as f:
        with MarReader(f) as m:
            if m.mardata.additional:
                for s in m.mardata.additional.sections:
                    if s.id == 1:
                        print("Product version: {}".format(s.productversion))
                        print("Channel: {}".format(s.channel))
                    else:
                        print(s)
            print("{:7s} {:7s} {:7s}".format("SIZE", "MODE", "NAME"))
            for e in m.mardata.index.entries:
                print("{:7d} {:04o}    {}".format(e.size, e.flags, e.name))


def do_create(marfile, files, compress):
    """Create anew MAR file."""
    with open(marfile, 'w+b') as f:
        # TODO: extra info, signature
        with MarWriter(f, compress=compress) as m:
            for f in files:
                m.add(f)


def main(argv=None):
    """Main CLI entry point."""
    parser = build_argparser()

    args = parser.parse_args(argv)

    logging.basicConfig(level=args.loglevel, format="%(message)s")

    if not args.action:
        parser.error("Must specify something to do (one of -x, -t, -c)")

    if args.action == 'create' and not args.files:
        parser.error("Must specify at least one file to add to marfile")

    if args.verify and not args.keyfiles:
        parser.error("Must specify a key file when verifying")

    marfile = os.path.abspath(args.marfile)

    # Move into the directory requested; we already have the absolute path of
    # the MAR file
    if args.chdir:
        os.chdir(args.chdir)

    if args.action == "extract":
        decompress = 'bz2' if args.bz2 else None
        do_extract(marfile, decompress, os.getcwd())

    elif args.action == "list":
        if args.verify:
            if do_verify(marfile, args.keyfiles):
                print("Verification OK")
            else:
                print("Verification failed")
                sys.exit(1)

        do_list(marfile)

    elif args.action == "create":
        compress = 'bz2' if args.bz2 else None
        do_create(marfile, args.files, compress)
