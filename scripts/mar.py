#!/usr/bin/env python
"""%prog [options] -x|-t|-c marfile [files]

Utility for managing mar files"""

# The canonical location for this file is
#   https://hg.mozilla.org/build/tools/file/default/buildfarm/utils/mar.py
#
# Please update the copy in puppet to deploy new changes to
# stage.mozilla.org, see
# https://wiki.mozilla.org/ReleaseEngineering/How_To/Modify_scripts_on_stage
#
# The MAR format is documented at
# https://wiki.mozilla.org/Software_Update:MAR

import os

from mardor.marfile import MarFile, BZ2MarFile

import logging
log = logging.getLogger(__name__)


def main():
    from optparse import OptionParser

    parser = OptionParser(__doc__)
    parser.set_defaults(
        action=None,
        bz2=False,
        chdir=None,
        keyfile=None,
        verify=False,
        loglevel=logging.INFO,
    )
    parser.add_option("-x", "--extract", action="store_const", const="extract",
                      dest="action", help="extract MAR")
    parser.add_option("-t", "--list", action="store_const", const="list",
                      dest="action", help="print out MAR contents")
    parser.add_option("-c", "--create", action="store_const", const="create",
                      dest="action", help="create MAR")
    parser.add_option("-j", "--bzip2", action="store_true", dest="bz2",
                      help="compress/decompress members with BZ2")
    parser.add_option("-k", "--keyfile", dest="keyfile",
                      help="sign/verify with given key")
    parser.add_option("-v", "--verify", dest="verify", action="store_true",
                      help="verify the marfile")
    parser.add_option("-C", "--chdir", dest="chdir",
                      help="chdir to this directory before creating or "
                      "extracing; location of marfile isn't affected by "
                      "this option.")
    parser.add_option("--verbose", dest="loglevel", action="store_const",
                      const=logging.DEBUG)

    options, args = parser.parse_args()

    logging.basicConfig(level=options.loglevel, format="%(message)s")

    if not options.action:
        parser.error("Must specify something to do (one of -x, -t, -c)")

    if not args:
        parser.error("You must specify at least a marfile to work with")

    marfile, files = args[0], args[1:]
    marfile = os.path.abspath(marfile)

    if options.bz2:
        mar_class = BZ2MarFile
    else:
        mar_class = MarFile

    signatures = []
    if options.keyfile:
        signatures.append((1, options.keyfile))

    # Move into the directory requested
    if options.chdir:
        os.chdir(options.chdir)

    if options.action == "extract":
        with mar_class(marfile) as m:
            m.extractall()

    elif options.action == "list":
        with mar_class(marfile, signature_versions=signatures) as m:
            if options.verify:
                m.verify_signatures()
            log.info("%-7s %-7s %-7s", "SIZE", "MODE", "NAME")
            for m in m.members:
                log.info("%-7i %04o    %s", m.size, m.flags, m.name)

    elif options.action == "create":
        if not files:
            parser.error("Must specify at least one file to add to marfile")
        with mar_class(marfile, "w", signature_versions=signatures) as m:
            for f in files:
                m.add(f)

if __name__ == "__main__":
    main()
