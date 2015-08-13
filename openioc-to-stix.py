#!/usr/bin/env python
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
OpenIOC to STIX Script
Wraps output of OpenIOC to CybOX Script
"""
# builtin
import logging
import argparse

# python-stix
from stix import utils

# Internal
from openioc2stix import translate
from openioc2stix.version import __version__


LOG = logging.getLogger(__name__)

# Exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def get_arg_parser():
    desc = "OpenIOC to STIX v%s" % __version__
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "-i",
        required=True,
        dest="infile",
        help="Input OpenIOC XML filename"
    )

    parser.add_argument(
        "-o",
        required=True,
        dest="outfile",
        help="Ouput STIX XML filename"
    )

    parser.add_argument(
        "-v",
        dest="verbose",
        default=False,
        help="Verbose output."
    )

    return parser


@utils.silence_warnings
def write_package(package, outfn):
    with open(outfn, "w") as f:
        xml = package.to_xml()
        f.write(xml)


def init_logging(verbose=False):
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    fmt = '[%(asctime)s] [%(levelname)s] %(message)s'
    logging.basicConfig(format=fmt, level=level)


def main():
    # Parse command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # initialize logging
    init_logging(args.verbose)
    # Set the namespace to be used in the STIX Package
    utils.set_id_namespace({"http://openioc.org/openioc":"openioc"})

    # Create Observables from binding object
    stix_package = translate.to_stix(args.infile)

    # Write the STIXPackage to a output file
    write_package(stix_package, outfn=args.outfile)


if __name__ == "__main__":
    main()
