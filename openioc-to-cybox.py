#!/usr/bin/env python
# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
openioc-to-cybox: OpenIOC to CybOX conversion utility.
"""

# builtin
import sys
import argparse
import logging
import codecs

# python-cybox
import cybox.utils

# Internal
from openioc2stix import translate
from openioc2stix.version import __version__

# mixbox
from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace

# Module logger.
LOG = logging.getLogger(__name__)

# Exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def error(fmt, *args):
    LOG.error(fmt, *args)
    sys.exit(EXIT_FAILURE)


def get_arg_parser():
    desc = "OpenIOC to CybOX v%s" % __version__
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
        action="store_true",
        default=False,
        help="Verbose output."
    )

    return parser


def init_logging(verbose=False):
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    fmt = '[%(asctime)s] [%(levelname)s] %(message)s'
    logging.basicConfig(format=fmt, level=level)


def write_observables(observables, outfn):
    # namespaces = {'http://openioc.org/':'openioc'}
    namespaces = {}
    xml = observables.to_xml(namespace_dict=namespaces)

    with open(outfn, 'wb') as outfile:
        bytes = codecs.encode('<?xml version="1.0" encoding="utf-8"?>\n')
        outfile.write(bytes)
        outfile.write(xml)

def init_id_namespace():
    # setup namespace...
    short_namespace = "openioc"
    namespace = Namespace("http://openioc.org/", short_namespace)
    set_id_namespace(namespace)


def main():
    # Parse command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Initialize the module logger.
    init_logging(args.verbose)

    # Set the id namespace
    init_id_namespace()

    try:
        # Convert the input document to a CybOx Observables document
        observables = translate.to_cybox(args.infile)

        # Write output to file
        write_observables(observables, args.outfile)
    except Exception as ex:
        LOG.exception(ex)
        sys.exit(EXIT_FAILURE)


if __name__ == "__main__":
    main()
