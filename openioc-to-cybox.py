#!/usr/bin/env python
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
OpenIOC to CybOX Translator.
Generates valid CybOX v2.1 XML output from OpenIOCs
"""

# builtin
import sys
import argparse
import logging

# python-cybox
import cybox.utils

# Internal
import translate


__version__ = "0.3"


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

    with open(outfn, 'w') as outfile:
        outfile.write('<?xml version="1.0" encoding="utf-8"?>\n')
        outfile.write(xml)

def init_id_namespace():
    ns = cybox.utils.Namespace(name="http://openioc.org/", prefix="openioc")
    cybox.utils.set_id_namespace(ns)


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
