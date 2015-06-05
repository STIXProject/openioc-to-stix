#/usr/bin/env python
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
OpenIOC to STIX Script
Wraps output of OpenIOC to CybOX Script
"""

# builtin
import sys
import argparse

# python-stix
from stix import utils
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.common.vocabs import PackageIntent

# python-cybox
from cybox.core import Observables
from cybox.common import ToolInformationList, ToolInformation

# openioc bindings and utilities
import openioc
import openioc_to_cybox


__version__ = "0.2"


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

    return parser


@utils.silence_warnings
def write_package(package, outfn):
    with open(outfn, "w") as f:
        xml = package.to_xml(ns_dict={"http://openioc.org/":"openioc"})
        f.write(xml)


def observable_to_indicator(observable):
    # Build CybOX tool content
    tool = ToolInformation(tool_name='OpenIOC to STIX Utility')
    tool.version = __version__

    # Build Indicator.producer contents
    producer = InformationSource()
    producer.tools = ToolInformationList(tool)

    # Build Indicator
    indicator = Indicator(title="CybOX-represented Indicator Created from OpenIOC File")
    indicator.producer = producer
    indicator.add_observable(observable)

    return indicator


def main():
    # Parse command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Create OpenIOC binding object
    openioc_indicators = openioc.parse(args.infile)

    # Create CybOX Observables bindings from OpenIOC binding object
    observables_obj = openioc_to_cybox.generate_cybox(
        indicators=openioc_indicators,
        infilename=args.infile,
        embed_observables=True
    )

    # Create Observables from binding object
    observables = Observables.from_obj(observables_obj)

    # Build Indicators from the Observable objects
    indicators = [observable_to_indicator(o) for o in observables]

    # Set the namespace to be used in the STIX Package
    utils.set_id_namespace({"https://github.com/STIXProject/openioc-to-stix":"openiocToSTIX"})

    # Wrap the created Observables in a STIX Package/Indicator
    stix_package = STIXPackage()

    # Set the Indicators collection
    stix_package.indicators = indicators

    # Create and write the STIX Header. Warning: these fields have been
    # deprecated in STIX v1.2!
    stix_header = STIXHeader()
    stix_header.package_intent = PackageIntent.TERM_INDICATORS_MALWARE_ARTIFACTS
    stix_header.description = "CybOX-represented Indicators Translated from OpenIOC File"
    stix_package.stix_header = stix_header

    # Write the STIXPackage to a output file
    write_package(stix_package, outfn=args.outfile)


if __name__ == "__main__":
    main()    