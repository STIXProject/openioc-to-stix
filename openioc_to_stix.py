#/usr/bin/env python

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# OpenIOC to STIX Script
# Wraps output of OpenIOC to CybOX Script
# v0.13

import sys
import os
import traceback
import warnings
import openioc #OpenIOC Bindings
import openioc_to_cybox #OpenIOC to CybOX Script
from cybox.core import Observables
import stix.utils
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader

__VERSION__ = 0.13

USAGE_TEXT = """
OpenIOC --> STIX Translator
v0.13 BETA // Compatible with STIX v1.1.1 and CybOX v2.1

Outputs a STIX Package with one or more STIX Indicators containing 
CybOX Observables translated from an input OpenIOC XML file. 

Usage: python openioc_to_stix.py -i <openioc xml file> -o <stix xml file>
"""

#Print the usage text
def usage():
    print USAGE_TEXT
    sys.exit(1)

def main():
    infilename = ''
    outfilename = ''

    #Get the command-line arguments
    args = sys.argv[1:]
    
    if len(args) < 4:
        usage()
        sys.exit(1)
        
    for i in range(0,len(args)):
        if args[i] == '-i':
            infilename = args[i+1]
        elif args[i] == '-o':
            outfilename = args[i+1]
    if os.path.isfile(infilename): 
        try:
            # Perform the translation using the methods from the OpenIOC to CybOX Script
            openioc_indicators = openioc.parse(infilename)
            observables_obj = openioc_to_cybox.generate_cybox(openioc_indicators, infilename, True)
            observables_cls = Observables.from_obj(observables_obj)

            # Set the namespace to be used in the STIX Package
            stix.utils.set_id_namespace({"https://github.com/STIXProject/openioc-to-stix":"openiocToSTIX"})

            # Wrap the created Observables in a STIX Package/Indicator
            stix_package = STIXPackage()
            # Add the OpenIOC namespace
            input_namespaces = {"http://openioc.org/":"openioc"}
            stix_package.__input_namespaces__ = input_namespaces

            for observable in observables_cls.observables:
                indicator_dict = {}
                producer_dict = {}
                producer_dict['tools'] = [{'name':'OpenIOC to STIX Utility', 'version':str(__VERSION__)}]
                indicator_dict['producer'] = producer_dict
                indicator_dict['title'] = "CybOX-represented Indicator Created from OpenIOC File"
                indicator = Indicator.from_dict(indicator_dict)
                indicator.add_observable(observables_cls.observables[0])
                stix_package.add_indicator(indicator)

            # Create and write the STIX Header
            stix_header = STIXHeader()
            stix_header.package_intent = "Indicators - Malware Artifacts"
            stix_header.description = "CybOX-represented Indicators Translated from OpenIOC File"
            stix_package.stix_header = stix_header

            # Write the generated STIX Package as XML to the output file
            outfile = open(outfilename, 'w')
            # Ignore any warnings - temporary fix for no schemaLocation w/ namespace
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                outfile.write(stix_package.to_xml())
                warnings.resetwarnings()
            outfile.flush()
            outfile.close()
        except Exception, err:
            print('\nError: %s\n' % str(err))
            traceback.print_exc()
    else:
        print('\nError: Input file not found or inaccessible.')
        sys.exit(1)

if __name__ == "__main__":
    main()    