#!/usr/bin/env python
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
OpenIOC to CybOX Translator.
Generates valid CybOX v2.1 XML output from OpenIOCs
"""

# builtin
import os
import sys
import argparse
import itertools
import logging

# python-cybox
from cybox import utils
from cybox.core import Observables
import cybox.bindings.cybox_core as cybox_binding
import cybox.bindings.cybox_common as cybox_common_binding

# openioc bindings and utilities
import openioc
import ioc_observable


__version__ = "0.3"


# Module logger. Lazily initialized
LOG = None

# Map of IndicatorItem conditions to CybOX operators
CONDITIONS = {
    'is': 'Equals',
    'isnot': 'DoesNotEqual',
    'contains': 'Contains',
    'containsnot': 'DoesNotContain'
}

# Exit codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def idgen(base=''):
    for cnt in itertools.count(start=1):
        yield base + str(cnt)

# Global identifier generator
OBSERVABLE_ID = idgen(base="openioc:indicator-item-")


def normalize_id(id):
    """Normalize any ids used in the IOC to make the compatible with CybOX
    This is just in case the normal UUID type is not used.
    """
    return id.replace(':','-')


def forcestring(value):
    """Test a value, if it is not an empty string or None, return it, otherwise
    return an empty string.
    """
    return value if value else ''


def error(fmt, *args):
     LOG.error(fmt, *args)
     sys.exit(EXIT_FAILURE)


def get_indicatoritem_string(indicatoritem, sep=''):
    """Build up a string representation of an entire OpenIOC IndicatorItem."""
    context = indicatoritem.get_Context()
    content = indicatoritem.get_Content()
    condition = forcestring(indicatoritem.get_condition())
    context_search = forcestring(context.get_search())
    context_document = forcestring(context.get_document())
    context_type = forcestring(context.get_type())
    content_type = forcestring(content.get_type())
    content_value = forcestring(content.get_valueOf_())
    comment = forcestring(indicatoritem.get_Comment())

    tokens = (condition, context_search, context_document, context_type,
              content_type, content_value, comment)

    indicatoritem_string = sep.join(tokens)

    return indicatoritem_string


def process_indicator_item(indicator_item, observables=None,
                           indicatoritem_dict=None):
    """Process an indicator item and create a single observable from it."""
    context = indicator_item.get_Context()
    content = indicator_item.get_Content()
    search_string = context.get_search()
    content_string = content.get_valueOf_().rstrip()
    condition = indicator_item.get_condition()
    relatedobj = None
    observable = None

    if observables:
        if indicator_item.get_id() is not None:
            id_string = 'openioc:indicator-item-' + normalize_id(indicator_item.get_id())
        else:
            id_string = next(OBSERVABLE_ID)
            indicatoritem_dict[get_indicatoritem_string(indicator_item)] = id_string
        observable = cybox_binding.ObservableType(id=id_string)

    # This could raise an exception
    properties = ioc_observable.createObj(search_string, content_string, CONDITIONS.get(condition))

    # Check if createObj returned only the expected object, or a list including a RelatedObject
    if utils.is_sequence(properties):
        properties = properties[0]
        relatedobj = properties[1]

    if properties:
        if observable:
            cyObject = cybox_binding.ObjectType(Properties=properties)
            observable.set_Object(cyObject)

            if relatedobj is not None:
                roType = cybox_binding.RelatedObjectsType()
                roType.add_Related_Object(relatedobj)
                cyObject.set_Related_Objects(roType)

            return observable
        return True

    if observable:
        skipped_term = forcestring(indicator_item.get_Context().get_search())

        description_text = (
            "Error|Ignore. IndicatorItem not translated. Encountered IOC "
            "term %s , which does not currently map to CybOX."
        )
        description_text = description_text % skipped_term
        description_text = utils.wrap_cdata (description_text)

        observable.set_Description(cybox_common_binding.StructuredTextType(valueOf_=description_text))
        return observable

    return False



def test_compatible_indicator(indicator):
    """#Test if an indicator is 'compatible', that is if it has at least one
    indicator item that is compatible with CybOX.
    """
    for indicator_item in indicator.get_IndicatorItem():
        if process_indicator_item(indicator_item):
            return True
    #Recurse as needed to handle embedded indicators
    for embedded_indicator in indicator.get_Indicator():
        if test_compatible_indicator(embedded_indicator):
            return True
        
    return False

#Process a single indicator and create the associated observable structure
def process_indicator(indicator, observables, observable_composition, top_level=True, embed_observables=False):
    if test_compatible_indicator(indicator):
        #Dictionary for keeping track of indicatoritems without IDs
        indicatoritem_dict = {}
        current_composition = None
        if not top_level:
            observable = cybox_binding.ObservableType(id='openioc:indicator-' + normalize_id(indicator.get_id()))
            nested_observable_composition = cybox_binding.ObservableCompositionType(operator=indicator.get_operator())
            observable.set_Observable_Composition(nested_observable_composition)
            observable_composition.add_Observable(observable)
            current_composition = nested_observable_composition
        elif top_level:
            current_composition = observable_composition
        
        for indicator_item in indicator.get_IndicatorItem():
            observable_obj = process_indicator_item(indicator_item, observables, indicatoritem_dict)
            if observable_obj:
                if embed_observables:
                    current_composition.add_Observable(observable_obj)
                else:
                    if indicator_item.get_id() is not None:
                        observable = cybox_binding.ObservableType(idref='openioc:indicator-item-' + normalize_id(indicator_item.get_id()))
                    else:
                        observable = cybox_binding.ObservableType(idref=indicatoritem_dict.get(get_indicatoritem_string(indicator_item)))
                    observables.add_Observable(observable_obj)
                    current_composition.add_Observable(observable)
                
        #Recurse as needed to handle embedded indicators
        for embedded_indicator in indicator.get_Indicator():
            process_indicator(embedded_indicator, observables, current_composition, False, embed_observables)
    else:
        return False
    
    return True

#Generate CybOX output from the OpenIOC indicators
def generate_cybox(indicators, infilename, embed_observables):
    #Create the core CybOX structure
    observables = cybox_binding.ObservablesType()

    #Set the description if it exists
    description = None
    if indicators.get_description() != None:
        description = indicators.get_description()
    elif indicators.get_short_description != None:
        description = indicators.get_short_description()
    
    indicator_definition = indicators.get_definition()
    for indicator in indicator_definition.get_Indicator():
        #Create the 'indicator' observable for holding the boolean indicator logic
        id_string = ''
        if indicator.get_id() is not None:
            id_string = 'openioc:indicator-' + normalize_id(indicator.get_id())
        else:
            id_string = 'openioc:indicator-' + generate_observable_id()
        indicator_observable = cybox_binding.ObservableType(id=id_string)
        #Set the title as appropriate
        if description != None:
            indicator_observable.set_Title(description)
        #Set observable source to IOC
        observable_source = cybox_common_binding.MeasureSourceType()
        observable_source_description = cybox_common_binding.StructuredTextType()
        observable_source_description.set_valueOf_('OpenIOC File: ' + os.path.basename(infilename))
        observable_source.set_Description(observable_source_description)
        indicator_observable.set_Observable_Source([observable_source])

        composition = cybox_binding.ObservableCompositionType(operator=indicator.get_operator())
        #Process the indicator, including any embedded indicators
        if process_indicator(indicator, observables, composition, True, embed_observables):
            indicator_observable.set_Observable_Composition(composition)
            observables.add_Observable(indicator_observable)
        else:
            #IOC had no indicator items compatible with CybOX
            return None

    return observables


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
        default=False,
        help="Verbose messages."
    )

    parser.add_argument(
        "-e",
        dest="embed",
        default=False,
        help="Verbose messages."
    )

    return parser


def init_logging(verbose=False):
    global LOG

    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    fmt = '[%(asctime)s] [%(levelname)s] %(message)s'
    logging.basicConfig(format=fmt, level=level)

    LOG = logging.getLogger(__name__)


def write_observables(observables, outfn):
    ns_dict = {'http://openioc.org/':'openioc'}

    with open(outfn, 'w') as outfile:
        xml = observables.to_xml(namespace_dict=ns_dict)
        outfile.write('<?xml version="1.0" encoding="utf-8"?>\n')
        outfile.write(xml)


def make_observables(indicators, embed_observables):
    observables = generate_cybox(indicators, embed_observables)

    if observables is None:
        msg = "Input file contained no indicator items compatible with CybOX"
        raise Exception(msg)

    observables.set_cybox_major_version('2')
    observables.set_cybox_minor_version('0')

    # Create and return Observables object
    return Observables.from_obj(observables)


def main():
    # Parse command line arguments
    argparser = get_arg_parser()
    args = argparser.parse_args()

    # Initialize the module logger.
    init_logging(args.verbose)

    try:
        LOG.info("Parsing OpenIOC file %s...", args.infile)
        indicators = openioc.parse(args.infile)

        LOG.info('Generating %s from %s...', args.outfile, args.infile)
        observables = make_observables(indicators, args.infile)

        # Write output to file
        write_observables(observables, args.embed)
    except Exception as ex:
        LOG.exception(ex)
        sys.exit(EXIT_FAILURE)

        
if __name__ == "__main__":
    main()    
