# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

#OpenIOC to CybOX Translator
#v0.22 BETA
#Generates valid CybOX v2.1 XML output from OpenIOCs
import openioc
from cybox.core import Observables
from cybox.utils import Namespace
import cybox.bindings.cybox_core as cybox_binding
import cybox.bindings.cybox_common as cybox_common_binding
import ioc_observable
import sys
import os
import traceback

#Normalize any ids used in the IOC to make the compatible with CybOX
#This is just in case the normal UUID type is not used
def normalize_id(id):
    if id.count(':') > 0:
        return id.replace(':','-')
    else:
        return id

#Test a value, if it is not an empty string or None, return it, otherwise return an empty string
def string_test(value):
    if value is not None and len(str(value)) > 0:
        return value
    else:
        return ''

#Build up a string representation of an entire OpenIOC IndicatorItem
def get_indicatoritem_string(indicatoritem, separator = None):
    context = indicatoritem.get_Context()
    content = indicatoritem.get_Content()
    condition = string_test(indicatoritem.get_condition())
    context_search = string_test(context.get_search())
    context_document = string_test(context.get_document())
    context_type = string_test(context.get_type())
    content_type = string_test(content.get_type())
    content_value = string_test(content.get_valueOf_())
    comment = string_test(indicatoritem.get_Comment())
    if separator is None:
        indicatoritem_string = condition + context_search + context_document\
        + context_type + content_type + content_value
    else:
        indicatoritem_string = condition + separator + context_search + separator\
        + context_document + separator + context_type + separator + content_type\
        + separator +  content_value
    return indicatoritem_string

#Map an IndicatorItem condition to a CybOX operator
def map_condition_keywords(condition):
    condition_dict = {
        'is':'Equals',
        'isnot':'DoesNotEqual',
        'contains':'Contains',
        'containsnot':'DoesNotContain'
    }
    return condition_dict.get(condition)

#Process an indicator item and create a single observable from it
def process_indicator_item(indicator_item, observables = None, indicatoritem_dict = None):
    context = indicator_item.get_Context()
    content = indicator_item.get_Content()
    search_string = context.get_search()
    content_string = content.get_valueOf_().rstrip()
    condition = indicator_item.get_condition()
    relatedobj = None
    observable = None

    if observables:
        id_string = ''
        if indicator_item.get_id() is not None:
            id_string = 'openioc:indicator-item-' + normalize_id(indicator_item.get_id())
        else:
            id_string = 'openioc:indicator-item-' + generate_observable_id()
            indicatoritem_dict[get_indicatoritem_string(indicator_item)] = id_string
        observable = cybox_binding.ObservableType(id=id_string)

    try:
        properties = ioc_observable.createObj(search_string, content_string, map_condition_keywords(condition))
    except Exception as e:
        if observable:
            description_text = str("<![CDATA[{0}]]>").format("Error|Fatal. Encountered error when attempting IndicatorItem translation:" + str(e)) 
    #check if createObj returned only the expected object, or a list including a RelatedObject
    if type(properties) is list:
        relatedobj = properties[1] 
        properties = properties[0]

    if properties:
        if observable:
            cyObject = cybox_binding.ObjectType(Properties=properties)
            observable.set_Object(cyObject)
            if relatedobj != None:
                roType = cybox_binding.RelatedObjectsType()
                roType.add_Related_Object(relatedobj)
                cyObject.set_Related_Objects(roType)
            return observable
        return True
    else:
        if observable:
            skipped_term = string_test(indicator_item.get_Context().get_search())
            description_text = str("<![CDATA[{0}]]>").format("Error|Ignore. IndicatorItem not translated. Encountered IOC term "\
                + skipped_term + ", which does not currently map to CybOX.") 
            observable.set_Description(cybox_common_binding.StructuredTextType(valueOf_=description_text))       
            return observable
        return False
    return

#Test if an indicator is 'compatible', that is if it has at least one indicator item that is compatible with CybOX
def test_compatible_indicator(indicator):
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

#Helper methods
def generate_observable_id():
    global obsv_id_base
    obsv_id_base += 1
    return str(obsv_id_base)

def generate_object_id():
    global obj_id_base
    obj_id_base += 1
    return str(obj_id_base)
    
#Print the usage text
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
OpenIOC --> CybOX XML Converter Utility
v0.22 BETA // Compatible with CybOX v2.1

Usage: python openioc_to_cybox.py <flags> -i <openioc xml file> -o <cybox xml file>

Available Flags:
    -e: Embedded Observable Output Mode. Creates a single root Observable with nested Observable Composition and Observables.
        If this mode is not specified, the script will create a single Observable at the root level for each Indicator Item
        and then add a separate Observable with the Boolean logic that composes the indicator, via Observable_Compositions.
    -v: Verbose output mode. Lists any skipped indicator items and also prints traceback for errors.
"""
obsv_id_base = 0    
obj_id_base = 0

def main():
    infilename = ''
    outfilename = ''
    global verbose_mode
    global skipped_indicators
    embed_observables = False
    verbose_mode = False
    skipped_indicators = []
    
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
        elif args[i] == '-v':
            verbose_mode = True
        elif args[i] == '-e':
            embed_observables = True
            
    #Basic input file checking
    if os.path.isfile(infilename):    
        #Parse the OpenIOC file
        indicators = openioc.parse(infilename)
        try:
            print 'Generating ' + outfilename + ' from ' + infilename + '...'
            observables = generate_cybox(indicators, infilename, embed_observables)
            
            if observables != None:
                observables.set_cybox_major_version('2')
                observables.set_cybox_minor_version('0')
                
                outfile = open(outfilename, 'w')
                outfile.write('<?xml version="1.0" encoding="utf-8"?>\n')
                observables_api_obj = Observables.from_obj(observables)
                outfile.write(observables_api_obj.to_xml(True, namespace_dict = {'http://openioc.org/':'openioc'}))
                outfile.flush()
                outfile.close()

                if verbose_mode:
                    for indicator in skipped_indicators:
                        skipped_id = ''
                        skipped_term = ''
                        if indicator.get_id() is not None:
                            skipped_id = indicator.get_id()
                            skipped_term = string_test(indicator.get_Context().get_search())
                        else:
                            skipped_id = get_indicatoritem_string(indicator, '_')

                        print "IndicatorItem " + skipped_id + " not translated. Encountered IOC term " + skipped_term + ", which does not currently map to CybOX"
            else:
                print('\nInput file %s contained no indicator items compatible with CybOX\n' % infilename)
            
        except Exception, err:
            print('\nError: %s\n' % str(err))
            if verbose_mode:
                traceback.print_exc()
           
    else:
        print('\nError: Input file not found or inaccessible.')
        sys.exit(1)
        
if __name__ == "__main__":
    main()    
