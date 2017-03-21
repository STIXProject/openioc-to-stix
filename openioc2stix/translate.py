# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
"""
Internal module dedicated to translating observables and indicators
as well as translating OpenIOC to CybOX and STIX.
"""

import logging

import cybox.utils
from cybox.core import Observables, Observable, ObservableComposition
from cybox.common import ToolInformationList, ToolInformation

import stix.utils
from stix.core import STIXPackage, STIXHeader, Indicators
from stix.common import InformationSource
from stix.common.vocabs import PackageIntent
from stix.indicator import Indicator

from . import openioc
from . import objectify
from . import xml
from . import utils
from . import version


# ID format for translated OpenIOC items
OPENIOC_ID_FMT = "openioc:item-%s"

# Map of IndicatorItem conditions to CybOX operators
CONDITIONS = {
    'is': 'Equals',
    'isnot': 'DoesNotEqual',
    'contains': 'Contains',
    'containsnot': 'DoesNotContain'
}

LOG = logging.getLogger(__name__)


def _translate_id(id_):
    """Process an id which is normalized and has 'openioc:item-' prepended

    Args:
        id: String to uniquely represent an observable or indicator

    Returns:
        If there is no id, None is returned.
        Otherwise a normalized id with 'openioc:item-' prepended is returned.
    """
    id_ = utils.normalize_id(id_)

    if not id_:
        return None

    return OPENIOC_ID_FMT % id_


def _make_observable(item):
    """Process an indicator item and creates a single observable from it.

    Args:
        item: Individual indicator item

    Returns:
        A cybox.core.Observable object
    """
    content   = openioc.get_content(item)
    search    = openioc.get_search(item)
    condition = openioc.get_condition(item)

    if not (content and search and condition):
        fmt = "Unable to produce Observable from IndicatorItem on line: %d"
        LOG.warn(fmt, item.sourceline)
        return None

    # Map the OpenIOC condition to a CybOX condition
    condition = CONDITIONS[condition]

    # Convert the IndicatorItem into a CybOX Object
    object_ = objectify.make_object(search, content, condition)

    if object_:
        return Observable(object_)

    skipped_term = utils.forcestring(search)

    fmt = ("Error|Ignore. IndicatorItem not translated. Encountered IOC "
           "term '%s' , which does not currently map to CybOX.")
    desc = fmt % skipped_term
    desc = cybox.utils.wrap_cdata(desc)

    obs  = Observable(description=desc)
    return obs


def _translate_item(item):
    """Process an indicator item and creates a single observable from it.

    Args:
        item: Individual indicator item

    Returns:
        A cybox.core.Observable object
    """
    return _make_observable(item)


def _translate_items(items):
    """Process an indicator item(s) and creates an observable list from it.

    Args:
        item: Indicator item(s)

    Returns:
        cybox.core.Observable object list.
    """
    observables = (_make_observable(x) for x in items)
    return [o for o in observables if o is not None]


def _indicator_to_observable(indicator):
    """Process indicator item(s), that can be nested, and create a composite object with observables.

    Args:
        indicator: Indicator(s) that will be translated

    Returns:
        A cybox.core.Observable object if `indicator` can be translated.
        None is returned if `indicator` contains invalid or untranslatable items.
    """
    items  = openioc.get_items(indicator)
    nested = openioc.get_indicators(indicator)

    if not (nested or items):
        return None

    # If the openioc indicator has only one IndicatorItem, return an Observable
    # object which has a single CybOX Object child.
    if not nested and len(items) == 1:
        return _translate_item(items[0])

    # The openioc Indicator had more than one item or nested indicators, so
    # we need to create an Observable Composition.
    # Initialize the parent Observable
    id_ = _translate_id(indicator.attrib.get("id"))
    root = Observable(id_=id_)

    operator = indicator.attrib.get("operator", "AND")
    composite = ObservableComposition(operator=operator)
    root.observable_composition = composite

    # Translate all the IndicatorItem and nested Indicator children
    observables = _translate_items(items) + _translate_indicators(nested)

    # Add the translated Observable objects to the composite
    composite.observables.extend(observables)

    return root

def _observable_to_indicator_stix(observable):
    """Translate a CybOX Observable into a STIX Indicator.

    Args:
        observable: Observable object that will be translated

    Returns:
        Indicator object with STIX utility and CybOX tags
    """
    # Build STIX tool content
    tool = ToolInformation(tool_name='OpenIOC to STIX Utility')
    tool.version = version.__version__

    # Build Indicator.producer contents
    producer = InformationSource()
    producer.tools = ToolInformationList(tool)

    # Build Indicator
    indicator = Indicator(title="CybOX-represented Indicator Created from OpenIOC File")
    indicator.producer = producer
    indicator.add_observable(observable)

    return indicator

def _translate_indicators(indicators):
    """Process an indicator item(s) and creates an observable list from it.

    Args:
        item: Indicator item(s)

    Returns:
        A cybox.core.Observable object list if `indicators` can be translated.
    """
    is_empty = utils.is_empty_observable
    translated = (_indicator_to_observable(x) for x in indicators)
    return [x for x in translated if not is_empty(x)]


def to_cybox(infile):
    """Translate the `infile` OpenIOC xml document into a CybOX Observable.

    Args:
        infile: OpenIOC xml filename to translate

    Returns:
        cybox.core.Observables object
    """
    iocdoc = xml.parse(infile)
    indicators = openioc.get_top_indicators(iocdoc)

    if len(indicators) == 0:
        raise Exception("Input document contained no indicator items.")

    observables = _translate_indicators(indicators)

    if not observables:
        raise Exception("Input document contained no indicator items compatible with CybOX.")

    obsdoc = Observables(observables)
    return obsdoc


@stix.utils.silence_warnings
def to_stix(infile):
    """Converts the `infile` OpenIOC xml document into a STIX Package.

    Args:
        infile: OpenIOC xml filename to translate

    Returns:
       stix.core.STIXPackage object
    """
    observables = to_cybox(infile)

    # Build Indicators from the Observable objects
    indicators = [_observable_to_indicator_stix(o) for o in observables]

    # Wrap the created Observables in a STIX Package/Indicator
    stix_package = STIXPackage()

    # Set the Indicators collection
    stix_package.indicators = Indicators(indicators)

    # Create and write the STIX Header. Warning: these fields have been
    # deprecated in STIX v1.2!
    stix_header = STIXHeader()
    stix_header.package_intent = PackageIntent.TERM_INDICATORS_MALWARE_ARTIFACTS
    stix_header.description = "CybOX-represented Indicators Translated from OpenIOC File"
    stix_package.stix_header = stix_header

    return stix_package
