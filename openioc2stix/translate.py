import logging

import cybox.utils
from cybox.core import Observables, Observable, ObservableComposition

from . import openioc
from . import objectify
from . import xml
from . import utils


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
    id_ = utils.normalize_id(id_)

    if not id_:
        return None

    return OPENIOC_ID_FMT % id_


def _make_observable(item):
    """Process an indicator item and create a single observable from it."""
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
    return _make_observable(item)


def _translate_items(items):
    observables = (_make_observable(x) for x in items)
    return [o for o in observables if o is not None]


def _indicator_to_observable(indicator):
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


def _translate_indicators(indicators):
    is_empty = utils.is_empty_observable
    translated = (_indicator_to_observable(x) for x in indicators)
    return [x for x in translated if not is_empty(x)]


def to_cybox(infile):
    """Translate the input OpenIOC document into a CybOX Observables
    document.
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


def to_stix(infile):
    """Converts the `infile` OpenIOC document into a STIX Package."""
    pass
