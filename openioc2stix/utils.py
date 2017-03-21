# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from cybox.common.properties import _LongBase, _IntegerBase, _FloatBase

try:
    # Old versions of cybox (prior to mixbox) defined this class.
    from cybox import TypedField
except ImportError:
    from mixbox.fields import TypedField


NUMERIC_FIELD_BASES = (_LongBase, _IntegerBase, _FloatBase)


def normalize_id(id_):
    """Normalize any ids used in the IOC to make the compatible with CybOX
    This is just in case the normal UUID type is not used.
    """
    if id_ is None:
        return None

    return id_.replace(":", "-")


def forcestring(value):
    """Test a value, if it is not an empty string or None, return the string
    representation of it, otherwise return an empty string.
    """
    if value is None:
        return ""

    return str(value)


def partial_match(dict_, key):
    """Returns a value from `dict_` for the associated `key`. If `key` is not
    found in `dict_` an attempt will be made to find a key in the dictionary
    which contains part of `key` and return its associated value.
    """
    if key in dict_:
        return dict_[key]

    for partial, value in dict_.iteritems():
        if partial in key:
            return value

    return None


def is_numeric(obj, attrname):
    klass = obj.__class__
    field = getattr(klass, attrname)

    if not isinstance(field, TypedField):
        return False

    if not field.type_:
        return False

    return any(issubclass(field.type_, base) for base in NUMERIC_FIELD_BASES)


def is_empty_observable(o):
    if o is None:
        return True
    elif o.object_:
        return False
    elif o.event:
        return False
    elif o.observable_composition and o.observable_composition.observables:
        return False

    return True
