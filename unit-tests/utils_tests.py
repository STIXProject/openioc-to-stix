# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from openioc2stix import utils

import cybox
from cybox.core import Observable, ObservableComposition, Event
from cybox.common import ObjectProperties
from cybox.common.properties import _LongBase, _IntegerBase, _FloatBase, String

class test_class(ObjectProperties):
    # Class used for testing cybox.TypesField attributes
    Long  = cybox.TypedField('Long', _LongBase)
    Int   = cybox.TypedField('Int', _IntegerBase)
    Float = cybox.TypedField('Float', _FloatBase)
    Str   = cybox.TypedField('Str', String)
    Non   = cybox.TypedField('None', None)

class wrong_test_class():
    # Class used for testing wrong attribute types
    def __init__(self, dne):
        self.dne = dne

    @property
    def dne(self):
        return self.dne

class UtilsTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_normalize_id(self):
        # Check to see if ':' are replaced with '-' by the function `normalize_id`
        test = "Replace:colons:in:str:with:dash"
        test = utils.normalize_id(test)
        self.assertFalse(':' in test and '-' not in test)

        # Normalize should return None when None is passed as an arg
        test = None
        self.assertIsNone(utils.normalize_id(test))

    def test_forcestring(self):
        # See if output is indeed of type string
        num = 5
        self.assertEqual(type(utils.forcestring(num)), str)

    def test_partial_match(self):
        # Check to see if correct matches are returned by `partial_match`
        key = "key1"
        partial_key = "Should be key2"
        no_key = "no key here"
        test_dict = {"key1": "This is key1", "key2": "This is key2"}

        # See if full match
        self.assertEqual(utils.partial_match(test_dict, key), "This is key1")
        # See if partial match
        self.assertEqual(utils.partial_match(test_dict, partial_key), "This is key2")
        # See if no match
        self.assertIsNone(utils.partial_match(test_dict, no_key))

    def test_is_numeric(self):
        # Check to see if the correct numerical cybox.TypedField is returned by `is_numeric`

        # Only true if a numeric TypedField is being checked
        test_object = test_class()
        self.assertTrue(utils.is_numeric(test_object, 'Long'))
        self.assertTrue(utils.is_numeric(test_object, 'Int'))
        self.assertTrue(utils.is_numeric(test_object, 'Float'))
        self.assertFalse(utils.is_numeric(test_object, 'Str'))

        # False if type_ is none
        self.assertFalse(utils.is_numeric(test_object, 'Non'))

        # Not a TypedField object
        test_object = wrong_test_class(5)
        self.assertFalse(utils.is_numeric(test_object, 'dne'))

    def test_is_empty_observable(self):
        # Check to see if the cybox.core.Observable object is empty by calling `is_empty_observable`

        # Empty Observable
        test = Observable()
        self.assertTrue(utils.is_empty_observable(test))

        # Observable is None
        test = None
        self.assertTrue(utils.is_empty_observable(test))

        # Non empty Observable with Object
        test = Observable(test_class())
        self.assertFalse(utils.is_empty_observable(test))

        # Non empty Observable with Event
        test = Observable(Event())
        self.assertFalse(utils.is_empty_observable(test))

        # Checks non empty observable_composition and observable_composition.observables
        test = Observable()
        obs  = ObservableComposition()
        test.observable_composition = obs
        test.observable_composition.observables = obs
        self.assertFalse(utils.is_empty_observable(test))

if __name__ == "__main__":
    unittest.main()
