# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
from StringIO import StringIO

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import lxml.etree as ET

from openioc2stix import openioc
from openioc2stix import translate


OPENIOC_XML = """<?xml version="1.0" encoding="us-ascii"?>
<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="fc2d3e44-80a6-4add-ad94-de9f289e62ff" last-modified="2011-10-28T21:00:13" xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>CCAPP.EXE</short_description>
  <description>Custom Reverse shell.</description>
  <keywords />
  <authored_by>Mandiant</authored_by>
  <authored_date>2010-12-13T12:49:53</authored_date>
  <links>
    <link rel="grade">Alpha</link>
  </links>
  <definition>
    <Indicator operator="OR" id="d610019c-379f-4d3e-b299-f0b0e5c3313a">
      <IndicatorItem id="86d0e6fc-ff41-4743-8a9a-c323ef8ad8cb" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />
        <Content type="md5">9855c23be2b6f38630756a277b52cdd2</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
  <definition>
      <Indicator operator="OR" id="d610019c-379f-4d3e-b299-f0b0e5c3313a">
          <IndicatorItem id="86d0e6fc-ff41-4743-8a9a-c323ef8ad8cb" condition="is">
            <Context document="FileItem" search="FileItem/Md5sum" type="mir" />
            <Content type="md5">9855c23be2b6f38630756a277b52cdd2</Content>
          </IndicatorItem>
          <IndicatorItem id="78c1c4c9-500f-40b3-be62-4c16b5058da9" condition="is">
            <Context document="FileItem" search="FileItem/Md5sum" type="mir" />
            <Content type="md5">acb81bee009b09b2a0688f05ea45851f</Content>
          </IndicatorItem>
          <Indicator operator="AND" id="3902a731-260b-49e8-84a5-77d2a420716e">
            <IndicatorItem id="034d5703-bc58-4a09-9333-e24cf4c41fe9" condition="contains">
              <Context document="FileItem" search="FileItem/PEInfo/Sections/Section/Name" type="mir" />
              <Content type="string">.vmp0</Content>
            </IndicatorItem>
            <IndicatorItem id="17dba1f2-9ee8-46a4-8b4f-c7ede9621c20" condition="contains">
              <Context document="FileItem" search="FileItem/PEInfo/DetectedAnomalies/string" type="mir" />
              <Content type="string">checksum_is_zero</Content>
            </IndicatorItem>
          </Indicator>
      </Indicator>
  </definition>
  <Indicator operator="OR" id="d610019c-379f-4d3e-b299-f0b0e5c3313a">
      <IndicatorItem id="86d0e6fc-ff41-4743-8a9a-c323ef8ad8cb" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />
        <Content type="md5">9855c23be2b6f38630756a277b52cdd2</Content>
      </IndicatorItem>
      <IndicatorItem id="78c1c4c9-500f-40b3-be62-4c16b5058da9" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />
        <Content type="md5">acb81bee009b09b2a0688f05ea45851f</Content>
      </IndicatorItem>
      <Indicator operator="AND" id="3902a731-260b-49e8-84a5-77d2a420716e">
        <IndicatorItem id="034d5703-bc58-4a09-9333-e24cf4c41fe9" condition="contains">
          <Context document="FileItem" search="FileItem/PEInfo/Sections/Section/Name" type="mir" />
          <Content type="string">.vmp0</Content>
        </IndicatorItem>
        <IndicatorItem id="17dba1f2-9ee8-46a4-8b4f-c7ede9621c20" condition="contains">
          <Context document="FileItem" search="FileItem/PEInfo/DetectedAnomalies/string" type="mir" />
          <Content type="string">checksum_is_zero</Content>
        </IndicatorItem>
      </Indicator>
    </Indicator>
</ioc>
"""


class EmailTest(unittest.TestCase):

    # https://github.com/STIXProject/openioc-to-stix/issues/17
    def test_email_attachment(self):
        test_file = os.path.join(os.path.dirname(__file__), "data",
                                 "iocbucket_9c2a7a3b3c8ea33d8e05ad2f0557cd56b5828a51_mhadi.ioc")

        stix_pkg = translate.to_stix(test_file)
        observable = stix_pkg.indicators[0].observable.observable_composition.observables[7]
        self.assertEquals(observable.object_.related_objects[0].relationship, "Contains")


class OpeniocTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Parse the xml string and define the root
        ioc_xml = StringIO(OPENIOC_XML)
        tree = ET.parse(ioc_xml)
        cls.root = tree.getroot()

        # Use this search to get top indicators to call functions on
        xpath = "./openioc:definition/openioc:Indicator"
        namespace = {"openioc": "http://schemas.mandiant.com/2010/ioc"}
        cls.indicators = list(cls.root.xpath(xpath, namespaces=namespace))

    def test_get_top_indicators(self):
        # Check to see if indicators were successfully obtained through the xpath query in `get_top_indicators` function

        # Check proper type was returned from function
        self.assertEqual(type(openioc.get_top_indicators(self.root)), list)

        # Should return only two indicators to be checked
        self.assertEqual(openioc.get_top_indicators(self.root)[0].tag, "{http://schemas.mandiant.com/2010/ioc}Indicator")
        self.assertEqual(openioc.get_top_indicators(self.root)[1].tag, "{http://schemas.mandiant.com/2010/ioc}Indicator")

    def test_get_indicators(self):
        # Check to see if the one indicator was successfully obtained through the xpath query
        # from the `get_indicators` function

        # Check proper type was returned from function
        self.assertEqual(type(openioc.get_indicators(self.root)), list)

        # Check indicator was found
        self.assertEqual(openioc.get_indicators(self.root)[0].tag, "{http://schemas.mandiant.com/2010/ioc}Indicator")

    def test_get_items(self):
        # Check to see if the all items were successfully obtained through the xpath query from the `get_items` function

        # Check proper type was returned from function
        self.assertEqual(type(openioc.get_items(self.indicators[0])), list)
        self.assertEqual(type(openioc.get_items(self.indicators[1])), list)

        # Check proper number of items were found in each indicator
        self.assertEqual(len(openioc.get_items(self.indicators[0])), 1)
        self.assertEqual(len(openioc.get_items(self.indicators[1])), 2)

    def test_get_search(self):
        # Check to see if the correct terms were found by using `get_search`

        # See if correct <Context> was grabbed
        self.assertEqual(openioc.get_search(self.indicators[0][0]), "FileItem/Md5sum")
        self.assertEqual(openioc.get_search(self.indicators[1][0]), "FileItem/Md5sum")
        self.assertEqual(openioc.get_search(self.indicators[1][1]), "FileItem/Md5sum")

        # If <Context> is None, search should return None
        self.assertIsNone(openioc.get_search(self.indicators[1][2]))

    def test_get_content(self):
        # Check to see if the correct terms were found by using `get_content`

        # See if correct <Content> was grabbed
        self.assertEqual(openioc.get_content(self.indicators[0][0]), '9855c23be2b6f38630756a277b52cdd2')
        self.assertEqual(openioc.get_content(self.indicators[1][0]), '9855c23be2b6f38630756a277b52cdd2')
        self.assertEqual(openioc.get_content(self.indicators[1][1]), 'acb81bee009b09b2a0688f05ea45851f')

        # If <Content> is None, search should return None
        self.assertIsNone(openioc.get_content(self.indicators[1][2]))

    def test_get_condition(self):
        # Check to see if a condition was found by using `get_condition`

        # See if correct 'condition' was grabbed
        self.assertEqual(openioc.get_condition(self.indicators[0][0]), 'is')
        self.assertEqual(openioc.get_condition(self.indicators[1][0]), 'is')
        self.assertEqual(openioc.get_condition(self.indicators[1][1]), 'is')

        # If <Content> is None, search should return None
        self.assertIsNone(openioc.get_condition(self.indicators[1][2]))


if __name__ == "__main__":
    unittest.main()
