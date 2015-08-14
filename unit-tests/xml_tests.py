# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
import lxml.etree as ET

from openioc2stix import xml
from StringIO import StringIO

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
</ioc>
"""


class XMLTest(unittest.TestCase):
    
    def setUp(self):
        self.XML_RESERVED_CHARS = ('<', '>', "'", '"', '&')
        self._XML_PARSER = None
        pass

    def test_get_xml_parser(self):
        # Check to see if the correct lxml.etree.ETCompactXMLParser object is returned by the function `get_xml_parser`
        self.assertEqual(type(xml.get_xml_parser()), ET.ETCompatXMLParser)

    def test_set_xml_parser(self):
        # Check to see if a new parser can be set by the function `set_xml_parser`
        self._XML_PARSER = ET.ETCompatXMLParser(
            attribute_defaults=False,
            load_dtd=False,
            huge_tree=False,
            no_network=True,
            ns_clean=True,
            recover=False,
            remove_pis=False,
            remove_blank_text=False,
            remove_comments=False,
            resolve_entities=False,
            strip_cdata=True,
            encoding=None
        )
        xml.set_xml_parser(self._XML_PARSER)

        # If parser is still 'None' then the parser was not set.
        self.assertIsNotNone(self._XML_PARSER)

    def test_parse(self):
        # Check to see if `parse` correctly returns lxml.etree._Element object
        ioc_xml = StringIO(OPENIOC_XML)
        root = xml.parse(ioc_xml)
        self.assertEqual(type(root), ET._Element)

    def test_tag(self):
        # Check to see if `tag` correctly returns a specifically formatted string
        ns = "namespace"
        name = "ioc"
        self.assertEqual(xml.tag(ns, name), '{namespace}ioc')

    def test_sanitize(self):
        # Check to see if `sanitize` correctly wraps XML_RESERVED_CHARS, for security,
        # when they are detected in a string
        for char in self.XML_RESERVED_CHARS:
            wrapped = xml.sanitize(char)
            if "<![CDATA[" in wrapped:
                self.assertTrue(True)
            else:
                self.assertFalse(True)


if __name__ == "__main__":
    unittest.main()
