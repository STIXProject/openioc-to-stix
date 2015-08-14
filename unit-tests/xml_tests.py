# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from openioc2stix import xml

class XMLTest(unittest.TestCase):
    
    def setUp(self):
        self.XML_RESERVED_CHARS = ('<', '>', "'", '"', '&')
        pass

    def test_sanitize(self):
        for char in self.XML_RESERVED_CHARS:
            wrapped = xml.sanitize(char)
            if "<![CDATA[" in wrapped:
                self.assertTrue(True)
            else:
                self.assertFalse(True)


if __name__ == "__main__":
    unittest.main()
