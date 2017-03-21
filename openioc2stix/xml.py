# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from lxml import etree
import cybox.utils

_XML_PARSER = None

# Used for CDATA wrapping field values.
XML_RESERVED_CHARS  = ('<', '>', "'", '"', '&')


def get_xml_parser(encoding=None):
    """Returns the global XML parser object. If no global XML parser has
    been set, one will be created and then returned.

    Args:
        encoding: The expected encoding of input documents. By default, an
            attempt will be made to determine the input document encoding.

    Return:
        The global XML parser object.

    """
    global _XML_PARSER

    if not _XML_PARSER:
        _XML_PARSER = etree.ETCompatXMLParser(
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
            encoding=encoding
        )

    return _XML_PARSER


def set_xml_parser(parser):
    """Set the XML parser to use internally. This should be an instance of
    ``lxml.etree.XMLParser``.

    Note:
        Setting `parser` to an object that is not an instance
        ``lxml.etree.XMLParser`` may result in undesired behaviors.

    Args:
        parser: An etree parser.

    """
    global _XML_PARSER
    _XML_PARSER = parser


def parse(infile):
    parser = get_xml_parser()
    doc = etree.parse(infile, parser=parser)
    root = doc.getroot()
    return root


def tag(ns, name):
    return "{%s}%s" % (ns, name)


def sanitize(string):
    """Sanitize a string input against reserved XML characters

    Args:
        string: String to be sanitized

    Returns: If invalid char was found, string is wrapped in <![CDATA[string]]>
             Otherwise original string is returned.

    """
    if not isinstance(string, basestring):
        return string

    # Remove CDATA wrapper if it existed.
    string = cybox.utils.unwrap_cdata(string)

    if any(c in string for c in XML_RESERVED_CHARS):
        return cybox.utils.wrap_cdata(string)
    else:
        return string