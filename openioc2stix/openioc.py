# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from . import xml

NS_OPENIOC = "http://schemas.mandiant.com/2010/ioc"
NAMESPACES = {"openioc": NS_OPENIOC}


def get_top_indicators(root):
    xpath = "./openioc:definition/openioc:Indicator"
    return list(root.xpath(xpath, namespaces=NAMESPACES))


def get_indicators(root):
    xpath = "./openioc:Indicator"
    return list(root.xpath(xpath, namespaces=NAMESPACES))


def get_items(indicator):
    xpath = "./openioc:IndicatorItem"
    return list(indicator.xpath(xpath, namespaces=NAMESPACES))


def get_search(item):
    tag = xml.tag(NS_OPENIOC, "Context")
    ctx = item.find(tag)

    if ctx is None:
        return None

    return ctx.attrib.get("search")


def get_content(item):
    tag = xml.tag(NS_OPENIOC, "Content")
    return item.findtext(tag)


def get_condition(item):
    return item.attrib.get("condition")
