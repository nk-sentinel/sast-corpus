from lxml import etree


def parse(document):
    config = etree.XMLParser(resolve_entities=True, no_network=False)
    return etree.fromstring(document, parser=config)
