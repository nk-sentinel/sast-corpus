from lxml import etree


def parse(document):
    config = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(document, parser=config)
