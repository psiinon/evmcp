"""
XML External Entity Injection — CWE-611: Improper Restriction of XML External Entity Reference.

lxml is configured with external entity resolution and DTD loading deliberately enabled,
allowing attackers to read local files or trigger SSRF via entity references.
"""
from lxml import etree


def parse_xml(xml_content: str) -> str:
    """Parse XML and return the text content of all elements.

    VULNERABLE: lxml parser with external entity resolution enabled (load_dtd=True,
    resolve_entities=True, no_network=False).

    Read /etc/passwd:
        <?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        <root>&x;</root>

    SSRF via entity (inside cloud environment):
        <!DOCTYPE foo [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>
        <root>&x;</root>

    Billion laughs DoS (entity expansion):
        <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
        <root>&lol2;</root>
    """
    try:
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,
        )
        root = etree.fromstring(xml_content.encode(), parser)
        texts = [t for elem in root.iter() for t in (elem.text, elem.tail) if t and t.strip()]
        return "\n".join(texts) if texts else "<no text content>"
    except etree.XMLSyntaxError as exc:
        return f"XML parse error: {exc}"
    except Exception as exc:
        return f"Error: {exc}"
