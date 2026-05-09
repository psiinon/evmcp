"""
Server-Side Request Forgery — CWE-918: Server-Side Request Forgery (SSRF).

The server makes an outbound HTTP request to a caller-supplied URL with no
scheme, host, or IP-range validation.
"""
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_url(url: str) -> str:
    """Fetch a URL and return the HTTP response.

    VULNERABLE: no URL validation, allows requests to internal/cloud-metadata services.

    AWS instance metadata (inside AWS):
        http://169.254.169.254/latest/meta-data/

    GCP metadata (inside GCP):
        http://metadata.google.internal/computeMetadata/v1/

    Self-request to list tools:
        http://localhost:8000/mcp

    Internal service probe:
        http://localhost:6379/   (Redis)
    """
    try:
        resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        headers_excerpt = dict(list(resp.headers.items())[:5])
        return (
            f"Status: {resp.status_code}\n"
            f"Headers (first 5): {headers_excerpt}\n"
            f"Body (first 2000 chars):\n{resp.text[:2000]}"
        )
    except requests.RequestException as exc:
        return f"Request failed: {exc}"
