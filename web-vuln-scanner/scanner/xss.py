import requests

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1);//"
]

def test_xss(url):
    vulns = []
    for payload in XSS_PAYLOADS:
        try:
            # send payload as query string ?q=<payload>
            resp = requests.get(url, params={"q": payload}, timeout=5)
            if payload in resp.text:
                vulns.append((url, payload))
        except Exception:
            pass
    return vulns
