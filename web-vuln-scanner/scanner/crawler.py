import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url

    def crawl(self, url=None, depth=1):
        if url is None:
            url = self.base_url
        print(f"[+] Crawling: {url} (depth={depth})")

        try:
            resp = requests.get(url, timeout=5, headers={"User-Agent":"scanner/0.1"})
            print(f"[debug] GET {url} -> {resp.status_code}")
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return

        if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type",""):
            soup = BeautifulSoup(resp.text, "lxml")

            links = set()

            # Normal links
            for a in soup.find_all("a", href=True):
                links.add(urljoin(url, a["href"]))

            # Angular routerLink links (e.g., <a routerLink="/login">)
            for tag in soup.find_all(attrs={"routerlink": True}):
                rl = tag.get("routerlink")
                # routerLink might be a list or string; normalize to string
                if isinstance(rl, list):
                    rl = rl[0] if rl else ""
                rl = str(rl).strip()
                if rl:
                    if not rl.startswith("/"):
                        rl = "/" + rl
                    links.add(urljoin(url, rl))

            print("[debug] Found links:")
            for link in sorted(links):
                print("   ", link)



