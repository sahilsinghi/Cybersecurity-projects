from playwright.sync_api import sync_playwright
from urllib.parse import urljoin

BASE = "http://127.0.0.1:3000"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(BASE, wait_until="networkidle")

        # Grab normal anchors
        anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")

        # Grab Angular routerLink targets
        router_links = page.eval_on_selector_all("[routerLink]", "els => els.map(e => e.getAttribute('routerLink'))")

        # Normalize routerLink to absolute URLs
        norm_rl = []
        for rl in router_links:
            if not rl:
                continue
            rl = rl.strip()
            if not rl.startswith("/"):
                rl = "/" + rl
            norm_rl.append(urljoin(BASE, rl))

        # Merge + de-duplicate
        all_links = sorted(set(anchors + norm_rl))

        print("[debug] Found", len(all_links), "links:")
        for link in all_links[:30]:
            print("   ", link)

        browser.close()

if __name__ == "__main__":
    main()
