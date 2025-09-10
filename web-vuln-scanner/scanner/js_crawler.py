import sqlite3
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

def save_links_and_forms(db_path, urls, forms):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS endpoints(
        url TEXT PRIMARY KEY,
        has_form INTEGER DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS forms(
        endpoint TEXT,
        form_details TEXT
    )""")
    for u in urls:
        cur.execute("INSERT OR IGNORE INTO endpoints (url, has_form) VALUES (?, 0)", (u,))
    for endpoint, f in forms:
        cur.execute("INSERT INTO forms (endpoint, form_details) VALUES (?, ?)", (endpoint, f))
        cur.execute("UPDATE endpoints SET has_form = 1 WHERE url = ?", (endpoint,))
    conn.commit()
    conn.close()

def crawl_js(base_url, db_path="webscanner.db"):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(base_url, wait_until="networkidle")

        # anchors
        anchors = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        # routerLinks
        router_links = page.eval_on_selector_all("[routerLink]", "els => els.map(e => e.getAttribute('routerLink'))")

        abs_router = []
        for rl in router_links:
            if rl:
                rl = rl.strip()
                if not rl.startswith("/"):
                    rl = "/" + rl
                abs_router.append(urljoin(base_url, rl))

        all_links = set(anchors + abs_router)
        host = urlparse(base_url).netloc
        same_site = [u for u in all_links if urlparse(u).netloc == host]

        # detect forms
                # detect “form-like” pages (inputs even if no <form>)
        forms = []
        for link in same_site:
            if "/redirect" in link:
                continue  # skip redirect trap
            try:
                page.goto(link, wait_until="networkidle")
                # prefer real <form>, else fall back to input/textarea/select
                found_forms = page.query_selector_all("form")
                if not found_forms:
                    controls = page.query_selector_all("input, textarea, select")
                    if controls:
                        html_snip = "\n".join([c.inner_html() or c.get_attribute("outerHTML") for c in controls[:10]])
                        forms.append((link, html_snip))
                else:
                    for f in found_forms:
                        forms.append((link, f.inner_html()))
            except Exception:
                pass


        save_links_and_forms(db_path, same_site, forms)
        browser.close()

if __name__ == "__main__":
    crawl_js("http://127.0.0.1:3000")

