#!/usr/bin/env python3
import sys
from rich import print
from scanner.crawler import Crawler
from scanner.xss import test_xss
from scanner.sqli import test_sqli   # ✅ make sure this is here
import sqlite3

def main():
    print("[bold green]Web Vulnerability Scanner[/bold green]")
    if len(sys.argv) < 2:
        print("Usage: python cli.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    print(f"[cyan]Target set to:[/cyan] {url}")

    # Crawl
    crawler = Crawler(url)
    crawler.crawl(url, depth=1)
    print("[yellow]Crawling complete. Checking for vulnerabilities...[/yellow]")

    # Load endpoints from DB
    conn = sqlite3.connect("webscanner.db")
    cur = conn.cursor()
    cur.execute("SELECT url FROM endpoints")
    urls = [row[0] for row in cur.fetchall()]
    conn.close()

    # Run XSS checks
    for u in urls:
        vulns = test_xss(u)
        for v in vulns:
            print(f"[red][XSS Found][/red] {v[0]} payload={v[1]}")

    # Run SQLi checks ✅
    for u in urls:
        vulns = test_sqli(u)
        for v in vulns:
            print(f"[red][SQLi Found][/red] {v[0]} param={v[1]} payload={v[2]} info={v[3]}")

    print("[green]Scan complete.[/green]")

if __name__ == "__main__":
    main()

