# Web Application Vulnerability Scanner — Report

**Date:** 2025-08-24

## Introduction
This project builds a lightweight web vulnerability scanner. It crawls OWASP Juice Shop, discovers endpoints, and runs XSS/SQLi checks with CVSS-style severity scoring.

## Tools Used
- Python (requests, BeautifulSoup, Playwright)
- SQLite (findings database)
- Docker (OWASP Juice Shop target)

## Steps Involved
1. Set up target in Docker.
2. Built JS-aware crawler with Playwright.
3. Stored endpoints in SQLite.
4. Implemented XSS and SQLi probes.
5. Logged findings with CVSS-based severity ratings.

## Findings

| Type | Severity | URL | Param | Payload | Notes |
|---|---|---|---|---|---|
| SQLi | Critical | http://127.0.0.1:3000/redirect?to=https://github.com/juice-shop/juice-shop | q | `'` | error-marker |
| SQLi | Critical | http://127.0.0.1:3000/rest/products/search | q | `'--` | error-marker |

## Evidence
- Evidence HTML saved in `evidence/`
- Screenshots: docker ps, scanner CLI, SQLite findings table

## Conclusion
Scanner successfully detected SQL Injection with severity ratings. Next steps: extend to DOM-XSS, CSRF, and richer CVSS scoring.
