def assign_severity(vuln_type, url, info=""):
    """
    Simple CVSS-like mapping for demo purposes.
    """
    vuln_type = vuln_type.upper()

    if vuln_type == "SQLI":
        return "Critical"
    elif vuln_type == "XSS":
        # DOM vs Reflected difference could go here
        return "High"
    elif "csrf" in vuln_type.lower():
        return "Medium"
    else:
        return "Low"
