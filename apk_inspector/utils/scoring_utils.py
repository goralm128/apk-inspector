
def compute_cvss_band(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    return "Unknown"
