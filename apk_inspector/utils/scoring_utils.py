def compute_cvss_band(cvss_input):
    """
    Accepts a float or list of floats and returns the severity band.
    """
    if isinstance(cvss_input, float):
        scores = [cvss_input]
    elif isinstance(cvss_input, list):
        scores = cvss_input
    else:
        return "Unknown"

    if not scores:
        return "Unknown"

    max_cvss = max(scores)
    if max_cvss >= 9.0:
        return "Critical"
    elif max_cvss >= 7.0:
        return "High"
    elif max_cvss >= 4.0:
        return "Medium"
    elif max_cvss > 0.0:
        return "Low"
    return "Unknown"

