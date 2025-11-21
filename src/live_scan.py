import requests
from urllib.parse import urlparse
import whois
import socket
from datetime import datetime
from requests.exceptions import RequestException

DEFAULT_TIMEOUT = 6  # seconds


def http_check(url: str, timeout: int = DEFAULT_TIMEOUT):
    """Perform a live HTTP check and return network behavior metrics."""
    try:
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url

        start_time = datetime.utcnow()
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SafeScanner/1.0)'}
        )
        end_time = datetime.utcnow()

        response_time = round((end_time - start_time).total_seconds(), 3)
        final_url = response.url
        status = response.status_code
        redirects = len(response.history)
        final_domain = urlparse(final_url).netloc.replace("www.", "")

        return final_url, status, redirects, final_domain, response_time

    except RequestException:
        parsed = urlparse(url if url else "http://invalid.invalid")
        return url, None, 0, parsed.netloc.replace("www.", ""), None


def domain_whois(domain: str):
    """Get domain age in days using WHOIS."""
    try:
        if not domain:
            return None
        domain_only = domain.split(':')[0]
        w = whois.whois(domain_only)
        created = w.creation_date

        if isinstance(created, list):
            created = created[0]
        if not created:
            return None

        return max((datetime.utcnow() - created).days, 0)
    except Exception:
        return None


def resolve_ip(domain: str):
    """Resolve domain to IP."""
    try:
        if not domain:
            return None
        domain_only = domain.split(':')[0]
        return socket.gethostbyname(domain_only)
    except Exception:
        return None


def risk_assessment(scan_data: dict):
    """Compute heuristic risk score based on scan results."""
    score = 0
    reasons = []

    # --- Domain age (newer = riskier)
    if scan_data.get("domain_age_days") is None:
        score += 25
        reasons.append("No WHOIS info available")
    elif scan_data["domain_age_days"] < 30:
        score += 40
        reasons.append("Domain recently registered (<30 days)")

    # --- HTTP status
    if scan_data.get("http_status") is None:
        score += 20
        reasons.append("No HTTP response")
    elif scan_data["http_status"] >= 400:
        score += 10
        reasons.append(f"HTTP error ({scan_data['http_status']})")

    # --- Redirects
    redirects = scan_data.get("redirects", 0)
    if redirects > 3:
        score += 10
        reasons.append("Excessive redirects (>3)")

    # --- Response time
    response_time = scan_data.get("response_time_sec")
    if response_time and response_time > 3:
        score += 5
        reasons.append("Slow server response (>3s)")

    # --- IP missing
    if not scan_data.get("ip_address"):
        score += 15
        reasons.append("Domain could not be resolved to IP")

    # --- Final classification
    status = "SAFE" if score < 40 else "RISKY"
    return {"status": status, "risk_score": min(score, 100), "reasons": reasons}


def live_scan(url: str, timeout: int = DEFAULT_TIMEOUT):
    """Run a live network + WHOIS + DNS scan and rate safety."""
    final_url, status, redirects, domain, response_time = http_check(url, timeout)
    domain_age = domain_whois(domain)
    ip = resolve_ip(domain)

    result = {
        "input_url": url,
        "final_url": final_url,
        "http_status": status,
        "redirects": redirects,
        "final_domain": domain,
        "domain_age_days": domain_age,
        "ip_address": ip,
        "response_time_sec": response_time
    }

    # Evaluate safety
    risk = risk_assessment(result)
    result.update(risk)
    return result


if __name__ == "__main__":
    # Simple CLI test
    test_url = input("Enter URL to scan: ").strip()
    info = live_scan(test_url)

    print("\nLive Scan Results:")
    for k, v in info.items():
        print(f"{k}: {v}")

    print("\nFinal Verdict:")
    print(f"Status: {info['status']} | Risk Score: {info['risk_score']}/100")
    if info['reasons']:
        print("Reasons:")
        for r in info['reasons']:
            print(f" - {r}")
