from urllib.parse import urlparse, parse_qs
import re, math, socket, time
import tldextract
from difflib import SequenceMatcher
from typing import Dict, Any

# Suspicious keywords
SUSPICIOUS_WORDS = [
    'login', 'secure', 'account', 'update', 'verify', 'confirm',
    'free', 'bank', 'signin', 'wp-', 'admin', 'paypal', 'apple',
    'amazon', 'google', 'ebay', 'security', 'password'
]

# Legitimate brand reference list
BRANDS = ['paypal', 'google', 'apple', 'amazon', 'microsoft', 'facebook', 'bank', 'netflix']

# Legitimate TLD probability mapping (approximation)
TLD_PROB = {
    'com': 0.95, 'org': 0.9, 'edu': 0.98, 'gov': 1.0,
    'net': 0.88, 'io': 0.75, 'co': 0.83, 'info': 0.7,
    'xyz': 0.5, 'top': 0.4, 'cn': 0.3, 'ru': 0.3
}

def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log(p, 2) for p in probs if p > 0)

def safe_ratio(a, b): return float(a) / (b + 1e-9)

def brand_similarity(url: str) -> float:
    u = re.sub(r'\W+', '', url.lower())
    return max(SequenceMatcher(None, u, b).ratio() for b in BRANDS)

def is_ip(host: str) -> int:
    try:
        socket.inet_aton(host.split(':')[0])
        return 1
    except Exception:
        return 0

def char_continuation_rate(url: str) -> float:
    if not url: return 0.0
    max_run, cur, prev = 1, 1, None
    for ch in url:
        if ch == prev:
            cur += 1
            max_run = max(max_run, cur)
        else:
            cur = 1
        prev = ch
    return safe_ratio(max_run, len(url))

def extract_features(url: str, do_enrich: bool = False) -> Dict[str, Any]:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://invalid.invalid")

    te = tldextract.extract(url)
    domain, subdomain, suffix = te.domain, te.subdomain, te.suffix
    host = parsed.netloc or ""
    path, query, fragment = parsed.path, parsed.query, parsed.fragment

    # Core lexical structure
    url_len = len(url)
    domain_len = len(domain)
    num_digits = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)
    num_special = sum(1 for c in url if not c.isalnum())
    num_hyphens, num_dots = url.count('-'), url.count('.')
    num_slash, num_eq, num_amp = url.count('/'), url.count('='), url.count('&')
    entropy_val = entropy(url)
    digit_ratio, letter_ratio = safe_ratio(num_digits, url_len), safe_ratio(num_letters, url_len)
    special_ratio = safe_ratio(num_special, url_len)
    suspicious_flag = int(any(w in url.lower() for w in SUSPICIOUS_WORDS))
    suspicious_count = sum(1 for w in SUSPICIOUS_WORDS if w in url.lower())
    tld_legit_prob = TLD_PROB.get(suffix.lower(), 0.5)

    # Additional derived features
    has_https = int(url.lower().startswith('https'))
    sub_count = subdomain.count('.') + 1 if subdomain else 0
    is_domain_ip = is_ip(host)
    brand_sim = brand_similarity(url)
    char_run = char_continuation_rate(url)

    # HTML-like feature approximations (offline)
    has_favicon = 1
    is_responsive = 1
    no_url_redirect = 0
    has_description = 1
    has_keywords = 1
    no_iframe = 0
    no_popup = 0
    has_ext_form_submit = 0
    has_hidden_fields = 0
    anchor_url_ratio = 0.5
    link_in_tags = 0.5
    sfh = 1
    num_external_resources = 1
    num_scripts = 3
    num_images = 2
    content_length = 20000
    has_title_tag = 1
    num_meta_tags = 5
    num_form_tags = 1
    num_comments = 2

    # Network / WHOIS approximations
    domain_age_days = 365
    domain_exp_days = 500
    dns_record = 1
    web_traffic_rank = 100000
    page_rank = 0.6
    ssl_final_state = 1
    ssl_issuer = "Let's Encrypt"
    registrar = "GoDaddy"
    asn = "AS15169"

    # Combine all features
    feats = {
        "URL": url,
        "URLLength": url_len,
        "Domain": domain,
        "DomainLength": domain_len,
        "IsDomainIP": is_domain_ip,
        "TLD": suffix,
        "URLSimilarityIndex": brand_sim,
        "CharContinuationRate": char_run,
        "TLDLegitimateProb": tld_legit_prob,
        "URLCharProb": safe_ratio(num_letters + num_digits, url_len),
        "URLTitleMatchScore": brand_sim,
        "HasFavicon": has_favicon,
        "IsResponsive": is_responsive,
        "NoOfURLRedirect": no_url_redirect,
        "HasDescription": has_description,
        "HasKeywords": has_keywords,
        "NoOfiFrame": no_iframe,
        "NoOfPopup": no_popup,
        "HasExternalFormSubmit": has_ext_form_submit,
        "HasHiddenFields": has_hidden_fields,
        "SSLFinalState": ssl_final_state,
        "AnchorURLRatio": anchor_url_ratio,
        "LinkInTags": link_in_tags,
        "SFH": sfh,
        "SubdomainCount": sub_count,
        "NumDigits": num_digits,
        "NumSpecialChars": num_special,
        "NumHyphens": num_hyphens,
        "NumDots": num_dots,
        "HasHTTPS": has_https,
        "UsesShortener": int(any(x in domain.lower() for x in ['bit', 't.co', 'goo.gl'])),
        "SuspiciousWord": suspicious_flag,
        "SuspiciousWordCount": suspicious_count,
        "Entropy": entropy_val,
        "DigitRatio": digit_ratio,
        "LetterRatio": letter_ratio,
        "SpecialRatio": special_ratio,
        "DomainAgeDays": domain_age_days,
        "DomainExpirationDays": domain_exp_days,
        "DNSRecord": dns_record,
        "WebTrafficRank": web_traffic_rank,
        "PageRank": page_rank,
        "NumExternalResources": num_external_resources,
        "NumScripts": num_scripts,
        "NumImages": num_images,
        "ContentLength": content_length,
        "HasTitleTag": has_title_tag,
        "NumMetaTags": num_meta_tags,
        "NumFormTags": num_form_tags,
        "NumComments": num_comments,
        "SSLIssuer": ssl_issuer,
        "Registrar": registrar,
        "ASN": asn
    }

    return feats
