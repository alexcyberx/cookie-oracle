import re
import json

# Predefined platform signatures
PLATFORM_SIGNATURES = {
    "Instagram": {
        "cookie_names": ["sessionid", "csrftoken", "ds_user_id"],
        "domain_patterns": [".*\\.instagram\\.com"]
    },
    "Facebook": {
        "cookie_names": ["c_user", "xs", "fr"],
        "domain_patterns": [".*\\.facebook\\.com"]
    },
    "Google": {
        "cookie_names": ["SID", "HSID", "APISID", "SSID", "SAPISID"],
        "domain_patterns": [".*\\.google\\.com"]
    },
    "GitHub": {
        "cookie_names": ["user_session", "logged_in", "__Host-user_session"],
        "domain_patterns": [".*\\.github\\.com"]
    },
    "Twitter": {
        "cookie_names": ["auth_token", "twid", "ct0"],
        "domain_patterns": [".*\\.twitter\\.com"]
    },
    "Amazon": {
        "cookie_names": ["session-id", "sess-at", "x-main"],
        "domain_patterns": [".*\\.amazon\\.(com|in|co\\.uk)"]
    },
    "Microsoft": {
        "cookie_names": ["ESTSAUTH", "MSISAuth"],
        "domain_patterns": [".*\\.microsoft\\.com", ".*\\.live\\.com"]
    }
}

def detect_platform(cookie_dict, domain=None):
    detected = []

    # Detect by cookie names
    for name in cookie_dict.keys():
        for platform, sig in PLATFORM_SIGNATURES.items():
            if name in sig["cookie_names"]:
                if domain and re.match(sig["domain_patterns"][0], domain):
                    detected.append({
                        'platform': platform,
                        'method': 'name+domain',
                        'confidence': 95
                    })
                else:
                    detected.append({
                        'platform': platform,
                        'method': 'name_only',
                        'confidence': 60
                    })

    return detected if detected else [{'platform': 'Unknown', 'method': 'none', 'confidence': 0}]