import re
from urllib.parse import unquote

def parse_cookie_string(cookie_string):
    cookie_dict = {}
    for part in cookie_string.split(';'):
        if '=' in part:
            key, value = part.strip().split('=', 1)
            cookie_dict[key] = unquote(value)
    return cookie_dict

def get_cookie_metadata(cookie_dict):
    # Placeholder for metadata extraction
    attrs = []
    for name, value in cookie_dict.items():
        attr = {
            'name': name,
            'length': len(value),
            'has_httponly': True,  # Default assumption; real detection later
            'has_secure': True,
            'samesite': 'Lax'
        }
        attrs.append(attr)
    return attrs