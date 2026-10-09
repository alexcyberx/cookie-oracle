import httpx
import asyncio
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

class SessionValidator:
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

    async def probe_session(self, cookie_dict: Dict, domain: str, platform: str) -> Dict:
        """
        Probes the session by sending a lightweight request to the target platform.
        Returns status info: active / expired / unknown
        """
        cookie_header = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])
        base_url = self._get_base_url(platform, domain)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Cookie": cookie_header
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(base_url, headers=headers, follow_redirects=False)
                return self._analyze_response(resp, platform)
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _get_base_url(self, platform: str, domain: str) -> str:
        """Return appropriate endpoint for each platform"""
        endpoints = {
            "Google": "https://myaccount.google.com/",
            "GitHub": "https://github.com/settings/profile",
            "Instagram": "https://www.instagram.com/accounts/edit/",
            "Facebook": "https://www.facebook.com/settings",
            "Twitter": "https://twitter.com/home",
            "Amazon": "https://www.amazon.com/gp/css/homepage.html",
            "Microsoft": "https://account.microsoft.com/"
        }
        if domain:
            return f"https://{domain}"
        return endpoints.get(platform, f"https://{self._guess_domain(platform)}")

    def _guess_domain(self, platform: str) -> str:
        """Fallback domain guess if platform unrecognized"""
        guesses = {
            "Google": "google.com",
            "GitHub": "github.com",
            "Instagram": "instagram.com",
            "Facebook": "facebook.com",
            "Twitter": "twitter.com",
            "Amazon": "amazon.com",
            "Microsoft": "microsoft.com"
        }
        return guesses.get(platform, "example.com")

    def _analyze_response(self, response: httpx.Response, platform: str) -> Dict:
        """
        Analyze HTTP response to determine session validity
        """
        url = str(response.url)
        body = response.text.lower() if response.text else ""

        # Check for redirects to login pages (session expired)
        login_indicators = ["login", "signin", "auth", "welcome", "enter"]
        is_login_page = any(indicator in body for indicator in login_indicators)
        redirects_to_login = response.status_code in [302, 303] and any(
            ind in str(response.headers.get("Location", "")).lower() for ind in login_indicators
        )

        # Check for logout button or edit profile links (session active)
        active_indicators = ["logout", "edit profile", "account", "csrf"]
        is_active_session = any(ind in body for ind in active_indicators)

        if is_login_page or redirects_to_login:
            return {"status": "expired", "confidence": 85}
        elif is_active_session:
            return {"status": "active", "confidence": 90}
        else:
            # Ambiguous - check status code
            if response.status_code == 200:
                return {"status": "likely_active", "confidence": 60}
            elif response.status_code in [401, 403]:
                return {"status": "expired", "confidence": 80}
            else:
                return {"status": "unknown", "confidence": 30}

async def validate_session_async(cookie_dict, domain, platform):
    validator = SessionValidator()
    return await validator.probe_session(cookie_dict, domain, platform)

def validate_session(cookie_dict, domain, platform):
    """Synchronous wrapper"""
    return asyncio.run(validate_session_async(cookie_dict, domain, platform))