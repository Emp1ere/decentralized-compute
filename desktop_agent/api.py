import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_retry_session():
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=None,
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


class ApiClient:
    def __init__(self, base_url, api_key, verify_ssl):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = bool(verify_ssl)
        self.session = build_retry_session()

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}"}

    def request(self, method, path, payload=None, timeout=15):
        response = self.session.request(
            method=method,
            url=f"{self.base_url}{path}",
            json=payload,
            headers=self._headers(),
            timeout=timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json() if response.content else {}

    def public_get(self, path, timeout=15):
        response = self.session.get(
            f"{self.base_url}{path}",
            timeout=timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json() if response.content else {}
