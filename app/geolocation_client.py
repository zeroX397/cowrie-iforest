import ipaddress
from typing import Dict, Optional

import requests


class GeolocationClient:
    def __init__(self, base_url: str, timeout_seconds: int = 5, enabled: bool = True):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.session = requests.Session()

    def _is_public_ip(self, ip_address: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_address)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            )
        except ValueError:
            return False

    def lookup(self, ip_address: str) -> Optional[Dict]:
        if not self.enabled:
            return None

        if not ip_address:
            return None

        if not self._is_public_ip(ip_address):
            return None

        url = f"{self.base_url}/{ip_address}"

        params = {
            "fields": "status,message,country,regionName,city,lat,lon,timezone,isp,query"
        }

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()

            data = response.json()

            if data.get("status") != "success":
                return None

            return {
                "ip_address": data.get("query") or ip_address,
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
            }

        except requests.RequestException:
            return None