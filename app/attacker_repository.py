from typing import Dict, Optional

import mysql.connector


class AttackerRepository:
    def __init__(self, db_config: Dict):
        self.db_config = db_config

    def _connect(self):
        return mysql.connector.connect(**self.db_config)

    def upsert_attacker(
        self,
        ip_address: str,
        geolocation: Optional[Dict] = None,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
    ) -> None:
        """
        Menyimpan atau memperbarui data attacker ke tabel attackers.

        Struktur tabel attackers:
        - id
        - ip_address
        - country
        - isp
        - latitude
        - longitude
        - first_seen
        - last_seen
        - created_at
        - updated_at
        """
        if not ip_address:
            return

        geolocation = geolocation or {}

        query = """
            INSERT INTO attackers (
                ip_address,
                country,
                isp,
                latitude,
                longitude,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (
                %(ip_address)s,
                %(country)s,
                %(isp)s,
                %(latitude)s,
                %(longitude)s,
                %(first_seen)s,
                %(last_seen)s,
                NOW(),
                NOW()
            )
            ON DUPLICATE KEY UPDATE
                country = COALESCE(VALUES(country), country),
                isp = COALESCE(VALUES(isp), isp),
                latitude = COALESCE(VALUES(latitude), latitude),
                longitude = COALESCE(VALUES(longitude), longitude),

                first_seen = CASE
                    WHEN first_seen IS NULL THEN VALUES(first_seen)
                    WHEN VALUES(first_seen) IS NULL THEN first_seen
                    WHEN VALUES(first_seen) < first_seen THEN VALUES(first_seen)
                    ELSE first_seen
                END,

                last_seen = CASE
                    WHEN last_seen IS NULL THEN VALUES(last_seen)
                    WHEN VALUES(last_seen) IS NULL THEN last_seen
                    WHEN VALUES(last_seen) > last_seen THEN VALUES(last_seen)
                    ELSE last_seen
                END,

                updated_at = NOW()
        """

        params = {
            "ip_address": ip_address,
            "country": geolocation.get("country"),
            "isp": geolocation.get("isp"),
            "latitude": geolocation.get("latitude"),
            "longitude": geolocation.get("longitude"),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

        connection = self._connect()
        cursor = None

        try:
            cursor = connection.cursor()
            cursor.execute(query, params)
            connection.commit()
        finally:
            if cursor is not None:
                cursor.close()
            connection.close()