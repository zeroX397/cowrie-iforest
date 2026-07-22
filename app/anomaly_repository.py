from typing import Dict

import mysql.connector


class AnomalyRepository:
    def __init__(self, db_config: Dict):
        self.db_config = db_config

    def _connect(self):
        return mysql.connector.connect(**self.db_config)

    def save_prediction(self, row: Dict) -> None:
        """
        Menyimpan hasil prediksi ke tabel anomalies.

        Struktur tabel anomalies:
        - id
        - sessions_id
        - anomalies_score
        - is_anomaly
        - detected_at
        - created_at
        """
        query = """
            INSERT INTO anomalies (
                sessions_id,
                anomalies_score,
                is_anomaly,
                detected_at,
                created_at
            )
            VALUES (
                %(sessions_id)s,
                %(anomalies_score)s,
                %(is_anomaly)s,
                NOW(),
                NOW()
            )
            ON DUPLICATE KEY UPDATE
                anomalies_score = VALUES(anomalies_score),
                is_anomaly = VALUES(is_anomaly),
                detected_at = NOW()
        """

        params = {
            "sessions_id": row.get("session_id"),
            "anomalies_score": float(row.get("anomaly_score", 0)),
            "is_anomaly": int(row.get("is_anomaly", 0)),
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