import argparse
import logging
import time

from app.anomaly_repository import AnomalyRepository
from app.attacker_repository import AttackerRepository
from app.config import get_settings
from app.cowrie_log_reader import CowrieLogReader
from app.feature_engineering import build_session_features
from app.geolocation_client import GeolocationClient
from app.iforest_predictor import IsolationForestPredictor


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def build_db_config(settings):
    return {
        "host": settings.db_host,
        "port": settings.db_port,
        "database": settings.db_name,
        "user": settings.db_user,
        "password": settings.db_password,
    }


def process_once():
    settings = get_settings()

    reader = CowrieLogReader(
        log_path=settings.cowrie_json_path,
        offset_path=settings.offset_path,
    )

    predictor = IsolationForestPredictor(
        model_path=settings.model_path,
        imputer_path=settings.imputer_path,
        feature_columns_path=settings.feature_columns_path,
        threshold_path=settings.threshold_path,
    )

    db_config = build_db_config(settings)

    attacker_repository = AttackerRepository(db_config)
    anomaly_repository = AnomalyRepository(db_config)

    geolocation_client = GeolocationClient(
        base_url=settings.geolocation_url,
        timeout_seconds=settings.geolocation_timeout_seconds,
        enabled=settings.geolocation_enabled,
    )

    events, new_offset = reader.read_new_events()

    if not events:
        logging.info("Tidak ada event baru dari log Cowrie.")
        reader.commit_offset(new_offset)
        return

    logging.info("Jumlah event baru dibaca: %s", len(events))

    session_features = build_session_features(events)

    if session_features.empty:
        logging.info("Tidak ada session valid yang dapat diproses.")
        reader.commit_offset(new_offset)
        return

    logging.info("Jumlah session yang diekstraksi: %s", len(session_features))

    prediction_results = predictor.predict(session_features)

    saved_count = 0
    anomaly_count = 0

    for _, row in prediction_results.iterrows():
        row_dict = row.to_dict()

        is_anomaly = int(row_dict.get("is_anomaly", 0))
        source_ip = row_dict.get("source_ip")

        first_seen = row_dict.get("first_seen")
        last_seen = row_dict.get("last_seen")

        if is_anomaly == 1:
            anomaly_count += 1

        if settings.store_only_anomalies and is_anomaly != 1:
            continue

        geolocation = geolocation_client.lookup(source_ip)

        attacker_repository.upsert_attacker(
            ip_address=source_ip,
            geolocation=geolocation,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        anomaly_repository.save_prediction(row_dict)

        saved_count += 1

    reader.commit_offset(new_offset)

    logging.info("Jumlah hasil prediksi disimpan: %s", saved_count)
    logging.info("Jumlah session anomali: %s", anomaly_count)


def main():
    parser = argparse.ArgumentParser(
        description="Cowrie Isolation Forest anomaly detection service"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Jalankan proses satu kali lalu berhenti.",
    )

    parser.add_argument(
        "--reset-offset",
        action="store_true",
        help="Reset offset agar log Cowrie dibaca dari awal.",
    )

    parser.add_argument(
        "--mark-current",
        action="store_true",
        help="Set offset ke posisi akhir file saat ini agar hanya membaca event baru setelah deploy.",
    )

    args = parser.parse_args()

    settings = get_settings()

    reader = CowrieLogReader(
        log_path=settings.cowrie_json_path,
        offset_path=settings.offset_path,
    )

    if args.reset_offset:
        reader.reset_offset()
        logging.info("Offset berhasil direset ke 0.")
        return

    if args.mark_current:
        reader.mark_current()
        logging.info("Offset berhasil diset ke posisi akhir file log saat ini.")
        return

    logging.info("Memulai Cowrie Isolation Forest service.")

    if args.once:
        process_once()
        return

    while True:
        try:
            process_once()
        except Exception as error:
            logging.exception("Terjadi error saat memproses log: %s", error)

        time.sleep(settings.poll_interval_seconds)


if __name__ == "__main__":
    main()