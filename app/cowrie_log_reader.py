import json
import os
from pathlib import Path
from typing import Dict, List, Tuple


class CowrieLogReader:
    def __init__(self, log_path: str, offset_path: str):
        self.log_path = Path(log_path)
        self.offset_path = Path(offset_path)

    def _load_offset(self) -> int:
        if not self.offset_path.exists():
            return 0

        try:
            with self.offset_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
                return int(data.get("offset", 0))
        except Exception:
            return 0

    def _save_offset(self, offset: int) -> None:
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)

        with self.offset_path.open("w", encoding="utf-8") as file:
            json.dump({"offset": offset}, file)

    def reset_offset(self) -> None:
        self._save_offset(0)

    def mark_current(self) -> None:
        if not self.log_path.exists():
            raise FileNotFoundError(f"File log Cowrie tidak ditemukan: {self.log_path}")

        current_size = self.log_path.stat().st_size
        self._save_offset(current_size)

    def read_new_events(self) -> Tuple[List[Dict], int]:
        if not self.log_path.exists():
            raise FileNotFoundError(f"File log Cowrie tidak ditemukan: {self.log_path}")

        current_size = self.log_path.stat().st_size
        offset = self._load_offset()

        # Jika file log dirotasi atau ukurannya mengecil, baca dari awal file aktif.
        if offset > current_size:
            offset = 0

        events: List[Dict] = []

        with self.log_path.open("r", encoding="utf-8", errors="ignore") as file:
            file.seek(offset)

            for line in file:
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    events.append(event)
                except json.JSONDecodeError:
                    continue

            new_offset = file.tell()

        return events, new_offset

    def commit_offset(self, offset: int) -> None:
        self._save_offset(offset)