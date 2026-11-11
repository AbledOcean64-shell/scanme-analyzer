"""Persistência de resumos de scans em SQLite."""

import math
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from scanme_analyzer.config import DATABASE_PATH


_CREATE_SCANS_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date TEXT NOT NULL,
    host_count INTEGER NOT NULL CHECK (host_count >= 0),
    risk_score REAL NOT NULL CHECK (risk_score >= 0),
    xml_path TEXT NOT NULL
)
"""


def initialize_database(database_path: str | Path = DATABASE_PATH) -> None:
    """Cria o arquivo SQLite e a tabela de scans caso ainda não existam."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(_CREATE_SCANS_TABLE)


def save_scan_record(
    host_count: int,
    risk_score: int | float,
    xml_path: str | Path,
    scan_date: datetime | None = None,
    database_path: str | Path = DATABASE_PATH,
) -> int:
    """Persiste o resumo do scan e retorna o identificador gerado.

    ``risk_score`` deve ser a média dos scores dos hosts do scan. O horário
    padrão é o momento atual em UTC; um horário fornecido é armazenado em
    formato ISO 8601, preservando seu fuso horário.
    """
    if isinstance(host_count, bool) or not isinstance(host_count, int):
        raise ValueError("A quantidade de hosts deve ser um número inteiro.")
    if host_count < 0:
        raise ValueError("A quantidade de hosts não pode ser negativa.")
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise ValueError("O score de risco deve ser numérico.")
    normalized_score = float(risk_score)
    if not math.isfinite(normalized_score) or normalized_score < 0:
        raise ValueError("O score de risco deve ser finito e não negativo.")
    if not isinstance(xml_path, (str, Path)) or not str(xml_path).strip():
        raise ValueError("O caminho do XML deve ser informado.")
    if scan_date is not None and not isinstance(scan_date, datetime):
        raise ValueError("A data do scan deve ser um datetime.")

    timestamp = (scan_date or datetime.now(timezone.utc)).isoformat()
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(_CREATE_SCANS_TABLE)
            cursor = connection.execute(
                """
                INSERT INTO scans (scan_date, host_count, risk_score, xml_path)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, host_count, normalized_score, str(xml_path)),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("O SQLite não retornou o identificador do scan.")
            return cursor.lastrowid
