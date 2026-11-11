import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanme_analyzer.database import initialize_database, save_scan_record


def test_save_scan_record_creates_database_and_persists_values(tmp_path):
    database_path = tmp_path / "nested" / "scanme.sqlite3"
    scan_date = datetime(2026, 11, 11, 16, 5, tzinfo=timezone.utc)

    scan_id = save_scan_record(
        host_count=4,
        risk_score=17.5,
        xml_path=Path("data/scans/example.xml"),
        scan_date=scan_date,
        database_path=database_path,
    )

    assert scan_id == 1
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT scan_date, host_count, risk_score, xml_path
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

    assert row == (
        scan_date.isoformat(),
        4,
        17.5,
        str(Path("data/scans/example.xml")),
    )


def test_initialize_database_is_safe_to_call_repeatedly(tmp_path):
    database_path = tmp_path / "scanme.sqlite3"

    initialize_database(database_path)
    initialize_database(database_path)

    with sqlite3.connect(database_path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
        ).fetchall()

    assert tables == [("scans",)]


def test_save_scan_record_preserves_history(tmp_path):
    database_path = tmp_path / "scanme.sqlite3"

    first_id = save_scan_record(1, 10, "first.xml", database_path=database_path)
    second_id = save_scan_record(2, 20, "second.xml", database_path=database_path)

    assert second_id == first_id + 1
    with sqlite3.connect(database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    assert count == 2


@pytest.mark.parametrize(
    ("host_count", "risk_score", "xml_path", "message"),
    [
        (-1, 0, "scan.xml", "quantidade de hosts não pode ser negativa"),
        (1.5, 0, "scan.xml", "quantidade de hosts deve ser um número inteiro"),
        (1, -0.1, "scan.xml", "score de risco deve ser finito e não negativo"),
        (1, float("inf"), "scan.xml", "score de risco deve ser finito e não negativo"),
        (1, 0, "", "caminho do XML deve ser informado"),
        (True, 0, "scan.xml", "quantidade de hosts deve ser um número inteiro"),
        (1, True, "scan.xml", "score de risco deve ser numérico"),
    ],
)
def test_save_scan_record_rejects_invalid_values(
    tmp_path, host_count, risk_score, xml_path, message
):
    with pytest.raises(ValueError, match=message):
        save_scan_record(
            host_count,
            risk_score,
            xml_path,
            database_path=tmp_path / "scanme.sqlite3",
        )
