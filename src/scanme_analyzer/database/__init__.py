"""Acesso e persistência de dados em SQLite."""

from scanme_analyzer.database.scans import initialize_database, save_scan_record

__all__ = ["initialize_database", "save_scan_record"]
