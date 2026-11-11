"""Caminhos compartilhados e configuração local do projeto."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
SCANS_DIR = DATA_DIR / "scans"
REPORTS_DIR = DATA_DIR / "reports"
GRAPHS_DIR = DATA_DIR / "graphs"
DATABASE_PATH = DATA_DIR / "scanme_analyzer.sqlite3"
