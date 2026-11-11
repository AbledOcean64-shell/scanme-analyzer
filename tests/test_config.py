from scanme_analyzer.config import (
    DATABASE_PATH,
    GRAPHS_DIR,
    REPORTS_DIR,
    SCANS_DIR,
)


def test_data_paths_are_under_data_directory():
    assert SCANS_DIR.parent == REPORTS_DIR.parent == GRAPHS_DIR.parent
    assert DATABASE_PATH.parent == SCANS_DIR.parent
    assert SCANS_DIR.name == "scans"
    assert REPORTS_DIR.name == "reports"
    assert GRAPHS_DIR.name == "graphs"
