"""Cálculo de pontuação e classificação de risco por host."""

import pandas as pd


PORT_RISK_POINTS = {
    21: 15,
    23: 25,
    3389: 10,
    445: 20,
}

RESULT_COLUMNS = ["Host", "Score", "Classificação", "Justificativa"]


def _classify_score(score: int) -> str:
    if score <= 20:
        return "Baixo"
    if score <= 50:
        return "Médio"
    return "Alto"


def calculate_risk_scores(hosts: pd.DataFrame) -> pd.DataFrame:
    """Calcula score, classificação e justificativa para cada host.

    Espera um DataFrame com as colunas ``Host`` e ``Porta``, como o produzido
    por :func:`scanme_analyzer.parsers.parse_nmap_xml`. Cada porta de risco
    distinta conta uma vez por host.
    """
    required_columns = {"Host", "Porta"}
    missing_columns = required_columns.difference(hosts.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Colunas obrigatórias ausentes: {missing}")

    numeric_ports = pd.to_numeric(hosts["Porta"], errors="raise")
    non_integer_ports = numeric_ports.dropna().mod(1).ne(0)
    if non_integer_ports.any():
        raise ValueError("A coluna 'Porta' deve conter números inteiros.")

    normalized_hosts = hosts[["Host"]].copy()
    if "Estado" in hosts.columns:
        is_open = hosts["Estado"].astype("string").str.casefold().eq("open")
        numeric_ports = numeric_ports.where(is_open)
    normalized_hosts["_Porta"] = numeric_ports.astype("Int64")
    results: list[dict[str, object]] = []

    for host, host_rows in normalized_hosts.groupby(
        "Host", dropna=False, sort=False
    ):
        open_ports = set(host_rows["_Porta"].dropna().astype(int))
        findings = [
            (port, points)
            for port, points in PORT_RISK_POINTS.items()
            if port in open_ports
        ]
        score = sum(points for _, points in findings)
        justification = (
            "; ".join(
                f"Porta {port} (+{points} pontos)" for port, points in findings
            )
            if findings
            else "Nenhuma porta de risco identificada."
        )
        results.append(
            {
                "Host": host,
                "Score": score,
                "Classificação": _classify_score(score),
                "Justificativa": justification,
            }
        )

    return pd.DataFrame.from_records(results, columns=RESULT_COLUMNS)
