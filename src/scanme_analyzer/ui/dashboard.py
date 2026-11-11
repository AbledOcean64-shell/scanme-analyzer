"""Métricas e interface do dashboard Streamlit."""

from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import streamlit as st
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from scanme_analyzer.analysis import calculate_risk_scores
from scanme_analyzer.config import SCANS_DIR
from scanme_analyzer.parsers import parse_nmap_xml


@dataclass(frozen=True)
class DashboardData:
    total_hosts: int
    total_open_ports: int
    average_score: float | None
    open_port_counts: pd.DataFrame
    service_counts: pd.DataFrame
    host_ranking: pd.DataFrame


def build_dashboard_data(hosts: pd.DataFrame) -> DashboardData:
    """Calcula métricas, gráficos agregados e ranking a partir dos hosts."""
    required_columns = {"Host", "Porta"}
    missing_columns = required_columns.difference(hosts.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Colunas obrigatórias ausentes: {missing}")

    total_hosts = int(hosts["Host"].nunique())
    if "Estado" in hosts.columns:
        is_open = hosts["Estado"].astype("string").str.casefold().eq("open")
        open_ports = hosts.loc[is_open.fillna(False)].copy()
    else:
        open_ports = hosts.loc[hosts["Porta"].notna()].copy()

    numeric_ports = pd.to_numeric(open_ports["Porta"], errors="raise")
    non_integer_ports = numeric_ports.dropna().mod(1).ne(0)
    if non_integer_ports.any():
        raise ValueError("A coluna 'Porta' deve conter números inteiros.")
    open_ports = open_ports.loc[numeric_ports.notna()].copy()
    open_ports["Porta"] = numeric_ports.loc[numeric_ports.notna()].astype(int)

    open_port_counts = (
        open_ports["Porta"]
        .value_counts()
        .sort_index()
        .rename_axis("Porta")
        .reset_index(name="Quantidade")
    )
    if "Serviço" in open_ports.columns:
        services = open_ports["Serviço"].fillna("Não identificado")
    else:
        services = pd.Series(
            "Não identificado", index=open_ports.index, dtype="string"
        )
    service_counts = (
        services.value_counts()
        .rename_axis("Serviço")
        .reset_index(name="Quantidade")
    )

    risk_scores = calculate_risk_scores(hosts)
    open_counts_by_host = (
        open_ports.groupby("Host", dropna=False)
        .size()
        .rename("Portas abertas")
        .reset_index()
    )
    host_ranking = risk_scores.merge(
        open_counts_by_host, on="Host", how="left", sort=False
    )
    host_ranking["Portas abertas"] = (
        host_ranking["Portas abertas"].fillna(0).astype(int)
    )
    host_ranking = host_ranking.sort_values(
        ["Score", "Portas abertas", "Host"],
        ascending=[False, False, True],
        na_position="last",
        kind="stable",
    ).reset_index(drop=True)

    return DashboardData(
        total_hosts=total_hosts,
        total_open_ports=len(open_ports),
        average_score=(
            float(risk_scores["Score"].mean()) if not risk_scores.empty else None
        ),
        open_port_counts=open_port_counts,
        service_counts=service_counts,
        host_ranking=host_ranking,
    )


def render_dashboard() -> None:
    """Exibe o dashboard, permitindo carregar um XML ou escolher um scan salvo."""
    st.set_page_config(page_title="ScanMe Analyzer", page_icon="🔎", layout="wide")
    st.title("ScanMe Analyzer")
    st.caption("Análise de hosts, portas abertas e exposição a riscos.")

    uploaded_file = st.file_uploader(
        "Carregue um XML exportado pelo Nmap", type=["xml"]
    )
    saved_scans = sorted(SCANS_DIR.glob("*.xml")) if SCANS_DIR.exists() else []
    selected_scan: str | None = None
    if uploaded_file is None and saved_scans:
        selected_scan = st.selectbox(
            "Ou selecione um scan salvo",
            options=["", *(str(path) for path in saved_scans)],
            format_func=lambda value: (
                "Selecione um arquivo..." if not value else Path(value).name
            ),
        )

    if uploaded_file is None:
        if not selected_scan:
            st.info("Carregue um arquivo XML do Nmap para visualizar o dashboard.")
            return
        scan_source: str | bytes = selected_scan
    else:
        scan_source = uploaded_file.getvalue()

    try:
        dashboard = build_dashboard_data(parse_nmap_xml(scan_source))
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        ElementTree.ParseError,
        DefusedXmlException,
    ) as error:
        st.error(f"Não foi possível analisar o scan: {error}")
        return

    metric_columns = st.columns(3)
    metric_columns[0].metric("Total de hosts", dashboard.total_hosts)
    metric_columns[1].metric("Total de portas abertas", dashboard.total_open_ports)
    metric_columns[2].metric(
        "Score médio",
        (
            f"{dashboard.average_score:.1f}"
            if dashboard.average_score is not None
            else "N/D"
        ),
    )

    chart_columns = st.columns(2)
    with chart_columns[0]:
        st.subheader("Portas abertas")
        if dashboard.open_port_counts.empty:
            st.info("Nenhuma porta aberta foi encontrada.")
        else:
            st.bar_chart(
                dashboard.open_port_counts,
                x="Porta",
                y="Quantidade",
                horizontal=True,
            )
    with chart_columns[1]:
        st.subheader("Serviços")
        if dashboard.service_counts.empty:
            st.info("Nenhum serviço foi identificado.")
        else:
            st.bar_chart(
                dashboard.service_counts,
                x="Serviço",
                y="Quantidade",
                horizontal=True,
            )

    st.subheader("Ranking de hosts mais expostos")
    if dashboard.host_ranking.empty:
        st.info("Nenhum host foi encontrado no scan.")
    else:
        ranking = dashboard.host_ranking.head(10).copy()
        ranking.insert(0, "Posição", range(1, len(ranking) + 1))
        st.dataframe(
            ranking[
                [
                    "Posição",
                    "Host",
                    "Score",
                    "Classificação",
                    "Portas abertas",
                    "Justificativa",
                ]
            ],
            hide_index=True,
            use_container_width=True,
        )
