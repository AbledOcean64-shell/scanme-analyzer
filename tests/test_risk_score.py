import pandas as pd
import pytest

from scanme_analyzer.analysis import calculate_risk_scores


def test_calculate_risk_scores_returns_one_result_per_host():
    hosts = pd.DataFrame(
        {
            "Host": ["192.0.2.10", "192.0.2.10", "192.0.2.10", "192.0.2.20"],
            "Porta": [21, 23, 445, 3389],
        }
    )

    result = calculate_risk_scores(hosts)

    assert result.to_dict(orient="records") == [
        {
            "Host": "192.0.2.10",
            "Score": 60,
            "Classificação": "Alto",
            "Justificativa": (
                "Porta 21 (+15 pontos); Porta 23 (+25 pontos); "
                "Porta 445 (+20 pontos)"
            ),
        },
        {
            "Host": "192.0.2.20",
            "Score": 10,
            "Classificação": "Baixo",
            "Justificativa": "Porta 3389 (+10 pontos)",
        },
    ]


@pytest.mark.parametrize(
    ("ports", "expected_score", "expected_classification"),
    [
        ([None], 0, "Baixo"),
        ([445], 20, "Baixo"),
        ([21, 23, 3389], 50, "Médio"),
        ([21, 23, 445], 60, "Alto"),
    ],
)
def test_calculate_risk_scores_applies_classification_boundaries(
    ports, expected_score, expected_classification
):
    hosts = pd.DataFrame({"Host": ["192.0.2.10"] * len(ports), "Porta": ports})

    result = calculate_risk_scores(hosts)

    assert result.loc[0, "Score"] == expected_score
    assert result.loc[0, "Classificação"] == expected_classification


def test_calculate_risk_scores_counts_each_risk_port_once():
    hosts = pd.DataFrame({"Host": ["192.0.2.10"] * 3, "Porta": [21, 21, 80]})

    result = calculate_risk_scores(hosts)

    assert result.loc[0, "Score"] == 15
    assert result.loc[0, "Justificativa"] == "Porta 21 (+15 pontos)"


def test_calculate_risk_scores_reports_hosts_without_risk_ports():
    hosts = pd.DataFrame(
        {"Host": ["192.0.2.10", "192.0.2.10"], "Porta": [None, 80]}
    )

    result = calculate_risk_scores(hosts)

    assert result.to_dict(orient="records") == [
        {
            "Host": "192.0.2.10",
            "Score": 0,
            "Classificação": "Baixo",
            "Justificativa": "Nenhuma porta de risco identificada.",
        }
    ]


def test_calculate_risk_scores_rejects_missing_columns():
    with pytest.raises(ValueError, match="Colunas obrigatórias ausentes: Porta"):
        calculate_risk_scores(pd.DataFrame({"Host": ["192.0.2.10"]}))


def test_calculate_risk_scores_rejects_non_integer_ports():
    hosts = pd.DataFrame({"Host": ["192.0.2.10"], "Porta": [21.5]})

    with pytest.raises(ValueError, match="números inteiros"):
        calculate_risk_scores(hosts)
