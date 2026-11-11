import pandas as pd

from scanme_analyzer.ui import build_dashboard_data


def test_build_dashboard_data_counts_open_ports_and_ranks_hosts():
    hosts = pd.DataFrame(
        {
            "Host": [
                "192.0.2.10",
                "192.0.2.10",
                "192.0.2.20",
                "192.0.2.20",
                "192.0.2.30",
            ],
            "Porta": [21, 80, 445, 443, 23],
            "Serviço": ["ftp", "http", "microsoft-ds", "https", "telnet"],
            "Estado": ["open", "open", "open", "closed", "filtered"],
        }
    )

    result = build_dashboard_data(hosts)

    assert result.total_hosts == 3
    assert result.total_open_ports == 3
    assert result.average_score == 35 / 3
    assert result.open_port_counts.to_dict(orient="records") == [
        {"Porta": 21, "Quantidade": 1},
        {"Porta": 80, "Quantidade": 1},
        {"Porta": 445, "Quantidade": 1},
    ]
    assert result.service_counts.to_dict(orient="records") == [
        {"Serviço": "ftp", "Quantidade": 1},
        {"Serviço": "http", "Quantidade": 1},
        {"Serviço": "microsoft-ds", "Quantidade": 1},
    ]
    assert result.host_ranking["Host"].tolist() == [
        "192.0.2.20",
        "192.0.2.10",
        "192.0.2.30",
    ]
    assert result.host_ranking["Score"].tolist() == [20, 15, 0]
    assert result.host_ranking["Portas abertas"].tolist() == [1, 2, 0]


def test_build_dashboard_data_handles_hosts_without_open_ports():
    hosts = pd.DataFrame(
        {
            "Host": ["192.0.2.10"],
            "Porta": [3389],
            "Serviço": ["ms-wbt-server"],
            "Estado": ["closed"],
        }
    )

    result = build_dashboard_data(hosts)

    assert result.total_hosts == 1
    assert result.total_open_ports == 0
    assert result.average_score == 0
    assert result.open_port_counts.empty
    assert result.service_counts.empty
    assert result.host_ranking.loc[0, "Score"] == 0
    assert result.host_ranking.loc[0, "Portas abertas"] == 0


def test_build_dashboard_data_handles_empty_scan():
    hosts = pd.DataFrame(
        columns=["Host", "Hostname", "Porta", "Serviço", "Versão", "Estado"]
    )

    result = build_dashboard_data(hosts)

    assert result.total_hosts == 0
    assert result.total_open_ports == 0
    assert result.average_score is None
    assert result.open_port_counts.empty
    assert result.service_counts.empty
    assert result.host_ranking.empty
