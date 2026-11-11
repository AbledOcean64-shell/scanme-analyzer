import pandas as pd
import pytest
from defusedxml import ElementTree

from scanme_analyzer.parsers import parse_nmap_xml


def test_parse_nmap_xml_extracts_host_ports_services_and_os(tmp_path):
    xml_path = tmp_path / "scan.xml"
    xml_path.write_text(
        """\
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.0.2.10" addrtype="ipv4"/>
            <hostnames><hostname name="server.example.test"/></hostnames>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open"/>
                <service name="ssh" product="OpenSSH" version="9.2p1"
                         extrainfo="Debian 2+deb12u7"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
              </port>
            </ports>
            <os>
              <osmatch name="Linux 5.4 - 5.15" accuracy="98"/>
            </os>
          </host>
        </nmaprun>
        """,
        encoding="utf-8",
    )

    result = parse_nmap_xml(xml_path)

    assert isinstance(result, pd.DataFrame)
    assert result.columns.tolist() == [
        "Host",
        "Hostname",
        "Porta",
        "Serviço",
        "Versão",
        "Sistema Operacional",
        "Estado",
    ]
    records = result.to_dict(orient="records")
    assert records[0] == {
        "Host": "192.0.2.10",
        "Hostname": "server.example.test",
        "Porta": 22,
        "Serviço": "ssh",
        "Versão": "OpenSSH 9.2p1 Debian 2+deb12u7",
        "Sistema Operacional": "Linux 5.4 - 5.15",
        "Estado": "open",
    }
    assert {key: value for key, value in records[1].items() if key != "Versão"} == {
        "Host": "192.0.2.10",
        "Hostname": "server.example.test",
        "Porta": 80,
        "Serviço": "http",
        "Sistema Operacional": "Linux 5.4 - 5.15",
        "Estado": "open",
    }
    assert pd.isna(records[1]["Versão"])
    assert str(result["Porta"].dtype) == "Int64"


def test_parse_nmap_xml_preserves_host_without_ports(tmp_path):
    xml_path = tmp_path / "host-only.xml"
    xml_path.write_text(
        """\
        <nmaprun>
          <host>
            <address addr="2001:db8::1" addrtype="ipv6"/>
            <hostnames/>
            <ports/>
            <os>
              <osmatch name="">
                <osclass vendor="Example" osfamily="Unix" osgen="1"/>
              </osmatch>
            </os>
          </host>
        </nmaprun>
        """,
        encoding="utf-8",
    )

    result = parse_nmap_xml(xml_path)

    assert result.to_dict(orient="records") == [
        {
            "Host": "2001:db8::1",
            "Hostname": None,
            "Porta": None,
            "Serviço": None,
            "Versão": None,
            "Sistema Operacional": "Example Unix 1",
            "Estado": None,
        }
    ]


def test_parse_nmap_xml_rejects_malformed_xml(tmp_path):
    xml_path = tmp_path / "invalid.xml"
    xml_path.write_text("<nmaprun>", encoding="utf-8")

    with pytest.raises(ElementTree.ParseError):
        parse_nmap_xml(xml_path)


def test_parse_nmap_xml_returns_empty_dataframe_without_hosts(tmp_path):
    xml_path = tmp_path / "empty.xml"
    xml_path.write_text("<nmaprun/>", encoding="utf-8")

    result = parse_nmap_xml(xml_path)

    assert result.empty
    assert result.columns.tolist() == [
        "Host",
        "Hostname",
        "Porta",
        "Serviço",
        "Versão",
        "Sistema Operacional",
        "Estado",
    ]
    assert str(result["Porta"].dtype) == "Int64"


def test_parse_nmap_xml_accepts_xml_bytes():
    result = parse_nmap_xml(
        b'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/>'
        b'<ports><port protocol="tcp" portid="80"><state state="open"/>'
        b"</port></ports></host></nmaprun>"
    )

    assert result.loc[0, "Host"] == "192.0.2.1"
    assert result.loc[0, "Porta"] == 80
    assert result.loc[0, "Estado"] == "open"
