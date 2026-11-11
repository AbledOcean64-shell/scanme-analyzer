"""Parser para arquivos XML exportados pelo Nmap."""

from pathlib import Path
from xml.etree.ElementTree import Element

import pandas as pd
from defusedxml import ElementTree


COLUMNS = [
    "Host",
    "Hostname",
    "Porta",
    "Serviço",
    "Versão",
    "Sistema Operacional",
    "Estado",
]


def _host_address(host: Element) -> str | None:
    addresses = host.findall("address")
    for address_type in ("ipv4", "ipv6"):
        for address in addresses:
            if address.get("addrtype") == address_type:
                return address.get("addr")
    return addresses[0].get("addr") if addresses else None


def _operating_system(host: Element) -> str | None:
    os_match = host.find("os/osmatch")
    if os_match is not None and os_match.get("name"):
        return os_match.get("name")

    os_class = host.find("os/osmatch/osclass")
    if os_class is None:
        os_class = host.find("os/osclass")
    if os_class is None:
        return None

    details: list[str] = []
    for attribute in ("vendor", "osfamily", "osgen"):
        detail = os_class.get(attribute)
        if detail:
            details.append(detail)
    return " ".join(details) or None


def parse_nmap_xml(xml_path: str | Path | bytes) -> pd.DataFrame:
    """Lê um XML do Nmap e retorna uma linha por porta identificada.

    Hosts sem portas também são incluídos, com os campos de porta e serviço
    vazios, para preservar as informações do host no resultado.
    """
    root = (
        ElementTree.fromstring(xml_path)
        if isinstance(xml_path, bytes)
        else ElementTree.parse(xml_path).getroot()
    )
    if root is None:
        raise ValueError("O arquivo XML do Nmap não contém um elemento raiz.")
    records: list[dict[str, str | int | None]] = []

    for host in root.findall("host"):
        hostname_element = host.find("hostnames/hostname")
        hostname = (
            hostname_element.get("name") if hostname_element is not None else None
        )
        host_details = {
            "Host": _host_address(host),
            "Hostname": hostname,
            "Sistema Operacional": _operating_system(host),
        }
        ports = host.findall("ports/port")

        if not ports:
            records.append(
                {
                    **host_details,
                    "Porta": None,
                    "Serviço": None,
                    "Versão": None,
                    "Estado": None,
                }
            )
            continue

        for port in ports:
            service = port.find("service")
            version_details: list[str] = []
            if service is not None:
                for attribute in ("product", "version", "extrainfo"):
                    detail = service.get(attribute)
                    if detail:
                        version_details.append(detail)
            state_element = port.find("state")
            records.append(
                {
                    **host_details,
                    "Porta": int(port.get("portid", "")),
                    "Serviço": service.get("name") if service is not None else None,
                    "Versão": " ".join(version_details) or None,
                    "Estado": state_element.get("state")
                    if state_element is not None
                    else None,
                }
            )

    dataframe = pd.DataFrame.from_records(records, columns=COLUMNS)
    dataframe["Porta"] = dataframe["Porta"].astype("Int64")
    return dataframe
