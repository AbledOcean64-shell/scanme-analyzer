# ScanMe Analyzer

Aplicação para importar arquivos XML exportados pelo **Nmap**, analisar hosts e
portas encontradas e apresentar uma visão geral da exposição a riscos. O projeto
inclui um dashboard Streamlit, classificação baseada em regras e um
módulo SQLite para registrar o histórico dos scans.

> O ScanMe Analyzer analisa arquivos de saída do Nmap; não executa scans de
> rede. Use os arquivos somente em avaliações autorizadas.

## Índice

- [Funcionalidades](#funcionalidades)
- [Screenshots](#screenshots)
- [Tecnologias utilizadas](#tecnologias-utilizadas)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Regras atuais de risco](#regras-atuais-de-risco)
- [Testes](#testes)
- [Melhorias futuras](#melhorias-futuras)

## Funcionalidades

- Importação de arquivos XML exportados pelo Nmap.
- Extração de endereço IP, hostname, porta, serviço, versão, sistema
  operacional e estado da porta.
- Dashboard interativo com:
  - total de hosts;
  - total de portas abertas;
  - score médio de risco;
  - gráficos de portas abertas e serviços;
  - ranking dos dez hosts mais expostos.
- Score, classificação e justificativa de risco calculados por host.
- Registro SQLite do resumo de cada scan: data, quantidade de hosts, score
  médio e caminho do XML.
- Testes automatizados para parser, análise, dashboard e persistência.

## Screenshots

As capturas de tela da aplicação ainda não estão incluídas neste repositório.
Quando estiverem disponíveis, serão adicionadas nesta seção.

## Tecnologias utilizadas

| Tecnologia | Uso |
| --- | --- |
| Python 3.12 | Linguagem e runtime do projeto |
| Streamlit | Interface e dashboard |
| Pandas | Estrutura tabular e análise dos dados |
| SQLite | Persistência local do histórico |
| `defusedxml` | Leitura segura dos arquivos XML |
| pytest | Testes automatizados |

## Requisitos

- Python **3.12**
- pip
- Um arquivo XML de saída do Nmap para analisar

## Instalação

Clone o repositório e entre na pasta do projeto. No PowerShell do Windows:

```powershell
git clone https://github.com/<usuario>/<repositorio>.git
cd <repositorio>
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

No macOS ou Linux, crie e ative o ambiente virtual com:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Uso

Inicie a interface:

```bash
streamlit run app.py
```

No dashboard, carregue um XML exportado pelo Nmap ou selecione um XML colocado
na pasta `data/scans/`. O dashboard apresenta as métricas, os gráficos e o
ranking para o scan selecionado.

### Analisar um XML em Python

```python
from scanme_analyzer.analysis import calculate_risk_scores
from scanme_analyzer.parsers import parse_nmap_xml

hosts = parse_nmap_xml("data/scans/scan.xml")
scores = calculate_risk_scores(hosts)

print(hosts.head())
print(scores)
```

O parser retorna um DataFrame com uma linha por porta; hosts sem portas também
são preservados. A coluna `Estado` indica o estado da porta conforme o XML.

### Salvar o resumo no SQLite

O módulo de banco salva uma entrada de histórico por chamada. O score do scan é
a média dos scores dos hosts:

```python
from scanme_analyzer.database import save_scan_record

scan_id = save_scan_record(
    host_count=int(hosts["Host"].nunique()),
    risk_score=float(scores["Score"].mean()) if not scores.empty else 0,
    xml_path="data/scans/scan.xml",
)

print(f"Scan salvo com ID {scan_id}")
```

Por padrão, o banco é criado em `data/scanme_analyzer.sqlite3`. O caminho pode
ser personalizado ao chamar `initialize_database` ou `save_scan_record`.

## Estrutura do projeto

```text
scanme-analyzer/
├── app.py
├── pyproject.toml
├── README.md
├── data/
│   ├── graphs/
│   ├── reports/
│   └── scans/
├── src/
│   └── scanme_analyzer/
│       ├── analysis/
│       │   └── risk_score.py
│       ├── charts/
│       ├── database/
│       │   └── scans.py
│       ├── parsers/
│       │   └── nmap_xml.py
│       ├── reports/
│       ├── services/
│       ├── ui/
│       │   └── dashboard.py
│       ├── __init__.py
│       └── config.py
└── tests/
    ├── test_config.py
    ├── test_dashboard.py
    ├── test_database.py
    ├── test_nmap_xml.py
    └── test_risk_score.py
```

As pastas `charts/`, `reports/` e `services/` reservam espaço para os próximos
módulos. Os XMLs locais, relatórios, gráficos e o banco de dados não são
versionados.

## Regras atuais de risco

O cálculo considera as portas abertas abaixo. Cada porta de risco distinta
contribui uma vez para o score do respectivo host.

| Porta | Pontos |
| ---: | ---: |
| 21 | 15 |
| 23 | 25 |
| 3389 | 10 |
| 445 | 20 |

| Score | Classificação |
| ---: | --- |
| 0–20 | Baixo |
| 21–50 | Médio |
| 51–100 | Alto |

## Testes

Com as dependências de desenvolvimento instaladas, execute:

```bash
python -m pytest
```

## Melhorias futuras

- Integrar o salvamento do histórico SQLite ao fluxo de análise do dashboard.
- Consultar e comparar scans anteriores pela interface.
- Exportar resultados e relatórios em CSV, JSON ou PDF.
- Adicionar filtros por host, serviço, estado e classificação de risco.
- Expandir as regras de pontuação e permitir configuração sem alterar o código.
- Adicionar capturas de tela e exemplos de relatórios ao repositório.
- Melhorar a cobertura com testes de interface e de integração.
