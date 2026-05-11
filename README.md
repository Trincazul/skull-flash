<h1 align="center">
  <br>
  <pre>
 _____ _          _ _   _____ _           _
/ ____| |        | | | |  ___| |         | |
| (___  | | ___  _| | | | |_  | | __ _ ___| |__
 \___ \ | |/ / | | | | | |  __| |/ _` / __| '_ \
 ____) ||   <| |_| | | | |  | | (_| \__ \ | | |
|_____/ |_|\_\\__,_|_|_| |_|  |_|\__,_|___/_| |_|
  </pre>
</h1>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0.0-blue.svg"/>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue"/>
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg"/>
  <img alt="CI" src="https://img.shields.io/badge/CI-GitHub%20Actions-green"/>
</p>

<p align="center">
  Ferramenta profissional de auditoria de segurança — port scan, OSINT, análise web/SSL,<br>
  correlação de CVEs, fingerprinting e dashboard em tempo real com SSE.
</p>

---

## Sumário

- [Visão Geral](#visão-geral)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Comandos CLI](#comandos-cli)
  - [scan](#skull-flash-scan)
  - [osint](#skull-flash-osint)
  - [web](#skull-flash-web)
  - [phone](#skull-flash-phone)
  - [cve](#skull-flash-cve)
  - [analyze](#skull-flash-analyze)
  - [serve](#skull-flash-serve)
  - [report](#skull-flash-report)
  - [plugin](#skull-flash-plugin)
  - [export](#skull-flash-export)
- [Dashboard Web](#dashboard-web)
- [Sistema de Plugins](#sistema-de-plugins)
- [Integrações](#integrações)
- [Docker](#docker)
- [Testes](#testes)
- [Aviso Ético e Legal](#aviso-ético-e-legal)
- [Autores](#autores)

---

## Visão Geral

Skull Flash v2 é uma ferramenta de auditoria de segurança de código aberto voltada para profissionais de pentest e estudantes da área. Combina múltiplos módulos em um único CLI com saída estruturada, relatórios exportáveis e um dashboard web em tempo real.

**Módulos disponíveis:**

| Módulo | O que faz |
|--------|-----------|
| **Port Scan** | Identifica portas abertas e serviços via nmap assíncrono |
| **OSINT** | Coleta WHOIS, registros DNS e enumeração de subdomínios |
| **Web / SSL** | Analisa headers de segurança HTTP e certificados TLS |
| **Fingerprinting** | Detecta tecnologias (CMS, frameworks, servidores, CDN) via resposta HTTP passiva |
| **CVE** | Correlaciona serviços com vulnerabilidades na base NVD |
| **Correlação** | Engine de 6 regras que gera findings com score de risco (0–100) |
| **Phone** | Lookup de operadora, país e tipo de número telefônico |
| **Dashboard Web** | Interface gráfica com atualizações em tempo real via SSE |
| **Plugins** | Sistema extensível com validação de segurança via AST |
| **Integrações** | Exportação para Jira, Dradis e Faraday |

---

## Instalação

### Requisitos

- Python 3.10 ou superior
- [nmap](https://nmap.org/download.html) instalado no sistema

### Instalação básica

```bash
git clone https://github.com/Trincazul/skull-flash.git
cd skull-flash
pip install -e .
```

### Com o dashboard web

```bash
pip install -e ".[web]"
```

### Com integrações (Jira, Faraday)

```bash
pip install -e ".[integrations]"
```

### Tudo de uma vez

```bash
pip install -e ".[all]"
```

### Com dependências de desenvolvimento

```bash
pip install -e ".[dev]"
```

### Via Docker

```bash
docker build -t skull-flash .
docker run --rm -it skull-flash skull-flash --help
```

---

## Configuração

O Skull Flash carrega configurações em ordem de prioridade:

1. Variáveis de ambiente prefixadas com `SKULLFLASH_`
2. Arquivo local: `~/.skullflash/config.yaml`
3. Arquivo padrão: `config/default.yaml`

### Variáveis de ambiente disponíveis

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `SKULLFLASH_NVD_API_KEY` | Chave da API NVD (aumenta o rate limit de CVEs) | — |
| `SKULLFLASH_SHODAN_API_KEY` | Chave da API Shodan | — |
| `SKULLFLASH_SCAN_TIMEOUT` | Timeout de scan em segundos | `30` |
| `SKULLFLASH_LOG_LEVEL` | Nível de log (`DEBUG`, `INFO`, `WARNING`) | `INFO` |
| `SKULLFLASH_DEFAULT_OUTPUT_DIR` | Diretório padrão para relatórios | `./reports` |

### Exemplo de `~/.skullflash/config.yaml`

```yaml
nvd_api_key: "sua-chave-aqui"
scan_timeout: 60
log_level: INFO
allowed_targets:
  - "192.168.1.0/24"
  - "10.0.0.0/8"
blocked_targets:
  - "8.8.8.8"
```

---

## Comandos CLI

### Opções globais

```
skull-flash [--verbose | --quiet] [--version] <comando>
```

| Flag | Descrição |
|------|-----------|
| `-v, --verbose` | Ativa saída DEBUG |
| `-q, --quiet` | Suprime tudo exceto erros |
| `--version` | Exibe a versão |

---

### `skull-flash scan`

Realiza um port scan no alvo usando nmap e exibe serviços detectados.

```bash
skull-flash scan --target 192.168.1.1
skull-flash scan --target 10.0.0.0/24 --ports 22,80,443,3306
skull-flash scan --target example.com --ports 1-65535 --cve --output relatorio.json
```

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| `-t, --target` | IP, hostname ou CIDR (obrigatório) | — |
| `-p, --ports` | Faixa de portas | `1-1000` |
| `--cve` | Correlaciona serviços com CVEs da NVD | — |
| `-o, --output` | Salva relatório no arquivo indicado | — |
| `--format` | Formato do relatório: `json`, `html`, `pdf` | `json` |

---

### `skull-flash osint`

Coleta informações públicas sobre um domínio ou IP.

```bash
skull-flash osint --target example.com
skull-flash osint --target example.com --subdomains --output osint.html --format html
```

| Opção | Descrição |
|-------|-----------|
| `-t, --target` | Domínio ou IP (obrigatório) |
| `--subdomains` | Habilita enumeração de subdomínios via DNS |
| `-o, --output` | Salva resultado em arquivo |
| `--format` | `json`, `html` ou `pdf` |

**O que é coletado:**
- Registro WHOIS (registrador, datas, nameservers)
- Registros DNS (A, AAAA, MX, NS, TXT, CNAME)
- Subdomínios (quando `--subdomains` ativo)

---

### `skull-flash web`

Analisa a postura de segurança de uma URL.

```bash
skull-flash web --target https://example.com
skull-flash web --target https://example.com --fingerprint --output web.json
skull-flash web --target https://example.com --no-ssl --no-headers
```

| Opção | Descrição |
|-------|-----------|
| `-t, --target` | URL com esquema (`https://...`) |
| `--no-ssl` | Pula verificação do certificado SSL/TLS |
| `--no-headers` | Pula verificação de headers de segurança |
| `--fingerprint` | Detecta tecnologias via resposta HTTP passiva |
| `-o, --output` | Salva resultado em arquivo |
| `--format` | `json`, `html` ou `pdf` |

**Headers verificados:** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`.

**Fingerprinting detecta:** 30+ tecnologias incluindo WordPress, Django, Rails, nginx, Apache, Cloudflare, Varnish, React, Next.js, entre outras.

---

### `skull-flash phone`

Realiza lookup de um número de telefone.

```bash
skull-flash phone --number +5511999990000
skull-flash phone -n +14155552671
```

**Informações retornadas:** operadora, país, região, tipo (móvel/fixo/VoIP), formatos nacional e internacional.

---

### `skull-flash cve`

Escaneia o alvo e correlaciona os serviços com CVEs da base NVD.

```bash
skull-flash cve --target 192.168.1.1
skull-flash cve --target 10.0.0.1 --ports 1-10000 --output cves.json
```

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| `-t, --target` | IP ou CIDR | — |
| `-p, --ports` | Faixa de portas | `1-1000` |
| `-o, --output` | Salva resultado | — |
| `--format` | `json`, `html`, `pdf` | `json` |

> Os resultados são armazenados em cache por 24 horas em `~/.skullflash/cve_cache.json`.

---

### `skull-flash analyze`

**Comando principal** — executa scan completo, módulos opcionais e o engine de correlação, gerando um relatório de risco com score de 0 a 100.

```bash
# Scan básico com análise de risco
skull-flash analyze --target 192.168.1.1

# Análise completa
skull-flash analyze \
  --target example.com \
  --ports 1-10000 \
  --cve \
  --web \
  --osint \
  --output relatorio_completo.json
```

| Opção | Descrição |
|-------|-----------|
| `-t, --target` | Alvo (obrigatório) |
| `-p, --ports` | Faixa de portas |
| `--cve` | Habilita correlação de CVEs |
| `--web` | Habilita análise de headers/SSL |
| `--osint` | Habilita coleta OSINT |
| `-o, --output` | Salva relatório completo |
| `--format` | `json`, `html`, `pdf` |

**Regras de correlação aplicadas:**

| Regra | Trigger | Severidade |
|-------|---------|------------|
| RULE-001 | CVE com CVSS ≥ 9.0 em serviço aberto | CRITICAL |
| RULE-002 | SSL fraco (TLS < 1.2, cipher fraca, cert expirado) | HIGH |
| RULE-003 | Header de segurança ausente (HSTS, CSP, etc.) | MEDIUM |
| RULE-004 | Serviço sensível exposto (FTP:21, Telnet:23, RDP:3389, VNC:5900, MongoDB:27017) | HIGH / MEDIUM |
| RULE-005 | 3 ou mais CVEs no mesmo host | HIGH |
| RULE-006 | Porta aberta sem produto/versão identificados | INFO |

---

### `skull-flash serve`

Inicia o dashboard web com atualizações em tempo real.

```bash
skull-flash serve
skull-flash serve --host 0.0.0.0 --port 9000
skull-flash serve --reload   # modo desenvolvimento
```

> Requer: `pip install "skull-flash[web]"`

Acesse `http://127.0.0.1:8080` no navegador após iniciar.

---

### `skull-flash report`

Converte um arquivo JSON salvo anteriormente em relatório HTML ou PDF.

```bash
skull-flash report --input resultado.json --format html --output relatorio.html
skull-flash report --input resultado.json --format pdf  --output relatorio.pdf
```

---

### `skull-flash plugin`

Gerencia o sistema de plugins.

#### Listar plugins disponíveis

```bash
skull-flash plugin list
```

#### Ver detalhes de um plugin

```bash
skull-flash plugin info whois_extended
```

#### Executar um plugin

```bash
skull-flash plugin run whois_extended --target example.com
skull-flash plugin run headers_analyzer --target https://example.com
skull-flash plugin run waf_detector --target https://example.com
```

#### Instalar um plugin (arquivo local ou URL HTTPS)

```bash
skull-flash plugin install /caminho/para/meu_plugin.py
skull-flash plugin install https://example.com/plugin.py
```

> Todos os plugins passam por validação estática via AST antes de serem carregados. Chamadas a `os.system`, `os.popen`, `eval`, `exec` e `__import__` são bloqueadas automaticamente.

**Plugins builtin incluídos:**

| Plugin | Descrição |
|--------|-----------|
| `whois_extended` | WHOIS + geolocalização de IP via ip-api.com |
| `headers_analyzer` | Análise detalhada de 7 headers de segurança com score |
| `waf_detector` | Detecção passiva de WAF (Cloudflare, AWS WAF, Imperva, Akamai e outros 6) |

**Como criar um plugin personalizado:**

```python
from skullflash.plugins.base import BasePlugin, PluginMeta

class MeuPlugin(BasePlugin):
    meta = PluginMeta(
        name="meu_plugin",
        version="1.0",
        description="Descrição do meu plugin",
    )

    async def run(self, target: str, options=None) -> dict:
        # Sua lógica aqui
        return {"resultado": target}

    def get_options(self) -> dict:
        return {"timeout": "Timeout em segundos (padrão: 10)"}
```

Salve o arquivo em `~/.skullflash/plugins/meu_plugin.py`.

---

### `skull-flash export`

Exporta findings de um relatório JSON para plataformas externas.

#### Jira

```bash
# Cria issues no Jira para findings de severidade MEDIUM ou superior
skull-flash export jira \
  --report relatorio.json \
  --threshold MEDIUM

# Variáveis de ambiente necessárias:
# SKULLFLASH_JIRA_URL      = https://sua-instancia.atlassian.net
# SKULLFLASH_JIRA_TOKEN    = seu-api-token
# SKULLFLASH_JIRA_USER     = seu@email.com
# SKULLFLASH_JIRA_PROJECT  = CHAVE_PROJETO
```

#### Dradis

```bash
# Gera XML compatível com importação no Dradis CE/Pro
skull-flash export dradis \
  --report relatorio.json \
  --output findings_dradis.xml
```

#### Faraday

```bash
# Envia findings via bulk_create API do Faraday CE
skull-flash export faraday \
  --report relatorio.json \
  --workspace meu_workspace

# Variáveis de ambiente necessárias:
# SKULLFLASH_FARADAY_URL       = http://localhost:5985
# SKULLFLASH_FARADAY_TOKEN     = seu-api-token
# SKULLFLASH_FARADAY_WORKSPACE = nome-do-workspace
```

---

## Dashboard Web

O dashboard oferece uma interface gráfica para executar scans e acompanhar os resultados em tempo real.

**Inicie com:**
```bash
skull-flash serve
```

**Funcionalidades:**
- Formulário de scan com seleção de módulos (OSINT, SSL, CVEs, Headers)
- Feed ao vivo com eventos em tempo real via SSE (Server-Sent Events)
- Gauge de risco (0–100) atualizado dinamicamente
- Tabela de findings ordenada por severidade
- Resumo executivo gerado automaticamente
- Export de relatório em JSON ou HTML

---

## Docker

### Build da imagem

```bash
docker build -t skull-flash .
```

### Exemplos de uso

```bash
# Scan simples
docker run --rm skull-flash skull-flash scan --target 192.168.1.1

# Análise completa com saída de relatório
docker run --rm -v $(pwd)/reports:/reports \
  skull-flash skull-flash analyze \
    --target 192.168.1.1 \
    --cve --web \
    --output /reports/resultado.json

# Dashboard web (modo host para acesso local)
docker run --rm -p 8080:8080 skull-flash skull-flash serve --host 0.0.0.0
```

---

## Testes

```bash
# Instalar dependências de desenvolvimento
pip install -e ".[dev]"

# Executar todos os testes com cobertura
pytest

# Executar um módulo específico
pytest tests/test_correlation.py -v
pytest tests/test_plugins.py -v
pytest tests/test_web_ui.py -v

# Linting
ruff check skullflash/

# Análise de segurança do código
bandit -r skullflash/

# Auditoria de dependências
pip-audit
```

**Suíte de testes:**

| Arquivo | O que testa |
|---------|-------------|
| `test_scanner.py` | Parser XML do nmap e mock de subprocess |
| `test_osint.py` | WHOIS, DNS lookup, tolerância a falhas |
| `test_web.py` | Verificação de headers com mock de httpx |
| `test_report.py` | Serialização de dataclasses e export JSON |
| `test_correlation.py` | Todas as 6 regras, score de risco e resumo executivo |
| `test_plugins.py` | Validação AST, carregamento e descoberta de plugins |
| `test_fingerprint.py` | Detecção de tecnologias e fingerprint de OS |
| `test_web_ui.py` | Rotas FastAPI, stream SSE e endpoints de relatório |

---

## Aviso Ético e Legal

> **IMPORTANTE:** Esta ferramenta destina-se exclusivamente a uso autorizado.

- Utilize o Skull Flash somente em sistemas para os quais você possui **autorização explícita por escrito**.
- O módulo de ética (`skullflash/utils/ethics.py`) registra todas as execuções em `~/.skullflash/audit.log`.
- Alvos podem ser bloqueados ou marcados como "requer confirmação" via `blocked_targets` e `allowed_targets` na configuração.
- O uso desta ferramenta em sistemas sem autorização é **ilegal** e de **responsabilidade exclusiva do operador**.

---

## Autores

**Endriw Villa, José Vitor de Souza**

- Github: [@Trincazul](https://github.com/Trincazul)
- Github: [@j-o-s-e-PH](https://github.com/j-o-s-e-PH)
- LinkedIn: [@endriw-villa](https://linkedin.com/in/endriw-villa)

## Contribuindo

Contribuições, issues e sugestões de features são bem-vindos!
Consulte a [página de issues](https://github.com/Trincazul/skull-flash/issues).

## Licença

MIT © Endriw Villa, José Vitor de Souza
