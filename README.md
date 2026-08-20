# STRIX_CLOUD

> Fork orientado a **seguridad cloud (CSPM)** para pruebas autorizadas: audita configuraciones de **AWS / Azure / GCP** en **solo lectura** y reporta hallazgos neutrales por proveedor (**JSON + SARIF**).

[![LiteLLM](https://img.shields.io/badge/LiteLLM-1E9E6A?style=for-the-badge)](https://github.com/BerriAI/litellm)
[![Caido](https://img.shields.io/badge/Caido-E5533C?style=for-the-badge)](https://github.com/caido/caido)
[![Nuclei](https://img.shields.io/badge/Nuclei-6D5AE6?style=for-the-badge)](https://github.com/projectdiscovery/nuclei)
[![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge)](https://github.com/microsoft/playwright)
[![Bubble%20Tea](https://img.shields.io/badge/Bubble%20Tea-FF62B0?style=for-the-badge)](https://github.com/charmbracelet/bubbletea)

> ⚠️ **Solo para pruebas autorizadas.** Ejecutar checks reales (`--run`) exige un fichero de autorización (`--scope`). Ver [docs/LEGAL.md](docs/LEGAL.md) y [docs/ETHICS.md](docs/ETHICS.md).

---

## En qué se basa (stack)

STRIX_CLOUD es un fork de [Strix](https://github.com/usestrix/strix) (Apache-2.0). El toolkit de Strix se apoya en excelentes proyectos open source; el diagrama muestra qué capacidad cubre cada uno (Strix los integra, no copia su código):

```mermaid
flowchart LR
  subgraph OSS["Proyectos open source"]
    LL["LiteLLM"]
    CA["Caido"]
    NU["Nuclei"]
    PW["Playwright"]
    BT["Bubble Tea"]
  end

  LL -->|"gateway multi-LLM"| BRAIN["Cerebro LLM<br/>(razonamiento)"]
  CA -->|"proxy HTTP"| PROXY["Interceptacion HTTP"]
  NU -->|"plantillas de vulns"| SCAN["Escaneo de vulnerabilidades"]
  PW -->|"automatizacion navegador"| BROWSER["Pruebas client-side<br/>(XSS / CSRF)"]
  BT -->|"framework TUI"| TUI["Interfaz de terminal"]

  BRAIN & PROXY & SCAN & BROWSER & TUI --> STRIX["Strix<br/>(agente de pentesting)"]

  classDef eng fill:#eef7f8,stroke:#0e7c86,color:#0b5c64;
  class STRIX eng;
```

Detalle y licencias: [wiki/Credits.md](wiki/Credits.md).

## Arquitectura y dependencias

Del plan y la autorización al catálogo de controles, los conectores y la exportación JSON/SARIF. Las cajas discontinuas son la evolución planificada (Fases 1-4).

```mermaid
flowchart TB
  subgraph IN["Entrada (config)"]
    PLAN["agents.yaml<br/>(plan de objetivos)"]
    SCOPE["scope.yaml<br/>(autorizacion)"]
  end

  CLI["strix-cloud<br/>(orchestrator.main)"]

  subgraph CORE["Orquestacion"]
    ORCH["orchestrator.py"]
    AUTHZ["authorization.py<br/>(gate --scope)"]
    LOADER["plugins/loader.py<br/>(descubre conectores)"]
  end

  subgraph GW["Conectores (CloudGateway)"]
    ABC["cloud_gateway.py<br/>(interfaz ABC)"]
    AWS["aws_connector.py"]
    AZ["azure_connector.py"]
    GCP["gcp_connector.py"]
  end

  subgraph CHECKS["Catalogo de controles"]
    CAT["checks/catalog.py<br/>(controles neutrales)"]
    NET["checks/network.py<br/>(CIDR / puertos)"]
  end

  subgraph COMMON["Utilidades comunes"]
    FIND["common/findings.py<br/>(Finding / Report / SARIF)"]
    AUD["common/audit.py<br/>(evidencia JSON)"]
    SEC["common/secrets.py<br/>(Key Vault / env)"]
  end

  subgraph SDK["SDKs cloud (extras opcionales)"]
    BOTO["boto3"]
    AZSDK["azure-mgmt-*"]
    GSDK["google-cloud-*"]
  end

  subgraph OUT["Salidas"]
    JSON["findings.json"]
    SARIF["findings.sarif"]
    LOG["audit log<br/>(STRIX_AUDIT_LOG)"]
  end

  PLAN --> ORCH
  SCOPE --> AUTHZ
  CLI --> ORCH
  ORCH --> AUTHZ
  ORCH --> LOADER
  LOADER --> ABC
  ABC --- AWS & AZ & GCP
  AWS --> BOTO
  AZ --> AZSDK
  GCP --> GSDK
  AWS & AZ & GCP --> CAT
  CAT --> NET
  CAT --> FIND
  AWS & AZ & GCP --> FIND
  ORCH --> FIND
  FIND --> JSON & SARIF
  ORCH --> AUD
  AUTHZ --> AUD
  AUD --> LOG
  AZ --> SEC
  SEC -. opcional .-> AZSDK

  subgraph FUT["Planificado (Fases 1-4)"]
    MITRE["checks/mitre.py<br/>(ATT&CK Cloud)"]
    STORE["common/store.py<br/>(dedup / baseline)"]
    LLM["llm/analyst.py<br/>(agente)"]
    GRAPH["export/graph.py<br/>(grafo)"]
  end
  CAT -.-> MITRE
  FIND -.-> STORE
  STORE -.-> LLM
  FIND -.-> GRAPH

  classDef planned stroke-dasharray:5 5,fill:#eeeeee,color:#333333;
  class MITRE,STORE,LLM,GRAPH,FUT planned;
```

Detalle: [wiki/Architecture.md](wiki/Architecture.md).

## Agentes y entornos

El mismo binario corre en laptop o CI y habla con AWS/Azure/GCP **solo por HTTPS de lectura**, acotado por el `scope` (allowlist de cuentas) y las credenciales.

```mermaid
flowchart LR
  subgraph EXEC["Donde se ejecuta el agente (contexto de confianza)"]
    DEV["Laptop del operador"]
    CI["CI (GitHub Actions)"]
    RUN["strix-cloud<br/>orchestrator + conectores"]
    DEV --> RUN
    CI --> RUN
  end

  SCOPE["scope.yaml<br/>(allowlist de cuentas)"] --> RUN
  KV["Key Vault / env<br/>(secrets.py)"] --> RUN
  RUN --> AUDIT["Audit log<br/>(evidencia JSON)"]

  RUN -->|"HTTPS 443 - solo lectura"| AWSAPI
  RUN -->|"HTTPS 443 - solo lectura"| AZAPI
  RUN -->|"HTTPS 443 - solo lectura"| GCPAPI

  subgraph AWSENV["Cuenta AWS (autorizada)"]
    AWSAPI["AWS API<br/>(control plane)"]
    S3["S3 buckets"]
    SG["EC2 Security Groups"]
    AWSAPI --- S3 & SG
  end
  subgraph AZENV["Suscripcion Azure (autorizada)"]
    AZAPI["Azure Resource Manager"]
    STG["Storage Accounts"]
    NSG["Network Security Groups"]
    AZAPI --- STG & NSG
  end
  subgraph GCPENV["Proyecto GCP (autorizado)"]
    GCPAPI["GCP API"]
    GCS["GCS buckets"]
    FW["Firewall rules"]
    GCPAPI --- GCS & FW
  end

  classDef target fill:#eeeeff,stroke:#8888aa;
  class AWSENV,AZENV,GCPENV target;
```

Detalle: [wiki/Agents.md](wiki/Agents.md).

## Red: cómo la API/LLM interactúa con el objetivo

Frontera clave: **el LLM nunca tiene ruta de red al objetivo**. Solo el runner habla con el objetivo (lectura); el LLM ve *findings saneados*; la remediación pasa por un PR con revisión humana (nunca auto-merge).

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operador
  participant STRIX as STRIX_CLOUD (runner)
  participant Cloud as APIs cloud (OBJETIVO)
  participant San as Sanitizador / guardrails
  participant LLM as Claude API (LLM)
  participant PR as GitHub (Pull Request)
  actor Rev as Revisor humano

  Op->>STRIX: strix-cloud --run --scope scope.yaml
  Note over STRIX: valida autorizacion (allowlist de cuentas)
  STRIX->>Cloud: HTTPS 443 describe/get/list (SOLO LECTURA)
  Cloud-->>STRIX: configuracion de recursos (evidencia)
  Note over STRIX: genera Findings (JSON / SARIF)

  rect rgb(230,236,255)
    Note over STRIX,LLM: El LLM NO toca el objetivo. Solo ve findings saneados.
    STRIX->>San: findings + evidencia cruda
    San-->>STRIX: texto saneado (anti prompt-injection)
    STRIX->>LLM: HTTPS 443 findings saneados
    LLM-->>STRIX: priorizacion + explicacion (+ diff propuesto)
  end

  STRIX->>PR: abre PR con el diff (Terraform / policy)
  PR->>Rev: revision humana obligatoria
  Rev-->>Cloud: aplica el cambio SOLO tras aprobar (nunca auto-merge)
```

Detalle: [wiki/Network.md](wiki/Network.md).

---

## Motor de hallazgos (CSPM)

Los conectores ejecutan checks de seguridad **read-only** y reportan hallazgos neutrales por proveedor (mismos controles en AWS, Azure y GCP). Ejemplo:

```bash
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml --security \
  --report findings.json --sarif findings.sarif --fail-on HIGH
```

Ver [docs/FINDINGS.md](docs/FINDINGS.md) para el catálogo de controles y [examples/scope.yaml](examples/scope.yaml) para el formato del fichero de autorización.

## Instalación

```bash
git clone https://github.com/YOUR_USERNAME/STRIX_CLOUD.git
cd STRIX_CLOUD

pip install -e .[dev]                 # solo desarrollo/tests
pip install -e .[dev,aws,azure,gcp]   # con los SDKs cloud para ejecutar checks
```

Esto expone el comando de consola `strix-cloud`. Uso rápido:

```bash
strix-cloud examples/agents.yaml                                   # dry-run (sin autorización)
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml # ejecución real (con autorización)
```

## Roadmap

- [x] Interfaz `CloudGateway`, loader de plugins y conectores AWS/Azure/GCP.
- [x] Motor de hallazgos (`Finding`/`Report`) con export JSON y SARIF.
- [x] Catálogo de controles neutral + checks de storage y red en los 3 proveedores.
- [x] **Fase 0**: paquete instalable (`strix-cloud`), CI sin `SKIP_TESTS`, audit JSON a fichero y gating de autorización (`--scope`).
- [ ] **Fase 1**: findings enriquecidos (OCSF-lite + MITRE ATT&CK), persistencia y baseline.
- [ ] **Fase 2**: ampliar controles (IAM, cómputo público, cifrado, logging) + multi-región AWS.
- [ ] **Fase 3-4**: capa de agente LLM (analista) y auto-remediación vía PR.

## Aviso legal y ético

Estos recursos son para investigación y **pruebas autorizadas únicamente**. NO ejecutes ningún agente contra sistemas sin autorización escrita. Consulta [docs/LEGAL.md](docs/LEGAL.md) y [docs/ETHICS.md](docs/ETHICS.md) antes de operar.

## Créditos

Gracias a los mantenedores de [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright) y [Bubble Tea](https://github.com/charmbracelet/bubbletea), y al proyecto [Strix](https://github.com/usestrix/strix). Ver [wiki/Credits.md](wiki/Credits.md).

## Contribuir

1. Trabaja sobre `main` (rama única del proyecto).
2. Añade tests y documentación para cambios relevantes.
3. Referencia cualquier autorización/legal si introduces funcionalidades de prueba.
