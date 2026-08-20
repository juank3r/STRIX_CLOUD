# Arquitectura y dependencias

Esta página explica cómo encajan las piezas de `STRIX_CLOUD` y qué depende de qué.

Hoy el proyecto es un **CSPM determinista read-only**: lee un plan de objetivos,
comprueba la autorización, descubre conectores, ejecuta checks de seguridad (solo
APIs `describe/get/list`) y agrega los hallazgos en un `Report` que se exporta a
JSON y SARIF. Las cajas en **línea discontinua** son la evolución planificada
(Fases 1-4 del roadmap: MITRE, persistencia, agente LLM y grafo).

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

## Cómo leerlo

- **`orchestrator.py`** es el centro: recibe el `plan` (`agents.yaml`), obliga a la
  **autorización** (`authorization.py` con `scope.yaml`) y usa el **loader** para
  instanciar el conector correcto.
- Todos los conectores implementan la interfaz **`CloudGateway`** (`cloud_gateway.py`):
  `validate_permissions` / `list_resources` / `run_safe_check` / `run_security_checks`.
- Los conectores traducen el **catálogo neutral de controles** (`checks/catalog.py`)
  a llamadas concretas del SDK del proveedor y devuelven objetos **`Finding`**.
- El **`Report`** (`common/findings.py`) agrega los findings y los exporta a **JSON**
  y **SARIF 2.1.0** (consumible por GitHub code scanning).
- La **auditoría** (`common/audit.py`) escribe evidencia JSON; los **secretos**
  (`common/secrets.py`) se resuelven desde Key Vault o variables de entorno.

## Dependencias externas

- **Runtime:** `PyYAML` (parseo del plan y del scope).
- **Extras por proveedor** (`pip install -e .[aws|azure|gcp]`): `boto3`,
  `azure-mgmt-*` / `azure-identity` / `azure-keyvault-secrets`, `google-cloud-*`.
  Son opcionales: sin ellos el conector correspondiente degrada con un aviso.

Ver también: [Agentes y entornos](Agents) · [Red: API/LLM y objetivo](Network).
