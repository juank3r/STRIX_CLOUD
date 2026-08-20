# STRIX_CLOUD

STRIX_CLOUD — Fork orientado a agentes para pruebas autorizadas en entornos cloud

## Descripción

STRIX_CLOUD es un fork pensado para desarrollar agentes modulares y seguros orientados
a auditorías y pruebas autorizadas en entornos cloud. Este repo contiene plantillas de
agentes, documentación legal/ética y una arquitectura de pasarelas (connectors) para
integración con proveedores cloud (AWS, Azure, GCP).

## Características

- Plantilla mínima de agente en `agents/python_agent/`.
- Documentación legal y ética en `docs/`.
- Wiki con guías y Getting Started.
- Arquitectura de pasarelas: interfaz `CloudGateway`, loader de plugins y conectores.

## Aviso legal y ético

Estos recursos son para investigación y pruebas autorizadas únicamente. NO ejecutes
ningún agente contra sistemas sin autorización escrita. Consulta `docs/LEGAL.md`
y `docs/ETHICS.md` antes de operar.

## Quickstart

1. Clona tu fork y cambia a la rama de trabajo:

```bash
git clone https://github.com/YOUR_USERNAME/STRIX_CLOUD.git
cd STRIX_CLOUD
git checkout cloud-pentest
```

2. Instala el paquete (editable) con los extras del proveedor que uses:

```bash
pip install -e .[dev]              # solo desarrollo/tests
pip install -e .[dev,aws,azure,gcp]  # con los SDKs cloud para ejecutar checks
```

Esto expone el comando de consola `strix-cloud`.

3. Para añadir un conector cloud, mira `agents/cloud_gateway.py` y
   `agents/plugins/loader.py` para el patrón de implementación.

## Contribuir

1. Crea una rama `feature/<nombre>`.
2. Añade tests y documentación para cambios relevantes.
3. Abre un PR hacia `cloud-pentest` y referencia cualquier autorización/legal
   necesaria si introduces funcionalidades de prueba.

## Motor de hallazgos (CSPM)

Los conectores ejecutan checks de seguridad **read-only** y reportan hallazgos
neutrales por proveedor (mismos controles en AWS, Azure y GCP). Ejecutar checks
reales (`--run`) exige un fichero de **autorización** (`--scope`) que lista las
cuentas objetivo permitidas; si un objetivo no está autorizado, la ejecución
aborta antes de tocar nada. Ejemplo:

```bash
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml --security \
  --report findings.json --sarif findings.sarif --fail-on HIGH
```

Ver `docs/FINDINGS.md` para el catálogo de controles y `examples/scope.yaml`
para el formato del fichero de autorización.

## Roadmap inmediato

- [x] Diseñar e implementar `CloudGateway` (spec).
- [x] Implementar loader de plugins y conectores AWS/Azure/GCP.
- [x] Motor de hallazgos (`Finding`/`Report`) con export JSON y SARIF.
- [x] Catálogo de controles neutral + checks de storage en los 3 proveedores.
- [x] Dominio de red: ingress sin restricción (SG/NSG/firewall) en los 3.
- [x] **Fase 0**: paquete instalable (`strix-cloud`), CI sin `SKIP_TESTS`,
      audit JSON a fichero y gating de autorización (`--scope`).
- [ ] **Fase 1**: findings enriquecidos (OCSF-lite + MITRE ATT&CK), persistencia y baseline.
- [ ] **Fase 2**: ampliar controles (IAM, cómputo público, cifrado, logging) + multi-región AWS.
- [ ] **Fase 3-4**: capa de agente LLM (analista) y auto-remediación vía PR.
