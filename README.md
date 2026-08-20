# STRIX_CLOUD

> **Seguridad cloud (CSPM) para pruebas autorizadas.** Audita configuraciones de **AWS · Azure · GCP** en **solo lectura** y reporta hallazgos por severidad en **JSON + SARIF**.

[![LiteLLM](https://img.shields.io/badge/LiteLLM-1E9E6A?style=for-the-badge)](https://github.com/BerriAI/litellm)
[![Caido](https://img.shields.io/badge/Caido-E5533C?style=for-the-badge)](https://github.com/caido/caido)
[![Nuclei](https://img.shields.io/badge/Nuclei-6D5AE6?style=for-the-badge)](https://github.com/projectdiscovery/nuclei)
[![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge)](https://github.com/microsoft/playwright)
[![Bubble%20Tea](https://img.shields.io/badge/Bubble%20Tea-FF62B0?style=for-the-badge)](https://github.com/charmbracelet/bubbletea)

> **Solo para pruebas autorizadas.** Ejecutar checks reales (`--run`) exige un fichero de autorización (`--scope`). Ver [docs/LEGAL.md](docs/LEGAL.md) y [docs/ETHICS.md](docs/ETHICS.md).

---

## De un vistazo

<p align="center">
  <img src="docs/diagrams/overview.svg" alt="STRIX_CLOUD escanea tus cuentas cloud en solo lectura y reporta hallazgos por severidad en JSON y SARIF" width="100%">
</p>

Escanea tus cuentas cloud **sin tocar nada** (solo APIs de lectura), clasifica los problemas de configuración por severidad y te da un informe portable.

## Cómo funciona

<p align="center">
  <img src="docs/diagrams/pipeline.svg" alt="Del plan al report, pasando por el gate de autorización; si el objetivo no está autorizado, aborta" width="100%">
</p>

Un **gate de autorización** (`scope.yaml`, allowlist de cuentas) decide si el escaneo puede ejecutarse: si el objetivo no está autorizado, aborta antes de la primera llamada.

## En qué se basa (stack)

Fork de [Strix](https://github.com/usestrix/strix) (Apache-2.0), que se apoya en
[LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido),
[Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright)
y [Bubble Tea](https://github.com/charmbracelet/bubbletea). Qué aporta cada uno y licencias:
[wiki/Credits.md](wiki/Credits.md).

## Instalación y uso

```bash
git clone https://github.com/juank3r/STRIX_CLOUD.git
cd STRIX_CLOUD

pip install -e .[dev]                 # desarrollo/tests
pip install -e .[dev,aws,azure,gcp]   # con los SDKs cloud para ejecutar checks
```

Esto expone el comando de consola `strix-cloud`:

```bash
strix-cloud examples/agents.yaml                                   # dry-run (sin autorización)
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml --security \
  --report findings.json --sarif findings.sarif --fail-on HIGH     # ejecución real
```

Catálogo de controles: [docs/FINDINGS.md](docs/FINDINGS.md) · formato del scope: [examples/scope.yaml](examples/scope.yaml).

## Diagramas detallados

Esquemas técnicos completos en la wiki:

- [Arquitectura y dependencias](wiki/Architecture.md)
- [Agentes y entornos](wiki/Agents.md)
- [Red: cómo la API/LLM interactúa con el objetivo](wiki/Network.md)
- [Créditos y stack](wiki/Credits.md)

## Roadmap

- [x] Interfaz `CloudGateway`, loader de plugins y conectores AWS/Azure/GCP.
- [x] Motor de hallazgos (`Finding`/`Report`) con export JSON y SARIF.
- [x] Catálogo de controles neutral + checks de storage y red en los 3 proveedores.
- [x] **Fase 0**: paquete instalable (`strix-cloud`), CI verde, audit JSON a fichero y gating de autorización (`--scope`).
- [ ] **Fase 1**: findings enriquecidos (OCSF-lite + MITRE ATT&CK), persistencia y baseline.
- [ ] **Fase 2**: ampliar controles (IAM, cómputo público, cifrado, logging) + multi-región AWS.
- [ ] **Fase 3-4**: capa de agente LLM (analista) y auto-remediación vía PR.

## Aviso legal y ético

Recursos para investigación y **pruebas autorizadas únicamente**. NO ejecutes ningún agente contra sistemas sin autorización escrita. Consulta [docs/LEGAL.md](docs/LEGAL.md) y [docs/ETHICS.md](docs/ETHICS.md) antes de operar.

## Créditos

Gracias a los mantenedores de LiteLLM, Caido, Nuclei, Playwright y Bubble Tea, y al proyecto [Strix](https://github.com/usestrix/strix). Detalle en [wiki/Credits.md](wiki/Credits.md).

## Contribuir

1. Trabaja sobre `main` (rama única del proyecto).
2. Añade tests y documentación para cambios relevantes.
3. Referencia cualquier autorización/legal si introduces funcionalidades de prueba.
