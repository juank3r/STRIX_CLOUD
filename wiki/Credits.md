# Créditos y stack open source

STRIX_CLOUD es un fork del proyecto **Strix** ([usestrix/strix](https://github.com/usestrix/strix), Apache-2.0).
Strix, a su vez, se apoya en el trabajo de proyectos open source excelentes. Esta
página reconoce ese stack y enlaza a los repos originales.

> "Strix builds on the incredible work of open-source projects like LiteLLM,
> Caido, Nuclei, Playwright, and Bubble Tea. Huge thanks to their maintainers!"

[![LiteLLM](https://img.shields.io/badge/LiteLLM-1E9E6A?style=for-the-badge)](https://github.com/BerriAI/litellm)
[![Caido](https://img.shields.io/badge/Caido-E5533C?style=for-the-badge)](https://github.com/caido/caido)
[![Nuclei](https://img.shields.io/badge/Nuclei-6D5AE6?style=for-the-badge)](https://github.com/projectdiscovery/nuclei)
[![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge)](https://github.com/microsoft/playwright)
[![Bubble%20Tea](https://img.shields.io/badge/Bubble%20Tea-FF62B0?style=for-the-badge)](https://github.com/charmbracelet/bubbletea)

## Qué aporta cada proyecto

El diagrama muestra qué capacidad de Strix cubre cada dependencia (Strix las
integra; no copia su código).

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

## Proyectos, rol y licencia

| Proyecto | Qué aporta | Licencia | Repositorio |
|----------|-----------|----------|-------------|
| **LiteLLM** | Gateway/SDK unificado: llama a 100+ LLMs (OpenAI, Anthropic, Gemini, Bedrock, Ollama…) con una sola interfaz | MIT | [BerriAI/litellm](https://github.com/BerriAI/litellm) |
| **Caido** | Toolkit de auditoría web / proxy de interceptación HTTP (alternativa ligera a Burp) | Freemium (código fuente disponible; SDK de plugins abierto en [caidooss](https://github.com/caidooss)) | [caido/caido](https://github.com/caido/caido) |
| **Nuclei** | Escáner de vulnerabilidades rápido basado en plantillas YAML (ProjectDiscovery) | MIT | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **Playwright** | Automatización de navegadores para pruebas client-side (Microsoft) | Apache-2.0 | [microsoft/playwright](https://github.com/microsoft/playwright) |
| **Bubble Tea** | Framework TUI en Go para la interfaz de terminal (Charm) | MIT | [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) |

## Cómo se relaciona con STRIX_CLOUD

STRIX_CLOUD hoy es un **CSPM determinista** (auditoría de configuración cloud) y
todavía no integra este toolkit ofensivo. El mapeo previsto es:

- **Capa LLM (Fases 3-4):** LiteLLM o la **API de Claude** directa para el agente
  analista/remediador.
- **Toolkit ofensivo (Caido / Nuclei / Playwright):** aplica al pentesting de
  *aplicaciones*; en la variante cloud es material para módulos futuros, no para
  el CSPM de configuración.
- **Bubble Tea:** referencia para una posible TUI de STRIX_CLOUD.

> Las marcas y logotipos pertenecen a sus respectivos dueños; se muestran aquí
> únicamente con fines de atribución.

Ver también: [Arquitectura](Architecture) · [Agentes y entornos](Agents) · [Red](Network).
