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

2. Ejecuta el agente de ejemplo (Python):

```bash
python agents/python_agent/agent.py
```

3. Para añadir un conector cloud, mira `agents/cloud_gateway.py` y
   `agents/plugins/loader.py` para el patrón de implementación.

## Contribuir

1. Crea una rama `feature/<nombre>`.
2. Añade tests y documentación para cambios relevantes.
3. Abre un PR hacia `cloud-pentest` y referencia cualquier autorización/legal
   necesaria si introduces funcionalidades de prueba.

## Roadmap inmediato

- Diseñar e implementar `CloudGateway` (spec).
- Implementar loader de plugins y conector AWS esqueleto.
- Configurar CI para tests y lint.
