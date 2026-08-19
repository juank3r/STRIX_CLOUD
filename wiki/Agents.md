# Agents

Este repositorio contiene plantillas de agentes orientadas a pruebas autorizadas en entornos cloud.

Estructura recomendada:

- `agents/<language>_agent/` — código del agente, `README.md`, `requirements.txt` o `package.json`.
- `agents/common/` — utilidades compartidas, logging, wrappers seguros.

Plantilla mínima (Python):

- `agent.py` — entrypoint que valida permisos y registra acciones.
- `requirements.txt` — dependencias.
- `README.md` — instrucciones de uso y límites.

Recuerda: todos los agentes deben comprobar siempre que disponen de autorización antes de actuar.
