# Getting Started

Requisitos:

- Python 3.11 (para ejemplos Python)
- `gh` (GitHub CLI) autenticado para subir cambios al wiki si lo deseas.

Instalación rápida:

```bash
# clona tu fork (si no está ya clonado)
git clone git@github.com:YOUR_USERNAME/STRIX_CLOUD.git
cd STRIX_CLOUD

# instala el paquete (editable) con los extras que necesites
pip install -e .[dev]                 # solo desarrollo/tests
pip install -e .[dev,aws,azure,gcp]   # con los SDKs cloud

# dry-run (lista recursos, sin autorización)
strix-cloud examples/agents.yaml

# ejecución real de checks (requiere fichero de autorización --scope)
strix-cloud examples/agents.yaml --run --scope examples/scope.yaml --security
```

> El comando `strix-cloud` lo expone el `pyproject.toml` (`[project.scripts]`).
> Ver el flujo completo en [Arquitectura](Architecture) y [Red](Network).

Si prefieres que publiquemos estas páginas en la wiki de GitHub, autorízame a usar tu sesión `gh` (no pegues tokens aquí; usa `gh auth login` si es necesario).
