# it4w skills marketplace

Marketplace de plugins/skills para Claude Code del equipo IT4W.

## Estructura

```
.claude-plugin/marketplace.json   # catálogo de plugins de este marketplace
plugins/<plugin-name>/
  .claude-plugin/plugin.json      # manifiesto del plugin
  skills/<skill-name>/SKILL.md    # una o más skills dentro del plugin
```

## Agregar una skill nueva

1. Copiar `plugins/example-skill` a `plugins/<nombre>`.
2. Editar `plugins/<nombre>/.claude-plugin/plugin.json` (name, description, version).
3. Escribir `plugins/<nombre>/skills/<nombre>/SKILL.md`.
4. Agregar una entrada en `.claude-plugin/marketplace.json` → `plugins[]`.
5. Validar: `claude plugin validate .`
6. Commit + push.

## Instalar / actualizar en una máquina

```bash
# una sola vez por máquina
claude plugin marketplace add <git-url-o-ruta-local> --scope user

# instalar un plugin del marketplace
claude plugin install <plugin-name>@it4w

# actualizar después de un push/bump de versión
claude plugin update <plugin-name>@it4w

# ver estado
claude plugin list
claude plugin marketplace list
```

## Versionado

- Si `plugin.json` tiene `"version"`, los usuarios quedan fijados a esa
  versión hasta que la subas de nuevo (bump) — `claude plugin update` recién
  entonces trae cambios.
- Si se omite `version`, los usuarios siguen el último commit del repo.
