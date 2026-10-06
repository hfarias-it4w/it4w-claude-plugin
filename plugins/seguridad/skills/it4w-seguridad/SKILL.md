---
name: it4w-seguridad
description: Estándar de seguridad IT4W v1.2 (deny by default, test de autorización de endpoints, SAST, SCA, secretos, contenedores, DAST, reglas de frontend, checklist de PR), aplicable a cualquier proyecto de IT4W sea cual sea el stack (.NET, NestJS/Node, Java/Spring, Python/FastAPI, frontends React/Angular/Vue). Usar SIEMPRE que se agregue o cambie un endpoint, ruta web, guard, permiso, rol, cookie, CORS, upload, dependencia, variable de entorno, workflow de CI o despliegue; al revisar un PR; al incorporar un proyecto nuevo; al preparar un pase a producción; o cuando aparezca cualquier hallazgo de seguridad.
---

# Seguridad IT4W (estándar v1.2)

Fuente de verdad completa: `reference/estandar-it4w-v1.2.html` (IT4W v1.2, 2026-09-30, transversal
a todos los proyectos de IT4W). Esta skill lo resume para aplicarlo en **cualquier stack**. Si algo
acá contradice el HTML, manda el HTML — y si el proyecto tiene su propia copia en
`docs/seguridad/estandar-it4w-v1.2.html`, esa es la vigente para ese repo (puede haber avanzado de
versión). El estándar es un **mínimo**: un repo puede ser más estricto en varios puntos y eso se
conserva.

## Principios (§1)

- **Deny by default**: lo que no está explícitamente permitido, está prohibido. Abrir algo es un
  acto explícito, con nombre, que queda listado y revisado.
- **La seguridad se prueba, no se supone**: cada control tiene un test que falla si alguien lo rompe.
- **Defensa en capas**: diseño seguro + test de autorización + SAST + SCA + secretos + DAST + revisión.
- **Evidencia**: cada corrida de CI deja reportes archivados (JUnit, SARIF).

## Alcance y clasificación de endpoints (§2)

| Clase | Métodos | Requisito mínimo |
|---|---|---|
| Escritura | POST, PUT, PATCH, DELETE | Autenticado + rol/permiso de escritura + validación de pertenencia (tenant/dueño). Nunca anónimo. |
| Lectura | GET, HEAD | Autenticado + rol/permiso de lectura + filtro por tenant/dueño. |
| Público | lista blanca | Solo lo estrictamente necesario (login, health, docs públicas), con justificación escrita. |
| Operativo | dashboards de jobs, métricas, swagger, actuator | Restringido por red y/o rol de administración; nunca abierto en producción. |

Lista blanca de endpoints públicos versionada en el repo (`security/public-endpoints.json`),
modificable solo vía PR con revisión. Formato: array de `"MÉTODO /ruta"`:

```json
["GET /health", "POST /auth/login"]
```

## Las capas del estándar y qué dejar en el repo

| Capa | Exige | Dónde queda en el repo |
|---|---|---|
| §3.1 Autorización global | Guard/middleware de auth global + autorización que **falla cerrado** en escritura (y, si el proyecto quiere ser más estricto, también en lectura) | ver "Patrones por stack" abajo |
| §3.2 Reglas de código | pertenencia desde la sesión, no del body; CSRF con cookies; CORS explícito; rate limit; sin stack traces | guards/middleware + `ValidationPipe`/filtros del framework |
| §4 Test de autorización | enumera endpoints reales; matriz sin credenciales / solo lectura / con permiso; manifiestos en ambos sentidos; prueba de mutación; etapa propia del pipeline | `test/security/` o equivalente, script dedicado (`test:security`) |
| §5 SAST | Semgrep con reglas propias (base gratis recomendada), bloqueante, SARIF | `security/semgrep/*.yml` — ver `templates/semgrep/` de esta skill |
| §6 SCA, secretos, contenedores | audit nativo del stack + Gitleaks (historial incluido) + Trivy (imagen y config); bloqueantes en High/Critical | job de CI dedicado |
| §7 DAST | ZAP baseline + API scan + Schemathesis/Newman contra **QA**, nunca prod; bloquea promoción | post-deploy a QA, nunca en cada PR |
| §8 Pipeline y ramas | etapas bloqueantes, reportes como artefactos, PR + 1 revisor, `security/exceptions.md` para excepciones | `.github/workflows/` o Azure Pipelines; CODEOWNERS; branch protection |
| §9 Front | lockfile + install reproducible, sin `.env` versionados, sin tokens en storage, sin HTML sin sanitizar, CSP/headers, sin source maps, sin CDN sin SRI | `security/semgrep/front.yml`, nginx/Caddy con CSP |
| §10 Checklist PR | ver abajo | plantilla de PR del repo |
| §11 Proyecto nuevo | README con roles, políticas y públicos; pentest coordinado | `security/README.md` |

## Patrones por stack (§3.1)

**.NET (ASP.NET Core):** `FallbackPolicy` con `RequireAuthenticatedUser()` + políticas por
capacidad (`AddPolicy("Escritura", ...)`), `[Authorize(Policy = "Escritura")]` en cada acción de
escritura.

**NestJS:** guard de autenticación global vía `APP_GUARD` (`JwtAuthGuard`, rutas públicas solo con
`@Public()`) + guard de roles/permisos que **falla cerrado** en escritura (una acción
POST/PUT/PATCH/DELETE sin `@Roles(...)`/`@RequirePermissions(...)` se rechaza).

**Node/Express:** middleware global `app.use(requireAuth)` antes de montar routers; rutas públicas
montadas antes, desde una lista explícita.

**Spring:** `SecurityFilterChain` con `.anyRequest().authenticated()` como última regla.

**FastAPI:** dependencia global de autenticación.

Código completo de cada patrón (incluye el guard de NestJS que falla cerrado en escritura y el test
de mutación que lo prueba): §3.1 y §4.3/§4.4 del HTML en `reference/`.

## Qué hacer en cada situación

### Endpoint nuevo o cambiado (API)

1. Declarar autorización explícita en **cada** handler (política/rol/permiso del framework).
   Escrituras (POST/PUT/PATCH/DELETE) siempre con permiso específico; nunca "solo autenticado".
2. ¿Tiene que ser público? Solo con el mecanismo explícito del framework (`@Public()`,
   `[AllowAnonymous]`, etc.) **y** entrada en `security/public-endpoints.json` con justificación en
   la descripción del PR. Sin manifiesto, el test de autorización (§4) debe fallar.
3. Validar entrada del lado server con el validador del framework (DTO/schema propio): whitelist de
   campos, ids tipados, límites en paginación/tamaño. Prohibido guardar el body crudo
   (`repo.save(body)`) o tomar nombres de columna/orden desde el cliente sin whitelist. SQL siempre
   parametrizado.
4. Pertenencia (tenant/dueño) derivada de la sesión/claims en el servidor, nunca de un id del
   body/query.
5. Correr el test de autorización (`test:security` o el script equivalente del proyecto): 401 sin
   token, 403 sin permiso, 200/201 con permiso.
6. Barrido manual sin token y con un usuario de permisos mínimos sobre las rutas nuevas; pegar el
   resultado en el PR.

### Ruta o pantalla nueva (web)

- **Ocultar es UX, no seguridad**: quien quiera saltear la interfaz llama a la API directamente. La
  regla "sin permiso no se puede crear/editar/borrar" la garantiza siempre el backend (§4).
- Sin `dangerouslySetInnerHTML`/`innerHTML`/`outerHTML` (React), `[innerHTML]`/
  `bypassSecurityTrustHtml` (Angular), `v-html` (Vue) con contenido sin sanitizar — usar
  `DOMPurify.sanitize(...)`. Sin `eval`/`new Function`.
- Token de sesión nunca en `localStorage`/`sessionStorage` — cookie `HttpOnly` + `Secure` +
  `SameSite` emitida por el backend.
- Variables de entorno de frontend (`VITE_*`, `NEXT_PUBLIC_*`, `REACT_APP_*`, `NG_APP_*`, etc.) son
  **públicas**: solo URLs y flags, nunca claves.
- Lockfile versionado + instalación reproducible (`npm ci`/`pnpm install --frozen-lockfile`) en CI.
  Sin CDN para scripts/estilos; si es inevitable, con SRI. Sin source maps en prod.
- Excepción: frameworks con código de servidor (Next.js, Nuxt, SvelteKit, Remix — route handlers,
  API routes, server actions). Esa parte **es backend** y cumple §3/§4 como cualquier API.

### Auth, sesión, cookies, CORS, CSRF

- Cambios en los módulos de auth, guards/middleware globales, config de CORS/cookies, pipeline de
  seguridad: requieren revisión de otra persona (CODEOWNERS si el repo lo soporta).
- Después del cambio: **login real por UI** sin sesión pregrabada, navegación sin recarga. Los tests
  con sesión/estado pregrabado (`storageState` y similares) no lo cubren.
- Prueba de mutación (al adoptar el estándar y ante cambios en guards): comentar el guard de auth
  global → el test de autorización debe fallar; idem el guard de roles/permisos; marcar un
  handler/controller como público sin el mecanismo explícito → falla por manifiesto y/o por Semgrep.

### Dependencias

- Instalación reproducible en CI/Docker (`npm ci`, `--frozen-lockfile`, `dotnet restore` con
  lockfile); el lockfile se versiona siempre.
- Audit nativo del stack sin High/Critical antes de mergear (`npm audit --audit-level=high`,
  `dotnet list package --vulnerable --include-transitive`, o Snyk/OWASP Dependency-Check/OSV-Scanner
  como alternativa multi-stack). Un hallazgo que no se puede corregir ya → fila en
  `security/exceptions.md` con responsable y vencimiento.
- Majors de framework solo con la suite completa verde y CI activo.

### Secretos y entornos

- Nunca secretos en el repo: `.env` reales, tokens, JWT secrets, connection strings → variables
  secretas del pipeline o un gestor de secretos. Solo `.env.example` versionado, con placeholders.
- Gitleaks (o TruffleHog) con historial incluido, bloqueante en CI y en pre-commit si es posible. Si
  un secreto real estuvo alguna vez versionado, en un log o en un chat: **se rota**, no alcanza con
  borrarlo.
- Seeds con placeholders; contraseñas/admin inicial rotadas tras el primer uso.

### Infra y despliegue

- DB sin `0.0.0.0/0`: en dev solo loopback; en prod sin puertos publicados salvo el proxy. Rol de
  base de datos de la app sin superusuario.
- Headers de seguridad y CSP en el servidor web (nginx/Caddy/IIS/CDN). Proxy de confianza
  (`TRUST_PROXY` o equivalente) solo detrás de un proxy conocido.
- Service accounts dedicadas con mínimos permisos (tokens fine-grained, nunca el token personal de
  un dev).
- DAST (ZAP/Schemathesis) antes de promover a prod; nunca contra producción.

### Al detectar una vulnerabilidad

Avisar de inmediato con severidad y evidencia, sin esperar a terminar la tarea en curso. Confirmar
en local; **nunca explotar contra QA o prod**. Si no se corrige en el mismo PR:
`security/exceptions.md` con hallazgo, herramienta, motivo, responsable y vencimiento.

## Checklist de PR (§10)

- [ ] Todo endpoint nuevo declara su política de autorización (o está en la lista blanca, justificado).
- [ ] Escrituras con permiso específico, no solo "autenticado".
- [ ] Recursos filtrados por permiso de dominio/tenant/dueño desde la sesión.
- [ ] El test de autorización pasa y cubre el endpoint nuevo.
- [ ] Sin secretos ni credenciales en el diff.
- [ ] Sin dependencias nuevas con vulnerabilidades High/Critical.
- [ ] Cambios en auth/roles/CORS/cookies revisados por otra persona.
- [ ] Front: sin HTML sin sanitizar, sin tokens en storage, sin claves en variables de entorno del
      frontend, sin `.env` versionados, lockfile al día.
- [ ] Sección "Impacto de seguridad" completa en la descripción del PR.

## Incorporar un proyecto nuevo (§11)

1. Configurar autorización por defecto (deny by default, §3.1) en el patrón del stack elegido.
2. Crear `security/public-endpoints.json` con la lista blanca mínima.
3. Adaptar el test de inventario de endpoints (§4) y etiquetarlo/nombrarlo para correr como etapa
   propia del pipeline (`test:security` o equivalente).
4. Agregar el pipeline de seguridad: build → test de autorización (bloqueante) → SAST (bloqueante) →
   SCA + secretos (bloqueante en High/Critical) → build de imagen + Trivy (bloqueante) → publicar
   reportes. DAST contra QA después del deploy, nunca en cada PR.
5. Configurar la política de ramas con ese pipeline como check requerido.
6. Documentar en el README del proyecto: roles, políticas y endpoints públicos.
7. Coordinar con el cliente/infra el ambiente para DAST y la frecuencia del pentest.
8. Copiar `reference/estandar-it4w-v1.2.html` a `docs/seguridad/` del proyecto como fuente de verdad local.

## Comandos de verificación (genéricos — adaptar nombres al proyecto)

```bash
<runner de tests> test:security                                    # matriz de autorización (IT4W §4)
semgrep scan --config security/semgrep --error --sarif -o semgrep.sarif   # SAST
npm audit --audit-level=high                                       # SCA (Node) — o equivalente del stack
dotnet list package --vulnerable --include-transitive               # SCA (.NET)
gitleaks detect --redact --exit-code 1                              # secretos (con --source . e historial)
trivy image --severity HIGH,CRITICAL --exit-code 1 <imagen>          # contenedores
trivy config .                                                      # IaC
zap-baseline.py -t https://qa.ejemplo/                               # DAST pasivo, post-deploy a QA
schemathesis run openapi.json --url https://qa.ejemplo               # DAST activo por contrato
```

## Herramientas recomendadas (línea base sin costo, Anexo A del HTML)

Semgrep (motor/CLI), audit nativo del stack + OSV-Scanner/OWASP Dependency-Check, Gitleaks, Trivy,
OWASP ZAP, Schemathesis o Newman. Esta combinación cubre **todas** las capas del estándar sin
licencias — es la línea base recomendada para cualquier proyecto de IT4W. SaaS pagos (Snyk,
SonarCloud/Qube, GitHub Advanced Security, Burp) suman dashboard/triage centralizado pero no
reemplazan el test de autorización de endpoints (§4), que es el control que de verdad prueba que
create/update/delete no se puedan ejecutar sin permiso.

## Plantillas incluidas en esta skill

- `templates/semgrep/nest.yml` — regla "acción de escritura sin `@Roles`" para NestJS/TypeScript.
- `templates/semgrep/dotnet.yml` — regla equivalente para .NET/C# ("escritura sin `[Authorize]`").
- `templates/semgrep/front.yml` — reglas de frontend (XSS por `dangerouslySetInnerHTML`/`innerHTML`,
  `eval`/`new Function`, token en `localStorage`/`sessionStorage`).
- `templates/public-endpoints.json.example` — formato del manifiesto de endpoints públicos.

Copiarlas a `security/semgrep/` y `security/` del proyecto y ajustar nombres/paths; son punto de
partida, no sustituto del test de autorización (§4), que sigue siendo el control autoritativo.

## Limitaciones (§13)

Estos controles reducen mucho el riesgo pero no lo eliminan: no detectan fallos de lógica de
negocio complejos ni autorización a nivel de fila mal implementada más allá de los casos modelados.
Se complementan con revisión manual y un pentest periódico.
