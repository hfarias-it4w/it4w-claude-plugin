---
name: it4w-seguridad
description: Estándar de seguridad IT4W v1.5 (deny by default, fail-closed, test de autorización de endpoints con caso positivo y aislamiento entre tenants, SAST con reglas probadas, SCA, secretos, contenedores, DAST, perfiles gestionados por un tercero, reglas de frontend, revisión manual por sprint, checklist de PR), aplicable a cualquier proyecto de IT4W sea cual sea el stack (.NET, NestJS/Node, Java/Spring, Python/FastAPI, frontends React/Angular/Vue). Usar SIEMPRE que se agregue o cambie un endpoint, ruta web, guard, permiso, rol, cookie, CORS, upload, dependencia, variable de entorno, workflow de CI o despliegue; al revisar un PR; al incorporar un proyecto nuevo; al preparar un pase a producción; o cuando aparezca cualquier hallazgo de seguridad.
---

# Seguridad IT4W (estándar v1.5)

Fuente de verdad completa: el HTML del estándar que cada proyecto IT4W versiona en
`docs/seguridad/estandar-it4w-v*.html` (al momento de escribir esta skill, la última conocida es
v1.5, 2026-10-05). Esta skill no incluye una copia del HTML — resume el estándar para aplicarlo en
**cualquier stack**. Si algo acá contradice el HTML del proyecto, manda el HTML (puede haber
avanzado de versión desde que se escribió esta skill). El estándar es una **base común y un
mínimo**: cada proyecto la ajusta a su stack, a quién define sus perfiles y a quién administra su
infraestructura; un repo puede ser más estricto en varios puntos y eso se conserva. Lo marcado como
*verificado* se probó con las versiones indicadas; lo marcado como *propuesta* todavía no.

## Principios (§1)

- **Deny by default**: lo que no está explícitamente permitido, está prohibido. Abrir algo es un
  acto explícito, con nombre, que queda listado y revisado.
- **La seguridad se prueba, no se supone**: cada control tiene un test que falla si alguien lo rompe.
- **Defensa en capas**: diseño seguro + test de autorización + SAST + SCA + secretos + DAST + revisión manual.
- **Evidencia**: cada corrida de CI deja reportes archivados (JUnit, SARIF).
- **Fail-closed**: si una herramienta falla, no está instalada o no encuentra qué analizar, el paso
  **falla**; nunca queda en verde por no haber revisado nada.
- **El pipeline no se apaga desde un PR**: los controles viven en una plantilla común que el proyecto
  consume (`extends`), no en un YAML que cualquier cambio pueda editar (§8.3, propuesta).

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
| §3.3 Perfiles gestionados por un tercero | mapeo claim → permiso en **un solo punto**, permiso en **positivo**, falla cerrado; lista de perfiles confirmada por el dueño del IdP | ver "Perfiles gestionados por un tercero" abajo |
| §4 Test de autorización | enumera endpoints reales; matriz sin credenciales / solo lectura / **con permiso (caso positivo obligatorio)** / **dos tenants con datos sembrados (404)**; manifiestos en ambos sentidos; prueba de mutación; etapa propia del pipeline | `test/security/` o equivalente, script dedicado (`test:security`) |
| §5 SAST | Semgrep con reglas propias (base gratis recomendada), **versión fija y reglas probadas con `semgrep --test`**, bloqueante, SARIF | `security/semgrep/*.yml` + sus casos de prueba — ver `templates/semgrep/` de esta skill |
| §6 SCA, secretos, contenedores | audit nativo del stack + **Trivy** (`config`/`fs`/`image`, obligatorio si hay Dockerfile) + **OSV-Scanner** (segunda fuente de dependencias) + Gitleaks (historial incluido); bloqueantes en High/Critical; binarios con **versión fija y sha256 verificado** | job de CI dedicado |
| §7 DAST | ZAP baseline + API scan + Schemathesis/Newman contra **QA**, nunca prod; bloquea promoción | post-deploy a QA, nunca en cada PR |
| §8 Pipeline y ramas | etapas bloqueantes, **fail-closed**, reportes como artefactos, PR + 1 revisor, `security/exceptions.md` para excepciones | `.github/workflows/` o Azure Pipelines; CODEOWNERS; branch protection |
| §8.3 Buenas prácticas (propuestas) | plantilla común con `extends` + *Required template*, escaneo programado, actualización automática de dependencias, plazos por severidad, pre-commit de Gitleaks, SBOM y firma, mínimo privilegio, baseline, hallazgos centralizados | plantilla de IT4W, configuración del repo |
| §9 Front | lockfile + install reproducible, sin `.env` versionados, sin tokens en storage, sin HTML sin sanitizar, CSP/headers, sin source maps, sin CDN sin SRI | `security/semgrep/front.yml`, nginx/Caddy con CSP |
| §10 Checklist PR | ver abajo | plantilla de PR del repo |
| §11 Proyecto nuevo | README con roles, políticas y públicos; responsables con nombre; pentest coordinado | `security/README.md`, `security/responsables.md` |
| §12 Responsabilidades | dueño y suplente por rol y por actividad (DAST, pentest, revisión manual, reportes, excepciones) | `security/responsables.md` — ver `templates/responsables.md.example` |
| §13 Revisión manual por sprint | revisión humana de lo que la automatización no ve, con informe versionado | `security/revisiones/AAAA-sprint-N.md` — ver `templates/revision-seguridad.md.example` |

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

Código completo de cada patrón (incluye el guard de NestJS que falla cerrado en escritura, el caso
positivo, el aislamiento entre tenants y el test de mutación que lo prueba): §3.1, §4.3 y §4.4 del
HTML del estándar del proyecto.

**Test de autorización en NestJS (§4.4), lo que suele romperlo:** importar `DiscoveryModule` en el
módulo de test (si no, `app.get(DiscoveryService)` falla); en Jest 30 la opción es
`--testPathPatterns` (la anterior, `--testPathPattern`, da error); `import request from 'supertest'`
con `esModuleInterop`; supertest no tiene `.all()`, así que un `@All()` se prueba expandido a cada
verbo; el regex de parámetros de ruta debe cubrir `:id`, `:user_id` y `:id2`; recorrer la cadena de
prototipos para ver los métodos heredados de controllers base.

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
   token, 403 sin permiso, **con un perfil autorizado ningún endpoint responde 401/403** (el caso
   positivo distingue "bloqueado" de "roto") y **el usuario del tenant A recibe 404 sobre recursos del
   tenant B** (no 403: no se revela que existe), también al borrar o modificar aunque tenga rol de
   escritura. El test del aislamiento necesita datos sembrados (un recurso por tenant).
6. Barrido manual sin token y con un usuario de permisos mínimos sobre las rutas nuevas; pegar el
   resultado en el PR.

### Perfiles gestionados por un tercero (IdP o portal externo) (§3.3)

Cuando la aplicación **no crea ni asigna roles** (los define y asigna el cliente o un sistema
externo y llegan en el token), el estándar sigue valiendo pero cambia qué se verifica:

- **Un único punto de mapeo** claim → permiso (un servicio o una policy), no `if` repetidos en
  handlers y controllers.
- **El permiso se modela en positivo** (`PuedeEscribir` verdadero solo si el token trae un perfil
  autorizado). Un permiso en negativo (`EsSoloLectura`, "bloquear si trae el perfil X") **falla
  abierto**: si el claim falta, cambia de nombre o llega un perfil nuevo, el usuario escribe.
- **Falla cerrado** ante claim ausente, vacío o desconocido; igual para los tenants (sin claim de
  tenant, el usuario no ve ninguno).
- La lista de perfiles autorizados sale de una **definición confirmada por el dueño del IdP**;
  mientras no esté confirmada, se registra como supuesto en el README del proyecto (fecha y
  responsable) y como riesgo abierto.
- Tests: (a) del mapeo (sin claim, claim vacío, perfil desconocido → no escribe; perfil autorizado →
  escribe), (b) los de §4 usando los perfiles y claims de la definición real.
- **No se prueba quién tiene cada perfil** (eso lo gobierna el dueño del IdP): se prueba que la
  aplicación respeta los que le llegan.
- Si el control actual está en negativo, **no se cambia en silencio**: se registra como hallazgo, se
  acuerda la lista de perfiles con el dueño del IdP y recién entonces se invierte.

### Ruta o pantalla nueva (web)

- **Ocultar es UX, no seguridad**: quien quiera saltear la interfaz llama a la API directamente. La
  regla "sin permiso no se puede crear/editar/borrar" la garantiza siempre el backend (§4).
- Sin `dangerouslySetInnerHTML`/`innerHTML`/`outerHTML` (React), `[innerHTML]`/
  `bypassSecurityTrustHtml` (Angular), `v-html` (Vue) con contenido sin sanitizar — usar
  `DOMPurify.sanitize(...)`. Vaciar un contenedor con `innerHTML = ""` está permitido (un texto
  vacío no inyecta nada). Sin `eval`/`new Function`.
- Token de sesión nunca en `localStorage`/`sessionStorage` — cookie `HttpOnly` + `Secure` +
  `SameSite` emitida por el backend. Cuidado con cookies cross-site (la app dentro de un `<iframe>`
  de otro sitio): Safari y Firefox bloquean por defecto las cookies de terceros, así que
  `SameSite=None` puede no enviarse; evaluar cookies particionadas (CHIPS) o evitar el iframe
  cross-site (verificar el soporte vigente de cada navegador).
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
- Prueba de mutación (al adoptar el estándar, ante cambios en guards y **en cada revisión de
  seguridad**, no solo una vez): comentar el guard de auth global → el test de autorización debe
  fallar; idem el guard de roles/permisos o la política de una escritura; hacer que el repositorio
  ignore el tenant → fallan los tests de aislamiento; marcar un handler/controller como público sin
  el mecanismo explícito → falla por manifiesto y/o por Semgrep.

### Dependencias

- Instalación reproducible en CI/Docker (`npm ci`, `--frozen-lockfile`, `dotnet restore` con
  lockfile); el lockfile se versiona siempre.
- Audit nativo del stack sin High/Critical antes de mergear (`npm audit --audit-level=high`,
  `dotnet list package --vulnerable --include-transitive`). **Se suma, no reemplaza**, a Trivy y
  OSV-Scanner (§6.1): cada fuente de avisos tiene cobertura y tiempos de actualización distintos.
- **Falla cerrado en .NET:** el paso hace `dotnet restore` antes de `dotnet list` (sin restore, con
  SDK 8 el comando termina con error y un `! grep "High|Critical"` final **pasa en verde sin haber
  revisado nada**; el SDK 10 restaura solo, pero no hay que depender de eso), usa
  `set -euo pipefail` y no valida con `! grep` sobre una salida que pudo haber fallado. Además,
  `dotnet restore -warnaserror:NU1903,NU1904` (NuGetAudit) convierte las vulnerabilidades High/
  Critical en error del restore. *Verificado.*
- **Trivy** (gratis, Apache 2.0, sin servidor): `trivy config` sobre Dockerfile/IaC,
  `trivy fs --scanners vuln` sobre el árbol de dependencias (los secretos los cubre Gitleaks con el
  historial completo), `trivy image` sobre la imagen ya construida. **Obligatorio si el proyecto
  tiene Dockerfile** — ningún backend desplegado en contenedor queda sin esto. En .NET, `trivy fs`
  no ve las dependencias de un checkout limpio (sin lockfile): las cubren `dotnet list` y OSV-Scanner.
- **OSV-Scanner** (gratis, Google, base osv.dev): `osv-scanner scan source -r .` como segunda fuente
  de avisos de dependencias (especialmente útil en Node/npm). En .NET lee `.csproj`/
  `packages.lock.json`, pero no reemplaza `dotnet list package --vulnerable --include-transitive`
  para transitivas. Sale con código de error ante **cualquier** hallazgo (no filtra por severidad),
  por eso las excepciones van en `osv-scanner.toml`, no en un umbral.
- Fijar la **versión exacta** de cada binario de seguridad en el pipeline (Trivy, OSV-Scanner,
  Gitleaks, Semgrep) — nunca `latest`; un cambio de versión no debe alterar el resultado de un PR
  sin que nadie lo decida. **Verificar el sha256** de cada binario descargado antes de ejecutarlo
  (archivo de checksums oficial del release) y actualizarlo junto con la versión. Nunca
  `curl ... | sh` desde `master`.
- Un hallazgo que no se puede corregir ya → excepción con **motivo, responsable y fecha de
  vencimiento** que caduca sola: `.trivyignore` (`<ID> exp:<AAAA-MM-DD>`), `osv-scanner.toml`
  (`[[IgnoredVulns]]` con `ignoreUntil`), o fila en `security/exceptions.md` (que reúne todas, también
  las de `.gitleaksignore`, que no caducan solas y se revisan cada sprint). Plantillas en
  `templates/` de esta skill.
- Majors de framework solo con la suite completa verde y CI activo.

### Secretos y entornos

- Nunca secretos en el repo: `.env` reales, tokens, JWT secrets, connection strings → variables
  secretas del pipeline o un gestor de secretos. Solo `.env.example` versionado, con placeholders.
- Gitleaks (o TruffleHog) **con historial completo** (`fetchDepth: 0` en Azure DevOps, que hace
  shallow fetch por defecto: sin eso solo se escanea el último commit y no detecta un secreto ya
  borrado del código), bloqueante en CI y en pre-commit si es posible (propuesta). Si un secreto real
  estuvo alguna vez versionado, en un log o en un chat: **se rota**, no alcanza con borrarlo.
- Seeds con placeholders; contraseñas/admin inicial rotadas tras el primer uso.

### Infra y despliegue

- DB sin `0.0.0.0/0`: en dev solo loopback; en prod sin puertos publicados salvo el proxy. Rol de
  base de datos de la app sin superusuario.
- Headers de seguridad y CSP en el servidor web (nginx/Caddy/IIS/CDN). Proxy de confianza
  (`TRUST_PROXY` o equivalente) solo detrás de un proxy conocido.
- Service accounts dedicadas con mínimos permisos (tokens fine-grained, nunca el token personal de
  un dev); service connections acotadas, secretos desde un gestor y **sin secretos en los builds de
  PR** (propuesta).
- DAST (ZAP/Schemathesis) antes de promover a prod; nunca contra producción.

### Revisión manual de seguridad por sprint (§13)

La automatización no ve la lógica de negocio ni el uso real. Esta revisión la complementa:

- **Cuándo:** siempre que el sprint toque auth, roles/permisos, datos sensibles, integraciones
  nuevas, archivos subidos o CORS/cookies/sesión; en el resto, una revisión liviana (30–60 min) de
  los endpoints nuevos o modificados, antes de salir a producción; y antes de cada salida de una
  versión mayor.
- **Quién:** alguien que **no desarrolló** lo que revisa (en equipos chicos, otro dev del proyecto o,
  si todos participaron, de otro proyecto de IT4W). Queda registrado en el informe.
- **Qué probar a mano:** lógica de negocio (saltear pasos de un flujo, repetir operaciones, cambiar
  montos/estados/fechas); IDOR/BOLA con IDs reales de **otro tenant**; escalada de rol; manipulación
  de requests con Burp (Community) o ZAP; CORS, atributos de cookies y sesión; archivos subidos
  (extensión/tipo falsos, tamaño, nombres con rutas, contenido activo). Con perfiles gestionados por
  un tercero, incluye los **perfiles reales** que llegan hoy en el token.
- **Informe:** `security/revisiones/AAAA-sprint-N.md` (alcance, casos probados, hallazgos con
  severidad/responsable/fecha, excepciones solicitadas, decisión). Plantilla en
  `templates/revision-seguridad.md.example`. Ambiente de pruebas, nunca producción.
- **Criterio de bloqueo:** Critical o High frenan la salida a producción; Medium solo sale con
  excepción registrada en `security/exceptions.md` (motivo, responsable, vencimiento) aprobada por el
  líder técnico; Low se corrige en el plazo de §8.3.
- **Relación con QA:** que cada perfil vea y pueda hacer lo que corresponde (permitido y denegado),
  mensajes de error sin datos internos y validaciones comunes → **prueba funcional de QA**;
  escalada de rol, IDOR con datos reales, requests manipuladas, lógica de negocio abusada, CORS/
  cookies/sesión y archivos → **esta revisión**; la regresión de lo ya cubierto por tests
  automáticos (§4) → el pipeline, no se repite a mano.
- **Pentest externo:** frecuencia mínima una vez por año y antes de cada salida de versión mayor o
  ante un cambio sustancial de auth, perfiles o arquitectura; lo coordina el líder técnico con el
  contacto del cliente, en ambiente de pruebas, y sus hallazgos entran en el mismo circuito de
  severidades, plazos y excepciones.

### Al detectar una vulnerabilidad

Avisar de inmediato con severidad y evidencia, sin esperar a terminar la tarea en curso. Confirmar
en local; **nunca explotar contra QA o prod**. Si no se corrige en el mismo PR:
`security/exceptions.md` con hallazgo, herramienta, motivo, responsable y vencimiento. Plazos de
corrección propuestos (a acordar con el cliente): Critical 7 días, High 30, Medium 90.

## Checklist de PR (§10)

- [ ] Todo endpoint nuevo declara su política de autorización (o está en la lista blanca, justificado).
- [ ] Escrituras con permiso específico, no solo "autenticado".
- [ ] Recursos filtrados por permiso de dominio/tenant/dueño desde la sesión, con un test de dos
      tenants y datos sembrados (404 sobre recursos ajenos).
- [ ] El test de autorización pasa y cubre el endpoint nuevo, incluido el caso "rol con permiso →
      permitido".
- [ ] Sin secretos ni credenciales en el diff.
- [ ] Sin dependencias nuevas con vulnerabilidades High/Critical.
- [ ] Si el proyecto tiene Dockerfile: sin hallazgos High/Critical de Trivy (usuario no root, sin
      secretos embebidos, imagen base actualizada).
- [ ] Toda excepción nueva (`.trivyignore`, `osv-scanner.toml`, `.gitleaksignore`) lleva motivo,
      responsable y fecha de revisión, y figura en `security/exceptions.md`.
- [ ] Cambios en auth/roles/CORS/cookies revisados por otra persona.
- [ ] Si los perfiles los define un tercero: el mapeo claim → permiso está en un único punto, en
      positivo y falla cerrado (§3.3).
- [ ] Si el cambio entra en lo que toca la revisión manual (§13): hay informe en
      `security/revisiones/`.
- [ ] Front: sin HTML sin sanitizar, sin tokens en storage, sin claves en variables de entorno del
      frontend, sin `.env` versionados, lockfile al día.
- [ ] Sección "Impacto de seguridad" completa en la descripción del PR.

## Incorporar un proyecto nuevo (§11)

1. Configurar autorización por defecto (deny by default, §3.1) en el patrón del stack elegido.
2. Crear `security/public-endpoints.json` con la lista blanca mínima.
3. Adaptar el test de inventario de endpoints (§4), con el caso positivo y la prueba de dos tenants, y
   etiquetarlo/nombrarlo para correr como etapa propia del pipeline (`test:security` o equivalente).
4. Agregar el pipeline de seguridad: build → test de autorización (bloqueante) → SAST (bloqueante) →
   SCA nativa del stack + OSV-Scanner + secretos (bloqueante en High/Critical) → Trivy (`config`/
   `fs`/`image` si hay Dockerfile, bloqueante) → publicar reportes. DAST contra QA después del
   deploy, nunca en cada PR. Correr en las ramas de integración del proyecto (`main`, `QA`,
   `develop` si existe), fijar la imagen del agente (ej. `ubuntu-24.04`, no `latest`) y respetar las
   reglas de la plantilla (§8.1): fail-closed, `fetchDepth: 0` para Gitleaks, binarios con versión
   fija y sha256, Semgrep con versión fija.
5. Configurar la política de ramas con ese pipeline como check requerido (en Azure Repos Git,
   registrarlo además como *Build validation* — el bloque `pr:` del YAML no alcanza ahí).
6. Documentar en el README del proyecto: roles, políticas y endpoints públicos.
7. Coordinar con el cliente/infra el ambiente para DAST y la frecuencia del pentest (§13.7).
8. Conseguir la última versión del HTML del estándar (con el responsable de seguridad de IT4W) y
   versionarla en `docs/seguridad/` del proyecto como fuente de verdad local.
9. Sumar Trivy y OSV-Scanner al pipeline fijando la versión y el checksum de cada binario, y
   registrar las excepciones iniciales con motivo, responsable y fecha (`.trivyignore`/
   `osv-scanner.toml`/`security/exceptions.md`).
10. Consumir la plantilla común con `extends` (§8.3) y probar las reglas de Semgrep con
    `semgrep --test`.
11. Completar la tabla de responsables del proyecto (`security/responsables.md`), crear
    `security/exceptions.md` y `security/revisiones/`, y fijar los plazos de corrección.
12. Si los perfiles los define un tercero, pedir al dueño del IdP la lista de claims y aplicar §3.3.

## Comandos de verificación (genéricos — adaptar nombres al proyecto)

```bash
<runner de tests> test:security                                    # matriz de autorización (IT4W §4); NestJS+Jest 30: --testPathPatterns security
# SAST: versión fija (imagen oficial). Primero las reglas, después el escaneo (excluyendo los casos de prueba)
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.179.0 semgrep --test security/semgrep
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:1.179.0 semgrep scan --config security/semgrep --exclude security/semgrep --error --metrics=off --sarif -o semgrep.sarif .
npm audit --audit-level=high                                       # SCA (Node) — o equivalente del stack
dotnet restore -warnaserror:NU1903,NU1904                           # SCA (.NET): NuGetAudit como error
dotnet list package --vulnerable --include-transitive               # SCA (.NET), con "set -euo pipefail" en el script
gitleaks detect --source . --redact --exit-code 1                   # secretos (requiere historial completo: fetchDepth: 0)
osv-scanner scan source -r .                                        # SCA, segunda fuente (excepciones: osv-scanner.toml)
trivy config --severity HIGH,CRITICAL --exit-code 1 .                # Dockerfile / IaC
trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed .  # dependencias
trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed <imagen>  # imagen construida
zap-baseline.py -t https://qa.ejemplo/                               # DAST pasivo, post-deploy a QA
schemathesis run openapi.json --url https://qa.ejemplo               # DAST activo por contrato
```

### Binarios del pipeline: versiones y checksums verificados (2026-10-05)

Descargar de un release concreto y verificar antes de ejecutar:
`echo "<sha256>  <archivo>" | sha256sum -c -`. Al actualizar una versión, actualizar también su checksum
(salen del archivo de checksums oficial de cada release) y revisar salida y código de retorno.

| Herramienta | Versión | Archivo (linux x64) | sha256 |
|---|---|---|---|
| Gitleaks | 8.30.1 | `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| Trivy | 0.75.0 | `trivy_0.75.0_Linux-64bit.tar.gz` | `c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f` |
| OSV-Scanner | 2.6.0 | `osv-scanner_linux_amd64` | `ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108` |
| Semgrep | 1.179.0 | imagen oficial `semgrep/semgrep:1.179.0` | — |

## Herramientas recomendadas (línea base sin costo, Anexo A del HTML)

Semgrep (motor/CLI), audit nativo del stack + OSV-Scanner/OWASP Dependency-Check, Gitleaks, Trivy,
OWASP ZAP, Schemathesis o Newman. Esta combinación cubre **todas** las capas del estándar sin
licencias — es la línea base recomendada para cualquier proyecto de IT4W. Opcionales gratuitas para
la parte automática (§8.3): Renovate (actualización de dependencias; en Azure Repos, Dependabot es de
GitHub), Syft/Trivy (SBOM), cosign (firma de imágenes), pre-commit (Gitleaks en la máquina del dev),
DefectDojo (hallazgos centralizados). SaaS pagos (Snyk, SonarCloud/Qube, GitHub Advanced Security,
Burp) suman dashboard/triage centralizado pero no reemplazan el test de autorización de endpoints
(§4), que es el control que de verdad prueba que create/update/delete no se puedan ejecutar sin
permiso.

## Plantillas incluidas en esta skill

- `templates/semgrep/nest.yml` + `nest.ts` — regla "acción de escritura sin `@Roles`" para
  NestJS/TypeScript (excluye `@Public()` y `@Roles` de clase; trata `@All()` como escritura).
- `templates/semgrep/dotnet.yml` + `dotnet.cs` — regla equivalente para .NET/C# ("escritura sin
  `[Authorize]`"; detecta verbos con y sin argumentos, como `[HttpPost("ruta")]`).
- `templates/semgrep/front.yml` + `front.tsx` — reglas de frontend (XSS por
  `dangerouslySetInnerHTML`/`innerHTML`, `eval`/`new Function`, token en `localStorage`/
  `sessionStorage` por clave literal, constante, corchetes o propiedad). Cada regla viene con su
  archivo de casos buenos y malos al lado (mismo nombre): se prueban con `semgrep --test`.
- `templates/public-endpoints.json.example` — formato del manifiesto de endpoints públicos.
- `templates/trivyignore.example` — formato de `.trivyignore` (excepciones con vencimiento).
- `templates/osv-scanner.toml.example` — formato de `osv-scanner.toml` (excepciones con vencimiento).
- `templates/exceptions.md.example` — registro único de excepciones (`security/exceptions.md`).
- `templates/revision-seguridad.md.example` — informe de la revisión manual por sprint (§13.4).
- `templates/responsables.md.example` — responsables por rol y por actividad (§12).

Copiar las de Semgrep **junto con sus casos de prueba** a `security/semgrep/` (renombrando si hace
falta, manteniendo el mismo nombre entre regla y casos) y excluir ese directorio del escaneo
(`--exclude security/semgrep`), o los casos malos se marcarían como hallazgos. Las demás, a la raíz del
proyecto o a `security/` según corresponda; ajustar nombres/paths. Son punto de partida, no sustituto
del test de autorización (§4), que sigue siendo el control autoritativo.

**Límites de las reglas de autorización de Semgrep:** lee la sintaxis de cada archivo; no resuelve
herencia ni atributos/decoradores aplicados por convención o desde otro archivo (un controller que
hereda su `[Authorize]` puede marcarse de más). Son una alarma temprana: **decide el test de §4**. La
regla de tokens detecta la clave por su nombre; `localStorage.setItem(CLAVE, t)` con una constante
importada cuyo nombre no sugiere un token no se marca.

## Limitaciones (§14)

Estos controles reducen mucho el riesgo pero no lo eliminan: no detectan fallos de lógica de
negocio complejos ni autorización a nivel de fila mal implementada más allá de los casos modelados.
Se complementan con la revisión manual por sprint y el pentest externo (§13).
