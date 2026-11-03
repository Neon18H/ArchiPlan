# ArchiPlan — diseñador local de arquitecturas de soluciones

Herramienta web que **corre en el PC del arquitecto** (sin nube, sin cuentas). Sirve para armar arquitecturas en **AWS** o **Azure** pieza por pieza, y unas reglas impiden que el diseño quede sin sentido.

## Requisitos
- Node.js 20 o superior

## Ejecutar

```bash
npm install
npm run dev          # modo desarrollo → http://localhost:5173 (se abre solo)
```

Para el uso diario (más liviano):

```bash
npm run serve        # compila y sirve en http://127.0.0.1:4317
```

Los proyectos se guardan como archivos `*.archi.json` en la carpeta `projects/`. Para cambiarla usa `ARCHIPLAN_PROJECTS_DIR=/ruta npm start`. El servidor solo escucha en `127.0.0.1`, así que no se expone en la red. Además se hace un autoguardado en el navegador por si lo cierras sin guardar.

## Qué incluye

| Función | Detalle |
|---|---|
| **Lienzo** | Arrastra piezas desde la paleta: ≈90 servicios de AWS (incluidos Global Accelerator, Transit Gateway, Network Firewall, Beanstalk, Batch, FSx, Neptune, MemoryDB, Amazon MQ, AppSync, IoT Core, SES, Inspector, Security Hub, servicios de IA…), ≈45 de Azure y actores genéricos. Haz doble clic para que la pieza quede en la zona correcta. Puedes deshacer y rehacer. |
| **Zonas** | Región → VPC → subnets pública/privada/de datos, más grupos libres. Al soltar una pieza dentro de una zona, la zona la contiene, y la zona crece sola. |
| **Reglas de conexión** | Cada pieza tiene un *rol*. Las conexiones sin sentido se bloquean y se explica por qué: usuario → BD, Internet → subnet privada, SQS → RDS, BD que inicia conexiones, WAF a algo que no sea CloudFront/ALB/API, etc. Las conexiones dudosas se permiten con un aviso. |
| **Validación en vivo** | Revisa la ubicación por zona, los puntos de entrada sin WAF, los puntos únicos de falla, Multi‑AZ, el cifrado, una subnet privada sin NAT ni VPC Endpoint, si falta observabilidad o identidad, los secretos de BD y las piezas sueltas. Muchas reglas traen un **arreglo automático ⚡**. |
| **Vistas C4** | C1 Contexto (actores, sistema y externos, calculada automáticamente), C2 Contenedores (la que se edita) y C3 Componentes (doble clic sobre un servicio). Con el filtro por **capas** resaltas borde, aplicación, datos, seguridad, etc. |
| **Guía paso a paso** | Un checklist de 12 pasos (actores → entrada → borde → identidad → cómputo → datos → red → asíncrono → secretos → observabilidad → conexiones → ADR) que indica la siguiente pieza y la agrega con un clic. |
| **Asistente** | Te hace unas 13 preguntas y genera la arquitectura inicial junto con sus ADR. |
| **Plantillas** | Web en 3 capas, API serverless, microservicios en ECS, orientada a eventos, sitio estático y pipeline de datos. |
| **Decisiones (ADR)** | Registro de decisiones con contexto, decisión y consecuencias. |
| **Multinube** | Catálogos de AWS y Azure con las mismas reglas, simulación y modelo de amenazas. Convierte un diagrama completo de AWS a Azure (o al revés) con un clic. |
| **Simulación** | Carga, picos, caída de instancias o AZ, falla de dependencias, DDoS L7 y L3/L4, y ataques web contra el WAF (ver abajo). |
| **Modelo de amenazas (STRIDE)** | Genera las amenazas por pieza, por flujo que cruza un límite de confianza y de la cuenta. Calcula el riesgo, detecta controles en el diagrama y aplica mitigaciones con un clic; se conecta con la simulación (ver abajo). |
| **Variantes A/B** | Clona el diseño, prueba alternativas y compáralas con las mismas simulaciones: disponibilidad, latencia, costo, amenazas y complejidad, con puntaje y ADR automático (ver abajo). |
| **Exportar** | PNG, SVG, PDF (A3), documento de arquitectura en HTML (imprimible a PDF) o Markdown, Mermaid, Terraform (AWS y/o Azure) y JSON. |

## Azure y multinube

La paleta tiene pestañas **AWS / Azure**. Cada servicio de Azure declara su **equivalente lógico** en AWS: Front Door ≈ CloudFront, Application Gateway ≈ ALB, Functions ≈ Lambda, Cosmos DB ≈ DynamoDB, Entra External ID ≈ Cognito, Key Vault ≈ Secrets Manager, etc. Gracias a eso, las reglas de conexión, la validación, la simulación y el modelo de amenazas funcionan igual en ambas nubes.

- **Textos en la nube del diagrama.** Hallazgos, amenazas, guía y simulación hablan de los servicios de Azure cuando el diagrama es de Azure.
- **Límites propios de Azure en la simulación.** API Management por nivel, Functions Flex Consumption, RU/s de Cosmos DB, 4.000 transacciones / 10 s de Key Vault, Event Grid, Event Hubs por TU, TPM de Azure OpenAI, failover de Azure SQL y PostgreSQL con o sin redundancia de zona.
- **Convertir AWS ⇄ Azure** (*Propiedades → Nube principal*). Reemplaza cada pieza por su equivalente y conserva conexiones, zonas, la configuración compatible y los protocolos personalizados. Se puede deshacer.
- **Plantillas y asistente** en ambas nubes.
- **Terraform azurerm.** Resource group, VNet y subnets (incluidas las delegadas para Container Apps y PostgreSQL), NSG derivados de las flechas, Front Door + WAF, Application Gateway, recursos por servicio y **RBAC de mínimo privilegio con identidades administradas**, también derivado de las flechas.

## Componentes (C4 nivel 3)

Doble clic sobre una pieza de cómputo, API o flujo (o el botón *Ver componentes*) abre sus **componentes internos**:

- El servicio aparece como un contenedor. A los lados están sus **dependencias reales de C2**: quién lo llama y a qué llama.
- **Generar componentes sugeridos** propone los módulos a partir de esas dependencias: API/controlador, autorización, servicio de dominio, un repositorio por base de datos, gestor de caché, publicadores, clientes de externos o LLM, configuración y telemetría. También propone sus relaciones.
- Los componentes se editan como en C2: arrastrar desde la paleta, conectar e inspeccionar (tipo, tecnología, responsabilidad).
- **Coherencia entre niveles.** Si en C2 hay una dependencia que ningún componente usa, o una relación de C3 que apunta a algo que ya no existe, se marca en la vista y en la pestaña Validación.
- Los componentes se guardan con el proyecto y salen en el documento de arquitectura.

## Simulación

El botón **▶ Simular** abre un panel debajo del lienzo y corre escenarios sobre la arquitectura que dibujaste:

| Escenario | Qué evalúa |
|---|---|
| Prueba de carga / Pico súbito | El primer cuello de botella, cuándo reacciona el autoescalado y cuánto tráfico se pierde mientras tanto. |
| Falla de una instancia | El failover: el health check del balanceador, el reemplazo por Auto Scaling, la promoción de la réplica o del standby de la BD y la caché fría. |
| Caída de una AZ | Qué pasa con las piezas sin Multi‑AZ o con una sola instancia, y si la VPC usa una sola AZ. |
| Falla de una dependencia | El radio de impacto cuando una pieza deja de responder (una API externa, Cognito, la BD…). |
| DDoS L7 (HTTP flood) | El rate limit del WAF (según las IPs de la botnet), Bot Control, la caché de la CDN, Shield Advanced, el throttling de API Gateway y el costo en Lambda ("denial of wallet"). |
| DDoS L3/L4 | Si el punto de entrada está protegido por Shield Standard o queda expuesto. |
| Ataques web | SQLi, XSS, path traversal y bots contra las reglas del WAF (Core Rule Set, reglas de SQLi, Bot Control). |

Mientras corre, el lienzo muestra el tráfico de cada flecha y la carga y el estado de cada pieza (OK, alta carga, saturado, degradado, caído). La línea de tiempo trae los eventos (escalado, failover, bloqueos) y el panel derecho lista los hallazgos con recomendaciones.

**Cómo se calcula.** Es un modelo de flujo por pasos de 5 s: el tráfico nace en los actores, se reparte por las flechas según el rol de cada pieza y cada pieza atiende hasta su capacidad (capacidad por instancia × instancias sanas). Lo que excede la capacidad falla, las colas acumulan y se vacían a la velocidad de sus consumidores, y el éxito de un request es el producto del éxito de cada salto síncrono.

Las capacidades son **estimaciones** de orden de magnitud: cuotas por defecto de AWS (API Gateway 10k req/s, concurrencia de Lambda 1.000, Cognito 120 req/s…) y cargas típicas por tamaño de instancia. Sirven para comparar diseños y encontrar puntos únicos de falla, **no reemplazan una prueba de carga real**. Cada pieza permite poner su capacidad medida en *Propiedades → Simulación*. Los supuestos están en `src/sim/profiles.ts` y el modelo en `src/sim/engine.ts`.

## Red configurable (Security Groups, puertos, listeners)

Todo lo de red se configura y queda enlazado con la validación, las simulaciones y el Terraform.

**Vista de red (botón ⛨ Red).** Pinta la red sobre el diagrama:
- Cada flecha muestra su puerto en verde (✓ 8080) o en rojo con el motivo (⛔ SG bloquea :8080).
- Cada pieza dentro de la VPC muestra el puerto en el que escucha y sus grupos de seguridad (un color por grupo).
- Haz clic en una flecha para ver la tarjeta **Tráfico de red**, con un interruptor para **permitir o bloquear** ese tráfico. ArchiPlan crea o quita la regla que hace falta.
- Haz clic en una pieza para ver **Quién puede entrar**, en frases como «App 8080 desde Application Load Balancer». Desde ahí se agregan accesos con **+ Permitir acceso** («Permitir SSH 22 desde un rango de IPs…»).

**Red automática o personalizada.** Al principio la red es *automática*: cada pieza recibe un grupo con lo mínimo que piden sus flechas. Cuando cambias algo (un interruptor, una regla, un grupo), pasa a *personalizada* sola y desde ahí mandan tus reglas. Puedes *volver a automática* cuando quieras.

**Tabla de accesos y grupos.** La leyenda de la vista de red abre:
- **Accesos**: cada conexión del diagrama con su puerto, su estado y un interruptor, más los accesos extra que no tienen flecha (por ejemplo, SSH abierto a Internet).
- **Security Groups (avanzado)**: los grupos, a qué piezas se aplican y sus reglas en formato «Permitir [puerto] desde [pieza / CloudFront / Internet / rango]».

**Otros ajustes en *Propiedades → Red*:**
- Puerto de escucha, con atajos (80, 443, 3000, 8080…).
- Listeners del balanceador (HTTPS con certificado, redirigir 80→443) y target groups con aviso si el puerto no coincide con el de la app.
- Cómo llama la CDN a su origen.
- IP pública.
- Auto Scaling: mínimo, máximo y CPU objetivo.

**Qué revisa el análisis de red, flecha por flecha:** listener en el puerto llamado, certificado TLS, bucle de redirección CDN→HTTP→HTTPS, balanceador interno llamado desde Internet, puerto del target group distinto del puerto de la app, regla de entrada del SG destino, regla de salida del SG origen, pieza sin SG, ruta de salida (NAT Gateway / VPC Endpoint), cómputo fuera de la VPC y bases de datos abiertas a Internet o SSH/RDP abiertos. Las flechas bloqueadas se pintan en rojo (⛔) en el lienzo. Cada problema aparece en *Validación* con su explicación y un arreglo ⚡ cuando lo hay.

### Petición de usuario

En **▶ Simular → Petición de usuario** se sigue una petición real, salto a salto: DNS → CDN → WAF → balanceador → aplicación → caché/BD/secretos, y las ramas asíncronas (colas, eventos). Hay cinco peticiones:

| Petición | Resultado esperado |
|---|---|
| Abrir la web, API con sesión, iniciar sesión | 200 OK |
| API sin token | 401 (si responde 200, hay un problema de autenticación) |
| Inyección SQL | 403 en el WAF (si llega a la BD, no hay protección) |

Cuando algo está mal configurado, la petición se corta donde fallaría en la nube real. El panel muestra el código que vería el usuario (por ejemplo 504 si un SG bloquea el balanceador → app, 503 si el target group apunta a otro puerto, 502 si falta el listener, 500 si la app no llega a la BD, o `ERR_TOO_MANY_REDIRECTS`). También dice **dónde te equivocaste** y trae el botón para corregirlo. La **batería de pruebas** corre las cinco peticiones a la vez. Los escenarios de carga también tienen en cuenta las conexiones bloqueadas.

## Escalado configurable

Cada pieza que escala tiene su sección **Escalado** en *Propiedades*, con una frase que resume qué va a pasar. Por ejemplo: «Empieza con 2 instancias; si la CPU pasa de 60 % agrega instancias hasta 6 (cada una tarda ~180 s en estar lista)».

| Pieza | Qué se configura |
|---|---|
| EC2 / VMSS / Elastic Beanstalk | Política: sin ASG, tamaño fijo, por CPU (target tracking), por peticiones (ALBRequestCountPerTarget) o por pasos. También mínimo, inicial, máximo, objetivo y calentamiento. |
| ECS / Container Apps | Tareas o réplicas mínimas, iniciales y máximas, y la política (CPU, peticiones o pasos). |
| EKS / AKS | Nodos y autoscaler. |
| Lambda / Functions | Concurrencia reservada y aprovisionada. |
| Aurora | Serverless v2 (ACU mínimas y máximas) o instancias fijas, y réplicas. |
| DynamoDB / Cosmos DB | On‑demand o provisionada (RCU con auto scaling), o RU/s. |
| API Gateway / APIM | Throttling (límite y ráfaga). |

La simulación usa **exactamente** esa configuración: si eliges «Tamaño fijo», no escala. Los eventos explican por qué escaló y cuánto tardó, y si llega al máximo te dice que lo subas. El Terraform genera el ASG, las políticas (target tracking, step scaling con su alarma), la concurrencia de Lambda, el rango de ACU de Aurora, el auto scaling de DynamoDB y el throttling de la API.

## Seguridad del proyecto

En *Amenazas → ⚙ Seguridad del proyecto* (o en *Propiedades* del proyecto) se configuran los guardrails y las prácticas que no son una pieza del diagrama, agrupados así:

- **Cuenta y gobierno:** SCP, permission boundary, MFA y SSO, logs inmutables, backups en otra cuenta.
- **Operación:** hallazgos al SIEM, runbook de DDoS, parcheo, restauraciones probadas.
- **Pipeline:** SAST/DAST, SCA, escaneo de secretos.
- **Aplicación:** validación de entradas, BOLA, sesiones, auditoría, firmas de webhooks, anti‑replay, resiliencia…
- **Datos:** TLS en la BD, AUTH en la caché, logs de acceso.
- **IA.**

Cada ajuste cumple los controles correspondientes en **todas** las amenazas a la vez, y los del modelo de amenazas se muestran como interruptores. Varios generan Terraform: la política de permission boundary aplicada a todos los roles, la SCP, el trail con Object Lock, la regla de EventBridge de GuardDuty a SNS, Inspector y Patch Manager, AWS Backup con vault lock, la alarma de picos y el parameter group con TLS obligatorio.

Los controles que dependen de la red ahora se calculan con la red configurada, en lugar de marcarse a mano:
- El SG de la base de datos solo acepta tráfico desde el grupo de la aplicación.
- El ALB solo acepta tráfico desde CloudFront.
- Hay redirección HTTP→HTTPS.
- El throttling de la API está configurado.
- La salida está controlada con Network Firewall.

## Asistente IA

El botón **✦ IA** abre un asistente que lee el diagrama completo cada vez que le escribes: las piezas, la red y los SG, el escalado, la validación, las amenazas abiertas, la seguridad del proyecto y tus últimas simulaciones. A partir de eso te dice qué está mal y dónde corregirlo dentro de ArchiPlan. Las piezas que menciona son enlaces al diagrama.

- **Proveedores:** OpenAI (GPT), Anthropic (Claude), DeepSeek u OpenRouter. En ⚙ eliges el proveedor, pegas tu API key y el modelo; «Ver los modelos de mi cuenta» lista los disponibles.
- **Acciones rápidas:** revisar la arquitectura, qué falta para producción, revisar la red y los SG, si aguanta un pico, riesgos de seguridad, costos y explicar la selección.
- **Revisar mientras diseño:** al dejar de editar unos segundos, comenta los cambios (opcional, consume tokens).
- **Privacidad:** la API key se guarda solo en tu equipo, en `~/.archiplan/ai.json`, con permisos 600. Nunca va en los proyectos ni en el repositorio, y las llamadas salen desde el servidor local. Por eso el asistente funciona con `npm run serve` o `npm run dev`.

## Variantes A/B

Para decidir entre dos o más caminos («¿ECS o Lambda?», «¿Aurora o DynamoDB?»), clona el diseño y compáralo con las mismas pruebas.

1. En la barra superior del lienzo pulsa **＋ Variante**. El diseño actual queda como «Variante A» y se abre una copia («Variante B») para editarla. Doble clic o ✎ para renombrar; × para eliminar.
2. Cambia lo que quieras en cada variante. Cada una guarda sus piezas, conexiones y Security Groups; la seguridad del proyecto, las amenazas aceptadas y los ADR son compartidos.
3. **⚖ Comparar** corre a cada variante: caída de una instancia, de una AZ y de la dependencia principal, carga y pico, ataques web y DDoS, las 5 peticiones de usuario, STRIDE, el análisis de red, la validación y un costo mensual estimado.

La tabla muestra disponibilidad, latencia p95, éxito en el pico, amenazas abiertas (críticas, altas, medias y bajas), ataques bloqueados, costo mensual y por millón de peticiones (con detalle por pieza), complejidad y qué cambia frente a la recomendada. En cada fila se marca la mejor y la peor.

- **Puntaje:** cada pilar va de 0 a 100 y el total es el promedio ponderado. Las prioridades vienen en perfiles (Equilibrado, Startup, Banca / regulado, Alto tráfico) o se ajustan con los controles. Cambiar las prioridades no vuelve a simular.
- **Costo:** precios de lista on-demand de us-east-1, con el tráfico promedio que indiques. Azure se estima con su equivalente en AWS. Es una referencia para comparar, no un presupuesto: valídalo con AWS Pricing Calculator.
- **ADR:** **Generar ADR** crea una decisión «propuesta» solo con la elección y su justificación: las cifras que la respaldan, lo que se acepta a cambio y los pendientes de la variante elegida. Si tienes el asistente IA configurado, **✨ Redactar con IA** lo reescribe con los mismos datos.

## Modelo de amenazas (STRIDE)

La pestaña **Amenazas** genera un modelo STRIDE a partir del diagrama, y se actualiza cada vez que lo cambias:

- **Zonas y límites de confianza.** Cada pieza queda en una zona según dónde está dibujada: Internet, Borde AWS, Servicios AWS, subnet pública, privada o de datos, o un grupo propio. Las flechas que pasan a una zona de mayor confianza se marcan en el lienzo como límites (⛨).
- **Amenazas por elemento.** STRIDE por elemento: actores, sistemas externos, puntos de entrada, APIs, cómputo, datos, mensajería, identidad y LLM (prompt injection), más amenazas de la cuenta (auditoría, detección) y de cada flujo que cruza un límite.
- **Riesgo.** Probabilidad × impacto (1‑3 cada uno). El impacto de los datos sale de su **clasificación** (Público, Interno, Confidencial o Restringido), que se define en las propiedades de cada pieza de datos.
- **Controles.** Unos se **detectan en el diagrama** (WAF y sus reglas, cifrado, Multi‑AZ, Secrets Manager, authorizer, CloudTrail, GuardDuty…) y traen arreglo ⚡ con un clic. Otros son **manuales** y se marcan al implementarlos: consultas parametrizadas, BOLA, firma de webhooks, rol de mínimo privilegio, etc.
- **Estado.** Se calcula solo (abierta, parcial o mitigada). También puedes marcar el riesgo como aceptado o "no aplica", con responsable y justificación. Todo se guarda en el proyecto.
- **Referencias.** OWASP Top 10 2021, OWASP API Security 2023, OWASP LLM Top 10 2025, CWE y MITRE ATT&CK.
- **Integración con la simulación.** Las amenazas de DoS, inyección, bots o indisponibilidad tienen un botón para correr el escenario correspondiente sobre la pieza afectada.
- **Exportación.** CSV (para Jira, Excel o GRC) y una sección completa en el documento de arquitectura.

### Sobre el Terraform
Es un **esqueleto** para el provider AWS 5.x. Incluye VPC, subnets por AZ, IGW/NAT, rutas y los recursos de cada pieza. Los **security groups** son los que configuraste en modo manual o, si no, los derivados de las flechas (incluida la prefix list administrada de CloudFront). Los **listeners** (HTTPS con `var.certificate_arn`, redirección 80→443), los **target groups** (puerto y health check, uno por destino con reglas por ruta) y el **Auto Scaling** (mín/máx y target tracking de CPU) salen de la configuración de red. En Azure se genera un NSG por subnet con la unión de las reglas de los grupos de sus piezas. El **IAM de mínimo privilegio** sale de lo que cada cómputo consume, además de los triggers (SQS/Kinesis/S3 → Lambda), suscripciones SNS y reglas de EventBridge. Lo que falta por completar está marcado con `TODO`. Revísalo antes de `terraform apply`.

## Estructura

```
server/            API local (guardar/abrir en disco) + servidor de producción
src/catalog/       Catálogos AWS (catalog.ts) y Azure (azure.ts), equivalencias, zonas  ← agrega servicios aquí
src/c3/            Vista de componentes (C4 nivel 3): sugerencias y coherencia con C2
src/rules/         connections.ts (matriz de reglas), validate.ts (hallazgos), guide.ts (checklist)
src/templates/     Plantillas y lógica del asistente
src/export/        Mermaid, Terraform AWS y Azure, documento, imagen/PDF
src/sim/           Simulación: perfiles de capacidad, escenarios y motor
src/threats/       Modelo de amenazas STRIDE: zonas de confianza, reglas y controles
src/net/           Red configurable: modelo (SG, puertos, listeners), alcanzabilidad y trazado de peticiones
src/scaling/       Escalado configurable (políticas por tipo de pieza)
src/security/      Seguridad del proyecto (guardrails y prácticas que cumplen controles)
src/ai/            Asistente IA: contexto del diagrama y cliente
src/variants/      Variantes A/B: comparación con las mismas pruebas, puntaje y ADR
src/cost/          Costo mensual estimado por pieza (precios de lista)
server/ai.mjs      Proxy local hacia OpenAI, Anthropic, DeepSeek y OpenRouter
src/components/    Lienzo, paleta, panel lateral, modales
```

### Agregar otra nube (p. ej. GCP)
1. Crea `src/catalog/gcp.ts` siguiendo `azure.ts`. Cada servicio declara `equiv` (su equivalente de AWS) y usa las mismas claves de propiedades; así reglas, simulación y amenazas funcionan sin cambios.
2. Agrega la nube a `Cloud`, a las etiquetas de zona (`zoneLabel`) y a la tabla de términos (`cloudText`).
3. Crea su exportador de IaC siguiendo `export/terraform-azure.ts`.

## Atajos
`Ctrl+Z` / `Ctrl+Y` deshacer y rehacer · `Ctrl+S` guardar · `Supr` eliminar · `Shift`+arrastrar para seleccionar varias piezas.
