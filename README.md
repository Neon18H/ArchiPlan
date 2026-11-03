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
| **Lienzo** | Arrastra piezas desde la paleta: ≈50 servicios de AWS, ≈45 de Azure y actores genéricos. Haz doble clic para que la pieza quede en la zona correcta. Puedes deshacer y rehacer. |
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
Es un **esqueleto** para el provider AWS 5.x. Incluye VPC, subnets por AZ, IGW/NAT, rutas y los recursos de cada pieza. Los **security groups** salen de las flechas (origen → destino, con el puerto del protocolo) y el **IAM de mínimo privilegio** sale de lo que cada cómputo consume, además de los triggers (SQS/Kinesis/S3 → Lambda), suscripciones SNS y reglas de EventBridge. Lo que falta por completar está marcado con `TODO`. Revísalo antes de `terraform apply`.

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
src/components/    Lienzo, paleta, panel lateral, modales
```

### Agregar otra nube (p. ej. GCP)
1. Crea `src/catalog/gcp.ts` siguiendo `azure.ts`. Cada servicio declara `equiv` (su equivalente de AWS) y usa las mismas claves de propiedades; así reglas, simulación y amenazas funcionan sin cambios.
2. Agrega la nube a `Cloud`, a las etiquetas de zona (`zoneLabel`) y a la tabla de términos (`cloudText`).
3. Crea su exportador de IaC siguiendo `export/terraform-azure.ts`.

## Atajos
`Ctrl+Z` / `Ctrl+Y` deshacer y rehacer · `Ctrl+S` guardar · `Supr` eliminar · `Shift`+arrastrar para seleccionar varias piezas.
