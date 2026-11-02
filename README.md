# ArchiPlan — diseñador local de arquitecturas de soluciones

Herramienta web que **corre en el PC del arquitecto** (sin nube, sin cuentas). Sirve para armar arquitecturas pieza por pieza, y unas reglas impiden que el diseño quede sin sentido.

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
| **Lienzo** | Arrastra piezas desde la paleta (≈50 servicios AWS y actores genéricos). Haz doble clic para que la pieza quede en la zona correcta. Puedes deshacer y rehacer. |
| **Zonas** | Región → VPC → subnets pública/privada/de datos, más grupos libres. Al soltar una pieza dentro de una zona, la zona la contiene, y la zona crece sola. |
| **Reglas de conexión** | Cada pieza tiene un *rol*. Las conexiones sin sentido se bloquean y se explica por qué: usuario → BD, Internet → subnet privada, SQS → RDS, BD que inicia conexiones, WAF a algo que no sea CloudFront/ALB/API, etc. Las conexiones dudosas se permiten con un aviso. |
| **Validación en vivo** | Revisa la ubicación por zona, los puntos de entrada sin WAF, los puntos únicos de falla, Multi‑AZ, el cifrado, una subnet privada sin NAT ni VPC Endpoint, si falta observabilidad o identidad, los secretos de BD y las piezas sueltas. Muchas reglas traen un **arreglo automático ⚡**. |
| **Vistas C4** | C1 Contexto (actores, sistema y externos, calculada automáticamente) y C2 Contenedores (la que se edita). Con el filtro por **capas** resaltas borde, aplicación, datos, seguridad, etc. |
| **Guía paso a paso** | Un checklist de 12 pasos (actores → entrada → borde → identidad → cómputo → datos → red → asíncrono → secretos → observabilidad → conexiones → ADR) que indica la siguiente pieza y la agrega con un clic. |
| **Asistente** | Te hace unas 13 preguntas y genera la arquitectura inicial junto con sus ADR. |
| **Plantillas** | Web en 3 capas, API serverless, microservicios en ECS, orientada a eventos, sitio estático y pipeline de datos. |
| **Decisiones (ADR)** | Registro de decisiones con contexto, decisión y consecuencias. |
| **Exportar** | PNG, SVG, PDF (A3), documento de arquitectura en HTML (imprimible a PDF) o Markdown, Mermaid, Terraform y JSON. |

### Sobre el Terraform
Es un **esqueleto** para el provider AWS 5.x. Incluye VPC, subnets por AZ, IGW/NAT, rutas y los recursos de cada pieza. Los **security groups** salen de las flechas (origen → destino, con el puerto del protocolo) y el **IAM de mínimo privilegio** sale de lo que cada cómputo consume, además de los triggers (SQS/Kinesis/S3 → Lambda), suscripciones SNS y reglas de EventBridge. Lo que falta por completar está marcado con `TODO`. Revísalo antes de `terraform apply`.

## Estructura

```
server/            API local (guardar/abrir en disco) + servidor de producción
src/catalog/       Catálogo de servicios, categorías, capas y zonas  ← agrega servicios aquí
src/rules/         connections.ts (matriz de reglas), validate.ts (hallazgos), guide.ts (checklist)
src/templates/     Plantillas y lógica del asistente
src/export/        Mermaid, Terraform, documento, imagen/PDF
src/components/    Lienzo, paleta, panel lateral, modales
```

### Agregar un proveedor (Azure / GCP)
1. Agrega servicios en `src/catalog/catalog.ts` con `provider: 'azure'` y un `role` existente. Las reglas de conexión funcionan por rol, así que se aplican sin cambios.
2. Si el proveedor tiene sus propias zonas (VNet, Resource Group), agrégalas en `ZONES` y `ZONE_PARENT`.
3. Crea su exportador de IaC (por ejemplo `export/bicep.ts`) siguiendo el patrón de `terraform.ts`.

## Atajos
`Ctrl+Z` / `Ctrl+Y` deshacer y rehacer · `Ctrl+S` guardar · `Supr` eliminar · `Shift`+arrastrar para seleccionar varias piezas.
