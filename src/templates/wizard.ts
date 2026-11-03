import type { Decision } from '../types';
import type { Spec, SpecService } from '../lib/layout';

export interface WizardAnswers {
  name: string;
  cloud?: 'aws' | 'azure';
  kind: 'web' | 'api' | 'eventos' | 'datos' | 'estatico';
  compute: 'serverless' | 'contenedores' | 'vms' | 'kubernetes';
  data: 'relacional' | 'nosql' | 'ambos' | 'ninguno';
  auth: boolean;
  cdn: boolean;
  async: boolean;
  cache: boolean;
  external: boolean;
  files: boolean;
  ai: boolean;
  ha: boolean;
  region: string;
}

export const DEFAULT_ANSWERS: WizardAnswers = {
  name: 'Nueva solución',
  cloud: 'aws',
  kind: 'web',
  compute: 'contenedores',
  data: 'relacional',
  auth: true,
  cdn: true,
  async: false,
  cache: false,
  external: false,
  files: true,
  ai: false,
  ha: true,
  region: 'us-east-1',
};

export const COMPUTE_INFO: Record<WizardAnswers['compute'], { service: string; label: string; why: string }> = {
  serverless: { service: 'lambda', label: 'Serverless (Lambda)', why: 'Escala a cero y se paga por invocación; ideal para tráfico variable y equipos pequeños.' },
  contenedores: { service: 'ecs', label: 'Contenedores (ECS Fargate)', why: 'Servicios siempre activos sin administrar servidores, despliegues inmutables.' },
  vms: { service: 'ec2', label: 'Máquinas virtuales (EC2)', why: 'Control total del sistema operativo; útil para software heredado o licencias por host.' },
  kubernetes: { service: 'eks', label: 'Kubernetes (EKS)', why: 'Portabilidad y ecosistema K8s; tiene sentido con muchos servicios y un equipo de plataforma.' },
};

/** Traduce las respuestas del asistente en una arquitectura inicial + decisiones (ADR). */
export function generateFromAnswers(a: WizardAnswers): { spec: Spec; decisions: Omit<Decision, 'id'>[] } {
  const s: SpecService[] = [];
  const e: [string, string, string?][] = [];
  const add = (x: SpecService) => (s.push(x), x.key);
  const decisions: Omit<Decision, 'id'>[] = [];

  const serverless = a.compute === 'serverless';
  const needsVpcData = a.data === 'relacional' || a.data === 'ambos' || a.cache;
  const computeZone = serverless ? (needsVpcData ? 'private' : 'region') : 'private';
  const ci = COMPUTE_INFO[a.compute];

  // ── Casos especiales
  if (a.kind === 'estatico') {
    add({ key: 'u', serviceId: 'user', zone: 'global', label: 'Visitante' });
    add({ key: 'dns', serviceId: 'route53', zone: 'global' });
    add({ key: 'cf', serviceId: 'cloudfront', zone: 'global' });
    add({ key: 'waf', serviceId: 'waf', zone: 'global' });
    add({ key: 'acm', serviceId: 'acm', zone: 'global' });
    add({ key: 's3', serviceId: 's3', zone: 'region', label: 'Bucket del sitio' });
    add({ key: 'cw', serviceId: 'cloudwatch', zone: 'region' });
    e.push(['u', 'dns'], ['u', 'cf'], ['dns', 'cf'], ['waf', 'cf'], ['acm', 'cf'], ['cf', 's3', 'HTTPS (OAC)'], ['cf', 'cw']);
    decisions.push({ title: 'Sitio estático en S3 + CloudFront', status: 'propuesta', context: 'El contenido no requiere renderizado en servidor.', decision: 'Publicar el build en un bucket privado servido por CloudFront con OAC.', consequences: 'Costo mínimo y alta disponibilidad; la lógica dinámica debe ir en una API aparte.' });
    return { spec: { services: s, edges: e, region: a.region }, decisions };
  }

  // ── Actores
  add({ key: 'u', serviceId: 'user', zone: 'global', label: a.kind === 'api' ? 'Cliente de la API' : 'Usuario', props: { channel: a.kind === 'api' ? 'API' : 'Web' } });
  if (a.external) add({ key: 'ext', serviceId: 'external', zone: 'global', label: 'Sistema externo' });

  // ── Entrada
  const publicEntry = a.kind !== 'datos';
  if (publicEntry) {
    add({ key: 'dns', serviceId: 'route53', zone: 'global' });
    e.push(['u', 'dns']);
  }
  let front: string | null = null;
  if (a.cdn && a.kind === 'web') {
    add({ key: 'cf', serviceId: 'cloudfront', zone: 'global' });
    e.push(['dns', 'cf'], ['u', 'cf']);
    front = 'cf';
  }
  let entry: string;
  if (serverless || a.kind === 'datos' || a.kind === 'eventos') {
    entry = add({ key: 'api', serviceId: 'apigw', zone: 'region' });
  } else {
    entry = add({ key: 'alb', serviceId: 'alb', zone: 'public' });
  }
  if (front) e.push([front, entry]);
  else if (publicEntry) e.push(['dns', entry]);
  else e.push(['u', entry]);
  add({ key: 'waf', serviceId: 'waf', zone: 'global' });
  e.push(['waf', front ?? entry]);
  if (a.external) e.push(['ext', entry, 'Webhook / API']);

  // ── Identidad
  if (a.auth) {
    add({ key: 'cog', serviceId: 'cognito', zone: 'region' });
    e.push(['u', 'cog', 'login (OIDC)'], [entry, 'cog', 'valida JWT']);
  }

  // ── Cómputo
  const app = add({
    key: 'app',
    serviceId: ci.service,
    zone: computeZone,
    label: a.kind === 'eventos' ? 'Recepción de eventos' : 'Aplicación',
    props: a.compute === 'contenedores' ? { desired: a.ha ? 2 : 1 } : a.compute === 'vms' ? { count: a.ha ? 2 : 1, autoscaling: a.ha } : {},
  });
  e.push([entry, app]);
  decisions.push({ title: `Cómputo: ${ci.label}`, status: 'propuesta', context: `Solución tipo "${a.kind}" con ${a.ha ? 'requisito de alta disponibilidad' : 'requisitos de disponibilidad moderados'}.`, decision: `Ejecutar la lógica de negocio en ${ci.label}.`, consequences: ci.why });

  // ── Datos
  if (a.data === 'relacional' || a.data === 'ambos') {
    add({ key: 'db', serviceId: serverless ? 'aurora' : 'rds', zone: 'data', label: 'Base de datos', props: serverless ? { serverless: true, replicas: a.ha ? 1 : 0 } : { multiAZ: a.ha } });
    add({ key: 'sm', serviceId: 'secrets', zone: 'region' });
    e.push([app, 'db'], [app, 'sm']);
    decisions.push({ title: 'Datos transaccionales en base relacional', status: 'propuesta', context: 'Se requieren transacciones y consultas con joins.', decision: serverless ? 'Aurora Serverless v2 (PostgreSQL).' : `Amazon RDS PostgreSQL ${a.ha ? 'Multi‑AZ' : 'en una AZ'}.`, consequences: 'Credenciales en Secrets Manager con rotación; la BD vive en subnet de datos aislada.' });
  }
  if (a.data === 'nosql' || a.data === 'ambos') {
    add({ key: 'ddb', serviceId: 'dynamodb', zone: 'region' });
    e.push([app, 'ddb']);
  }
  if (a.cache) {
    add({ key: 'cache', serviceId: 'elasticache', zone: 'data', props: { replicas: a.ha ? 1 : 0 } });
    e.push([app, 'cache']);
  }
  if (a.files || a.kind === 'datos') {
    add({ key: 's3', serviceId: 's3', zone: 'region', label: a.kind === 'datos' ? 'Data lake' : 'Archivos' });
    e.push([app, 's3']);
    if (front) e.push([front, 's3']);
  }

  // ── Asíncrono / eventos
  if (a.async || a.kind === 'eventos') {
    if (a.kind === 'eventos') {
      add({ key: 'eb', serviceId: 'eventbridge', zone: 'region' });
      e.push([app, 'eb']);
    }
    add({ key: 'q', serviceId: 'sqs', zone: 'region', label: 'Cola de trabajos', props: { dlq: true } });
    add({ key: 'w', serviceId: ci.service, zone: computeZone, label: 'Worker', props: a.compute === 'contenedores' ? { desired: a.ha ? 2 : 1 } : a.compute === 'vms' ? { count: a.ha ? 2 : 1 } : {} });
    e.push([a.kind === 'eventos' ? 'eb' : app, 'q'], ['q', 'w']);
    if (s.some((x) => x.key === 'db')) e.push(['w', 'db'], ['w', 'sm']);
    if (s.some((x) => x.key === 'ddb')) e.push(['w', 'ddb']);
    add({ key: 'sns', serviceId: 'sns', zone: 'region', label: 'Notificaciones' });
    e.push(['w', 'sns'], ['sns', 'u', 'correo / push']);
    decisions.push({ title: 'Procesamiento asíncrono con colas', status: 'propuesta', context: 'Hay trabajos que no deben bloquear la respuesta al usuario.', decision: 'Publicar trabajos en SQS (con DLQ) y procesarlos con workers.', consequences: 'Absorbe picos y permite reintentos; las respuestas al usuario pasan a ser eventuales.' });
  }

  // ── Datos / analítica
  if (a.kind === 'datos') {
    add({ key: 'kds', serviceId: 'kinesis', zone: 'region' });
    add({ key: 'glue', serviceId: 'glue', zone: 'region' });
    add({ key: 'ath', serviceId: 'athena', zone: 'region' });
    add({ key: 'qs', serviceId: 'quicksight', zone: 'region' });
    add({ key: 'an', serviceId: 'admin', zone: 'global', label: 'Analista' });
    e.push([entry, 'kds'], ['kds', app], ['glue', 's3', 'ETL'], ['ath', 's3', 'consulta'], ['qs', 'ath'], ['an', 'qs']);
  }

  // ── IA y externos
  if (a.ai) {
    add({ key: 'br', serviceId: 'bedrock', zone: 'region', label: 'LLM (Bedrock)' });
    e.push([app, 'br']);
  }
  if (a.external) e.push([app, 'ext']);

  // ── Red: NAT si el cómputo privado necesita salir
  const appPrivate = computeZone === 'private';
  if (appPrivate) {
    const needsOut = a.external || a.ai || s.some((x) => x.zone === 'region' && x.key !== 'cog' && x.key !== 'api');
    if (needsOut) {
      add({ key: 'nat', serviceId: 'natgw', zone: 'public' });
      e.push([app, 'nat']);
      if (s.some((x) => x.key === 'w')) e.push(['w', 'nat']);
    }
  }

  // ── Observabilidad
  add({ key: 'cw', serviceId: 'cloudwatch', zone: 'region' });
  e.push([app, 'cw']);
  if (s.some((x) => x.key === 'w')) e.push(['w', 'cw']);

  return { spec: { services: s, edges: e, region: a.region }, decisions };
}
