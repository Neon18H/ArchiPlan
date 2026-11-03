/**
 * C4 nivel 3 (componentes): los módulos internos de un servicio y cómo usan las
 * dependencias que el servicio tiene en el diagrama de contenedores (C2).
 */
import { getService, lid } from '../catalog/catalog';
import { byId, isService, uid } from '../lib/graph';
import type { AppEdge, AppNode, C3Component, C3Link, C3Model, ComponentKind, ConnData, ServiceNode } from '../types';

export const COMPONENT_KINDS: Record<ComponentKind, { label: string; short: string; color: string; help: string }> = {
  controller: { label: 'API / Controlador', short: 'API', color: '#2a78d6', help: 'Recibe requests (REST, GraphQL, gRPC) y las delega.' },
  consumer: { label: 'Consumidor de mensajes', short: 'CON', color: '#E7157B', help: 'Procesa mensajes o eventos entrantes.' },
  auth: { label: 'Autenticación / autorización', short: 'AUT', color: '#DD344C', help: 'Valida tokens y permisos por recurso.' },
  service: { label: 'Servicio de dominio', short: 'DOM', color: '#ED7100', help: 'Reglas y casos de uso del negocio.' },
  repository: { label: 'Repositorio', short: 'REP', color: '#C925D1', help: 'Acceso a una base de datos o motor de búsqueda.' },
  cache: { label: 'Gestor de caché', short: 'CCH', color: '#a21caf', help: 'Lecturas calientes, sesiones, invalidación.' },
  client: { label: 'Cliente / adaptador', short: 'CLI', color: '#5c677d', help: 'Llama a un sistema externo, un modelo o otro servicio.' },
  publisher: { label: 'Publicador de eventos', short: 'PUB', color: '#be185d', help: 'Publica mensajes o eventos de dominio.' },
  config: { label: 'Configuración y secretos', short: 'CFG', color: '#b91c1c', help: 'Lee secretos y configuración (con caché).' },
  telemetry: { label: 'Telemetría', short: 'OBS', color: '#B0084D', help: 'Logs estructurados, métricas y trazas.' },
  scheduler: { label: 'Tarea programada', short: 'JOB', color: '#3F8624', help: 'Procesos periódicos o diferidos.' },
  validator: { label: 'Validador', short: 'VAL', color: '#7AA116', help: 'Validación de entradas y esquemas.' },
  other: { label: 'Componente', short: 'CMP', color: '#8a8f98', help: 'Otro módulo interno.' },
};

/** ¿Tiene sentido abrir la vista de componentes para esta pieza? */
export function c3Eligible(n: AppNode | undefined): n is ServiceNode {
  if (!isService(n)) return false;
  return ['compute', 'workflow', 'api'].includes(getService(n.data.serviceId).role);
}

export interface C3Neighbor {
  node: ServiceNode;
  dir: 'in' | 'out';
  protocol: string;
  edgeId: string;
}

const PASSIVE_ROLES = ['waf', 'cert', 'registry', 'devops', 'netgw', 'kms', 'dns'];

/** Vecinos de la pieza en C2 (lo que en C3 aparece como dependencias externas). */
export function neighbors(nodeId: string, nodes: AppNode[], edges: AppEdge[]): C3Neighbor[] {
  const map = byId(nodes);
  const out: C3Neighbor[] = [];
  for (const e of edges) {
    if (e.source !== nodeId && e.target !== nodeId) continue;
    const otherId = e.source === nodeId ? e.target : e.source;
    const other = map.get(otherId);
    if (!isService(other)) continue;
    if (PASSIVE_ROLES.includes(getService(other.data.serviceId).role)) continue;
    out.push({ node: other, dir: e.source === nodeId ? 'out' : 'in', protocol: String((e.data as ConnData)?.protocol ?? ''), edgeId: e.id });
  }
  return out;
}

/** Dependencias de C2 que ningún componente usa (incoherencia entre niveles). */
export function coverage(node: ServiceNode, nodes: AppNode[], edges: AppEdge[]): { missing: C3Neighbor[]; orphans: C3Component[]; stale: C3Link[] } {
  const m = node.data.c3;
  const nb = neighbors(node.id, nodes, edges);
  if (!m || !m.components.length) return { missing: [], orphans: [], stale: [] };
  const linked = new Set(m.links.flatMap((l) => [l.source, l.target]).filter((x) => x.startsWith('ext:')).map((x) => x.slice(4)));
  const nbIds = new Set(nb.map((x) => x.node.id));
  return {
    missing: nb.filter((x) => !linked.has(x.node.id) && getService(x.node.data.serviceId).role !== 'observability'),
    orphans: m.components.filter((c) => !m.links.some((l) => l.source === c.id || l.target === c.id)),
    stale: m.links.filter((l) => [l.source, l.target].some((x) => x.startsWith('ext:') && !nbIds.has(x.slice(4)))),
  };
}

/** Propone componentes y relaciones a partir del rol de la pieza y sus dependencias. */
export function suggestComponents(node: ServiceNode, nodes: AppNode[], edges: AppEdge[]): C3Model {
  const nb = neighbors(node.id, nodes, edges);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const l = lid(node);
  const serverless = ['lambda', 'stepfunctions'].includes(l);
  const comps: C3Component[] = [];
  const links: C3Link[] = [];
  const add = (kind: ComponentKind, label: string, tech: string, description: string, col: number, row: number) => {
    const c: C3Component = { id: uid('c'), kind, label, tech, description, position: { x: col * 250, y: row * 110 } };
    comps.push(c);
    return c;
  };
  const link = (source: string, target: string, label = '') => links.push({ id: uid('l'), source, target, label });

  const inbound = nb.filter((x) => x.dir === 'in');
  const outbound = nb.filter((x) => x.dir === 'out');
  const reqIn = inbound.filter((x) => ['actor', 'external', 'lb', 'api', 'cdn', 'compute', 'workflow'].includes(role(x.node)));
  const msgIn = inbound.filter((x) => ['queue', 'stream', 'topic', 'eventbus', 'datastore', 'storage'].includes(role(x.node)));
  const idpIn = inbound.filter((x) => role(x.node) === 'identity');

  let row = 0;
  const entries: C3Component[] = [];
  if (reqIn.length || (!msgIn.length && !idpIn.length)) {
    const api = add('controller', serverless ? 'Handler HTTP' : 'API REST', serverless ? 'Handler' : 'Controlador HTTP', 'Expone los endpoints y traduce requests a casos de uso.', 0, row++);
    entries.push(api);
    reqIn.forEach((x) => link(`ext:${x.node.id}`, api.id, x.protocol));
  }
  for (const x of msgIn) {
    const c = add('consumer', `Consumidor de ${x.node.data.label}`, 'Listener', 'Procesa cada mensaje de forma idempotente; reintenta y envía a la DLQ si falla.', 0, row++);
    entries.push(c);
    link(`ext:${x.node.id}`, c.id, x.protocol || 'mensajes');
  }
  for (const x of idpIn) {
    const c = add('consumer', `Trigger de ${x.node.data.label}`, 'Trigger', 'Reacciona a eventos del proveedor de identidad (registro, login).', 0, row++);
    entries.push(c);
    link(`ext:${x.node.id}`, c.id, 'evento');
  }
  const hasHttp = entries.some((e) => e.kind === 'controller');
  const auth = hasHttp ? add('auth', 'Autorización', 'Middleware', 'Valida el token (JWT/OIDC) y que el usuario pueda acceder al recurso pedido.', 1, 0) : null;
  const domain = add('service', 'Servicio de dominio', 'Casos de uso', 'Reglas del negocio; no conoce detalles de infraestructura.', 2, Math.max(0, Math.floor((row - 1) / 2)));
  for (const e of entries) {
    if (e.kind === 'controller' && auth) {
      link(e.id, auth.id, 'valida');
      link(auth.id, domain.id, 'invoca');
    } else link(e.id, domain.id, 'invoca');
  }

  let r2 = 0;
  for (const x of outbound) {
    const r = role(x.node);
    const lbl = x.node.data.label;
    let c: C3Component | null = null;
    if (r === 'datastore' || r === 'search') c = add('repository', `Repositorio ${lbl}`, x.protocol.split(' ')[0] || 'ORM / SDK', 'Encapsula las consultas; usa parámetros (nunca concatena SQL).', 3, r2++);
    else if (r === 'cache') c = add('cache', 'Gestor de caché', x.protocol.split(' ')[0] || 'Cliente Redis', 'Cache‑aside con TTL e invalidación al escribir.', 3, r2++);
    else if (r === 'storage') c = add('client', `Almacén de archivos`, 'SDK de almacenamiento', 'Sube y lee archivos; genera URLs firmadas con expiración.', 3, r2++);
    else if (['queue', 'topic', 'eventbus', 'stream', 'workflow'].includes(r)) c = add('publisher', `Publicador → ${lbl}`, 'SDK de mensajería', 'Publica eventos de dominio (outbox para no perder mensajes).', 3, r2++);
    else if (r === 'secrets') c = add('config', 'Configuración y secretos', 'SDK de secretos', 'Lee credenciales al iniciar y las cachea; soporta rotación.', 3, r2++);
    else if (r === 'observability') c = add('telemetry', `Telemetría`, 'OpenTelemetry', 'Logs estructurados, métricas y trazas con id de correlación.', 3, r2++);
    else if (r === 'identity') c = add('auth', `Cliente de ${lbl}`, 'OIDC', 'Valida y refresca tokens con el proveedor de identidad.', 3, r2++);
    else c = add('client', `Cliente ${lbl}`, x.protocol.split(' ')[0] || 'HTTP', r === 'ai' ? 'Construye prompts separando instrucciones de datos y valida la salida del modelo.' : 'Timeouts cortos, reintentos con backoff y circuit breaker.', 3, r2++);
    link(domain.id, c.id, 'usa');
    link(c.id, `ext:${x.node.id}`, x.protocol);
  }
  return { components: comps, links };
}
