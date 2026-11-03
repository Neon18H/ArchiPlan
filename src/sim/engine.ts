/**
 * Motor de simulación de ArchiPlan.
 *
 * Modelo de flujo por pasos de tiempo (dt = 5 s) sobre el grafo del diagrama:
 *  - El tráfico nace en los actores, entra por el punto de entrada (resolviendo DNS) y se
 *    reparte por las flechas según el rol de cada pieza (enrutar, llamar, encolar, cachear).
 *  - Cada pieza atiende hasta su capacidad (perfil × instancias sanas); el exceso falla
 *    y lo que no se atiende no sigue aguas abajo.
 *  - La tasa de éxito de un request es el producto del éxito de cada salto síncrono.
 *  - Colas: absorben picos (backlog) y se drenan a la velocidad de los consumidores.
 *  - Autoscaling, failover, caída de instancias/AZ, DDoS y ataques web se modelan como
 *    eventos que cambian la capacidad o inyectan/bloquean flujos.
 *
 * Es un modelo analítico de orden de magnitud: sirve para comparar diseños y encontrar
 * cuellos de botella y puntos únicos de falla, no para predecir números exactos.
 */
import { cloudText, getService, lid, primaryCloud } from '../catalog/catalog';
import { ancestors, byId, isService, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, Role, ServiceNode } from '../types';
import { fmtRps, profileFor, type SimProfile } from './profiles';
import { originProtocol } from '../net/model';
import type { Scenario } from './scenarios';
import { coverage, MODE_MAP, replicationLinks, suggestLinks, type FailureKind, type ReplicaLink } from '../resilience/replication';
import { criticalPath, DEFAULT_DR, dataRecovery, dnsCutover, fmtDur, holdsData, nodeRes, regionRecovery, type DnsCutover, type DrConfig, type NodeRes } from '../resilience/model';

export const DT = 5;
const UNDETECTED = 30; // s que tarda un health check en sacar una instancia caída
const LOGIN_RATIO = 0.05; // fracción de requests que son logins
const CACHE_HIT = 0.8;
const CDN_MISS_STATIC = 0.1;
const CDN_MISS_DYNAMIC = 0.8;

/** Flujos de tráfico que se simulan en paralelo. */
export const FLOWS = ['legit', 'flood', 'sqli', 'xss', 'lfi', 'bots'] as const;
export type Flow = (typeof FLOWS)[number];
const F = FLOWS.length;
const LEGIT = 0;
const FLOOD = 1;
const WEB = [2, 3, 4, 5];
export const FLOW_LABEL: Record<Flow, string> = { legit: 'Legítimo', flood: 'HTTP flood', sqli: 'Inyección SQL', xss: 'XSS', lfi: 'Path traversal', bots: 'Bots maliciosos' };

type EdgeKind = 'route' | 'sync' | 'async' | 'consume' | 'cache';
interface TEdge {
  id: string;
  s: string;
  t: string;
  kind: EdgeKind;
  w: number;
}

export type NodeStatus = 'ok' | 'hot' | 'saturated' | 'degraded' | 'down' | 'idle' | 'passive';

export interface NodeFrame {
  offered: number;
  attack: number;
  cap: number;
  util: number;
  status: NodeStatus;
  healthy: number;
  instances: number;
  backlog?: number;
  blocked?: number;
  absorbed?: number;
  /** Primaria caída cuyo tráfico atiende una réplica. */
  failoverTo?: string;
  /** Réplica promovida que atiende como primaria. */
  promoted?: boolean;
}

export interface Frame {
  t: number;
  legitOffered: number;
  legitOk: number;
  success: number;
  latency: number;
  attackSent: number;
  attackBlocked: number;
  attackAbsorbed: number;
  attackToApp: number;
  nodes: Record<string, NodeFrame>;
  edges: Record<string, { rps: number; attack: number }>;
}

export interface SimEvent {
  t: number;
  label: string;
  kind: 'bad' | 'good' | 'info';
  nodeId?: string;
}

export interface Finding {
  severity: 'error' | 'warn' | 'info' | 'ok';
  title: string;
  detail: string;
  nodeIds: string[];
}

export interface SimSummary {
  availability: number;
  minSuccess: number;
  p95Latency: number;
  baseLatency: number;
  badSeconds: number;
  recoverySeconds: number | null;
  bottleneck: { id: string; label: string; peakUtil: number } | null;
  peakBacklog: number;
  attack?: { sent: number; blocked: number; absorbed: number; toApp: number; perFlow: { flow: Flow; sent: number; blocked: number; toApp: number; toData: number }[] };
  lambdaCostUsd?: number;
  /** Escenarios de región y datos: datos perdidos (s de escrituras; Infinity = sin copia; null = no aplica). */
  dataLossS?: number | null;
  /** Tiempo que el servicio estuvo por debajo del 99 % desde el evento (s). */
  downtimeS?: number;
  /** Segundos sirviendo datos corruptos sin saberlo. */
  corruptS?: number;
  /** Resultado principal de un ataque (cuentas tomadas, GB exfiltrados, costo…). */
  impact?: { label: string; value: string; tone: 'good' | 'warn' | 'bad'; detail: string };
  /** Failovers a réplicas dibujadas en el diagrama. */
  failovers?: { primaryId: string; replicaId: string; ok: boolean; late?: boolean; at: number; rtoS: number; rpoS: number; why: string }[];
}

export interface SimResult {
  scenario: Scenario;
  targetId: string | null;
  frames: Frame[];
  events: SimEvent[];
  summary: SimSummary;
  findings: Finding[];
  warnings: string[];
}

/* ───────────────────────────── utilidades */

const sum = (a: ArrayLike<number>) => {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i];
  return s;
};
const ROUTERS: Role[] = ['cdn', 'lb', 'api', 'dns', 'inspection'];
const MESSAGING: Role[] = ['queue', 'topic', 'eventbus', 'stream', 'workflow'];

function sourceWeight(n: ServiceNode) {
  return { user: 1, admin: 0.05, external: 0.2, onprem: 0.2 }[lid(n)] ?? 0.2;
}

function classify(s: ServiceNode, t: ServiceNode, ps: SimProfile, pt: SimProfile): { kind: EdgeKind | 'entry' | 'login'; w: number } | null {
  const sd = getService(s.data.serviceId);
  const td = getService(t.data.serviceId);
  if (td.role === 'actor') return null;
  // El firewall recibe el tráfico por el túnel GENEVE del GWLB, no como una llamada
  if (td.role === 'appliance' || sd.role === 'appliance') return null;
  if (sd.role === 'inspection' && td.role === 'inspection') return null;
  // Inspección de salida: solo pasan por ella las llamadas que salen de la VPC
  if (td.role === 'inspection' && ['compute', 'workflow'].includes(sd.role)) return { kind: 'sync', w: 0.1 };
  if (sd.role === 'actor' || sd.role === 'external') {
    if (td.role === 'identity') return { kind: 'login', w: LOGIN_RATIO };
    if (pt.passive && td.role !== 'dns') return null;
    return { kind: 'entry', w: 1 };
  }
  if (ps.passive || pt.passive) return null;
  if (['waf', 'cert', 'registry', 'devops', 'observability', 'kms', 'secrets', 'analytics', 'identity'].includes(sd.role)) return null;
  if (['observability', 'kms', 'cert', 'secrets', 'devops', 'waf', 'netgw', 'registry', 'identity'].includes(td.role)) return null;
  if (ROUTERS.includes(sd.role)) return { kind: 'route', w: 1 };
  if (sd.emitsEvents && ['datastore', 'storage'].includes(sd.role)) {
    return ['compute', ...MESSAGING].includes(td.role) ? { kind: 'async', w: 0.3 } : null;
  }
  if (['datastore', 'cache', 'search', 'storage'].includes(sd.role)) return null;
  if (sd.role === 'queue') return td.role === 'compute' || td.role === 'workflow' ? { kind: 'consume', w: 1 } : null;
  if (['topic', 'eventbus', 'stream'].includes(sd.role)) return { kind: 'async', w: 1 };
  if (MESSAGING.includes(td.role)) return { kind: 'async', w: 1 };
  if (td.role === 'cache') return { kind: 'cache', w: 1 };
  if (td.role === 'storage' && sd.role !== 'workflow') return { kind: 'sync', w: 0.3 };
  return { kind: 'sync', w: 1 };
}

/** Une el éxito de una dependencia tocada por una fracción w de los requests. */
const depOk = (w: number, s: number) => (w <= 1 ? 1 - w * (1 - s) : Math.pow(s, w));

/* ───────────────────────────── estado por pieza */

interface NState {
  instances: number;
  lost: number;
  downFrom: number;
  downUntil: number;
  undetectedUntil: number;
  undetectedFrac: number;
  pending: { at: number; to: number } | null;
  replaceAt: number;
  backlog: Float64Array;
  coldFrom: number;
  coldUntil: number;
}

export function pickDefaultTarget(nodes: AppNode[], edges: AppEdge[], kind: Scenario['kind']): string | null {
  const services = nodes.filter(isService);
  const map = byId(nodes);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  if (kind === 'instance-failure') {
    const order = ['compute', 'datastore', 'cache', 'search'];
    for (const r of order) {
      const c = services.find((n) => role(n) === r && (getService(n.data.serviceId).vpcBound || profileFor(n).stateful));
      if (c) return c.id;
    }
    return null;
  }
  if (kind === 'credential-stuffing') {
    const idp = services.find((n) => role(n) === 'identity');
    if (idp) return idp.id;
  }
  if (kind === 'exfiltration') {
    const toData = services.find((n) => role(n) === 'compute' && edges.some((e) => e.source === n.id && ['datastore', 'storage'].includes(getService((map.get(e.target) as ServiceNode)?.data.serviceId ?? '').role)));
    return (toData ?? services.find((n) => role(n) === 'compute'))?.id ?? null;
  }
  if (kind === 'data-corruption' || kind === 'ransomware') {
    const data = services.filter((n) => holdsData(nodeRes(n, map).kind));
    const crit = criticalPath(nodes, edges);
    return (data.find((n) => crit.has(n.id) && role(n) === 'datastore') ?? data.find((n) => role(n) === 'datastore') ?? data[0])?.id ?? null;
  }
  if (kind === 'node-outage' || kind === 'slow-dependency' || kind === 'gameday') {
    return (services.find((n) => role(n) === 'external' && edges.some((e) => e.target === n.id)) ?? services.find((n) => role(n) === 'datastore') ?? services.find((n) => role(n) === 'compute'))?.id ?? null;
  }
  // Punto de entrada: el primer destino del usuario (resolviendo el DNS)
  const user = services.find((n) => lid(n) === 'user') ?? services.find((n) => role(n) === 'actor' || role(n) === 'external');
  if (!user) return services.find((n) => ROUTERS.includes(role(n)) && role(n) !== 'dns')?.id ?? null;
  const targets: string[] = [];
  for (const e of edges.filter((x) => x.source === user.id)) {
    const t = map.get(e.target);
    if (!isService(t)) continue;
    if (role(t) === 'dns') edges.filter((x) => x.source === t.id).forEach((x) => targets.push(x.target));
    else if (role(t) !== 'identity') targets.push(t.id);
  }
  const prio = ['cdn', 'api', 'lb'];
  for (const r of prio) {
    const hit = targets.find((id) => {
      const n = map.get(id);
      return isService(n) && role(n) === r;
    });
    if (hit) return hit;
  }
  return targets[0] ?? null;
}

export function targetCandidates(nodes: AppNode[], kind: Scenario['kind']): ServiceNode[] {
  const services = nodes.filter(isService);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  if (kind === 'instance-failure') return services.filter((n) => getService(n.data.serviceId).vpcBound && !['lb', 'netgw', 'inspection'].includes(role(n)) || profileFor(n).stateful);
  if (kind === 'node-outage' || kind === 'slow-dependency') return services.filter((n) => !['actor'].includes(role(n)) && !profileFor(n).passive);
  if (kind === 'exfiltration') return services.filter((n) => role(n) === 'compute');
  if (kind === 'credential-stuffing') return services.filter((n) => role(n) === 'identity' || (['cdn', 'lb', 'api', 'compute'].includes(role(n)) && lid(n) !== 'lambda'));
  if (kind === 'data-corruption' || kind === 'ransomware') {
    const map = byId(nodes);
    return services.filter((n) => holdsData(nodeRes(n, map).kind) || lid(n) === 'memorydb' || lid(n) === 'elasticache');
  }
  return services.filter((n) => ['cdn', 'lb', 'api', 'compute', 'external'].includes(role(n)) && lid(n) !== 'lambda');
}

/* ───────────────────────────── simulación */

export interface SimOptions {
  /** Flechas que la configuración de red bloquea (id → motivo). Las peticiones por ahí fallan. */
  blocked?: Map<string, string>;
  /** Estrategia de DR del proyecto (caída de región). */
  dr?: DrConfig;
  /** Seguridad del proyecto (backups fuera de la cuenta, timeouts por defecto…). */
  security?: Record<string, boolean>;
  /** Región principal (para los textos). */
  region?: string;
}

export function simulate(nodes: AppNode[], edges: AppEdge[], sc: Scenario, opts: SimOptions = {}): SimResult {
  const map = byId(nodes);
  const blockedPair = new Set<string>();
  const blockedInto = new Set<string>();
  for (const [eid] of opts.blocked ?? []) {
    const e = edges.find((x) => x.id === eid);
    if (!e) continue;
    blockedPair.add(`${e.source}>${e.target}`);
    const src = map.get(e.source);
    if (isService(src) && ['actor', 'dns', 'external'].includes(getService(lid(src)).role)) blockedInto.add(e.target);
  }
  const via = (s: string, t: string, v: number) => (blockedPair.has(`${s}>${t}`) ? 0 : v);
  const services = nodes.filter(isService);
  const svcIds = new Set(services.map((n) => n.id));
  const prof = new Map<string, SimProfile>(services.map((n) => [n.id, profileFor(n)]));
  const dr = opts.dr ?? DEFAULT_DR;
  const security = opts.security ?? {};
  const res = new Map<string, NodeRes>(services.map((n) => [n.id, nodeRes(n, map, security)]));
  // La configuración de redundancia manda sobre el perfil (Multi‑AZ cluster, RDS Proxy, failover automático…)
  for (const n of services) {
    const r = res.get(n.id)!;
    const p = prof.get(n.id)!;
    if (p.stateful && ['relational', 'cache', 'search', 'broker'].includes(r.kind)) {
      p.failoverTime = r.failoverS;
      p.multiAz = r.azs >= 2;
    }
  }
  const def = (id: string) => getService(lid(map.get(id) as ServiceNode));
  const label = (id: string) => (map.get(id) as ServiceNode)?.data.label ?? id;
  const warnings: string[] = [];
  const events: SimEvent[] = [];

  // ── 1. Clasificar flechas
  const tedges: TEdge[] = [];
  const entryEdges = new Map<string, string[]>();
  const loginEdges = new Map<string, string[]>();
  for (const e of edges) {
    if (!svcIds.has(e.source) || !svcIds.has(e.target)) continue;
    const s = map.get(e.source) as ServiceNode;
    const t = map.get(e.target) as ServiceNode;
    const c = classify(s, t, prof.get(s.id)!, prof.get(t.id)!);
    if (!c) continue;
    if (c.kind === 'entry') {
      if (!entryEdges.has(s.id)) entryEdges.set(s.id, []);
      entryEdges.get(s.id)!.push(t.id);
    } else if (c.kind === 'login') {
      if (!loginEdges.has(s.id)) loginEdges.set(s.id, []);
      loginEdges.get(s.id)!.push(t.id);
    } else tedges.push({ id: e.id, s: s.id, t: t.id, kind: c.kind, w: c.w });
  }
  // Resolver DNS: el tráfico de un actor hacia Route 53 sigue a los destinos del DNS.
  const sources = new Map<string, string[]>();
  for (const [src, targets] of entryEdges) {
    const set = new Set<string>();
    for (const t of targets) {
      if (def(t).role === 'dns') tedges.filter((x) => x.s === t).forEach((x) => set.add(x.t));
      else set.add(t);
    }
    if (set.size) sources.set(src, [...set]);
  }
  for (const [src] of loginEdges) if (!sources.has(src)) sources.set(src, []);
  if (!sources.size) warnings.push('No hay actores conectados a un punto de entrada: agrega un Usuario y conéctalo (directo o vía Route 53).');
  const totalW = [...sources.keys()].reduce((a, id) => a + sourceWeight(map.get(id) as ServiceNode), 0) || 1;
  const srcShare = new Map([...sources.keys()].map((id) => [id, sourceWeight(map.get(id) as ServiceNode) / totalW]));

  const outE = new Map<string, TEdge[]>();
  const inE = new Map<string, TEdge[]>();
  for (const e of tedges) {
    if (!outE.has(e.s)) outE.set(e.s, []);
    outE.get(e.s)!.push(e);
    if (!inE.has(e.t)) inE.set(e.t, []);
    inE.get(e.t)!.push(e);
  }

  // ── 2. Orden topológico (los ciclos se rompen ignorando las flechas de regreso)
  const indeg = new Map(services.map((n) => [n.id, (inE.get(n.id) ?? []).length]));
  const queue = services.filter((n) => indeg.get(n.id) === 0).map((n) => n.id);
  const order: string[] = [];
  const seen = new Set<string>();
  while (order.length < services.length) {
    if (!queue.length) {
      const rest = services.find((n) => !seen.has(n.id));
      if (!rest) break;
      queue.push(rest.id);
    }
    const id = queue.shift()!;
    if (seen.has(id)) continue;
    seen.add(id);
    order.push(id);
    for (const e of outE.get(id) ?? []) {
      indeg.set(e.t, (indeg.get(e.t) ?? 1) - 1);
      if (indeg.get(e.t)! <= 0 && !seen.has(e.t)) queue.push(e.t);
    }
  }
  // Réplicas dibujadas: van al final del orden (son destinos, nadie depende de ellas aguas abajo)
  const links: ReplicaLink[] = replicationLinks(nodes).filter((l) => svcIds.has(l.primaryId) && svcIds.has(l.replicaId));
  const replicaIds = new Set(links.map((l) => l.replicaId));
  if (replicaIds.size) {
    const rest = order.filter((id) => !replicaIds.has(id));
    order.length = 0;
    order.push(...rest, ...[...replicaIds]);
  }
  // Flotas de firewalls detrás de cada punto de inspección (GWLBE → GWLB → firewalls)
  const fleetOf = new Map<string, string[]>();
  const ipsOf = new Map<string, { block: number[]; sees: boolean; mode: 'ips' | 'ids' | 'off'; applianceId: string }>();
  const applianceIds = services.filter((n) => def(n.id).role === 'appliance').map((n) => n.id);
  for (const n of services) {
    if (def(n.id).role !== 'inspection') continue;
    const fleet = new Set<string>();
    const seenI = new Set([n.id]);
    const stack = [n.id];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const e of edges.filter((x) => x.source === cur)) {
        const r = svcIds.has(e.target) ? def(e.target).role : null;
        if (r === 'appliance') fleet.add(e.target);
        else if (r === 'inspection' && !seenI.has(e.target)) {
          seenI.add(e.target);
          stack.push(e.target);
        }
      }
    }
    fleetOf.set(n.id, [...fleet]);
    const first = [...fleet].map((id) => map.get(id) as ServiceNode)[0];
    // Solo inspecciona donde pasa tráfico (el GWLB detrás de un endpoint recibe el túnel, no las peticiones)
    const inPath = edges.some((e) => e.target === n.id && svcIds.has(e.source) && !['inspection', 'appliance'].includes(def(e.source).role));
    if (!first || !inPath) continue;
    // ¿Ve el contenido? Solo si alguien antes terminó el TLS (balanceador, API) o si el firewall descifra
    const upstream = new Set<string>();
    const back = [n.id];
    while (back.length) {
      const cur = back.pop()!;
      for (const e of edges.filter((x) => x.target === cur)) {
        if (!svcIds.has(e.source) || upstream.has(e.source)) continue;
        upstream.add(e.source);
        if (def(e.source).role === 'inspection') back.push(e.source);
      }
    }
    const cleartext = [...upstream].some((id) => {
      const u = map.get(id) as ServiceNode;
      const r = def(id).role;
      return r === 'lb' || r === 'api' || (r === 'cdn' && originProtocol(u) === 'http-only');
    });
    const fp = first.data.props;
    const mode = String(fp.mode ?? 'IPS').startsWith('IDS') ? 'ids' : fp.threatPrevention === false ? 'off' : 'ips';
    const sees = cleartext || !!fp.tlsDecryption;
    const block = new Array(F).fill(0);
    if (mode === 'ips' && sees) {
      block[2] = 0.7;
      block[3] = 0.5;
      block[4] = 0.7;
    }
    ipsOf.set(n.id, { block, sees, mode, applianceId: first.id });
  }
  if (applianceIds.length) {
    const rest = order.filter((id) => !applianceIds.includes(id));
    order.length = 0;
    order.push(...rest, ...applianceIds);
  }
  const pos = new Map(order.map((id, i) => [id, i]));
  const isBack = (e: TEdge) => (pos.get(e.t) ?? 0) <= (pos.get(e.s) ?? 0);

  // ── 3. Estado inicial
  const st = new Map<string, NState>();
  for (const n of services) {
    const p = prof.get(n.id)!;
    st.set(n.id, { instances: p.instances, lost: 0, downFrom: -1, downUntil: -1, undetectedUntil: -1, undetectedFrac: 0, pending: null, replaceAt: Infinity, backlog: new Float64Array(F), coldFrom: -1, coldUntil: -1 });
  }
  const isDown = (id: string, t: number) => {
    const s = st.get(id)!;
    return t >= s.downFrom && s.downFrom >= 0 && t < s.downUntil;
  };
  /** Multiplicadores de capacidad: región secundaria reducida (warm standby), activo‑activo, hilos ocupados por una dependencia lenta. */
  const capMods = new Map<string, (t: number) => number>();
  const slowCap = new Map<string, number>();
  const capacity = (id: string, t: number): number => {
    const p = prof.get(id)!;
    if (p.passive) return Infinity;
    if (isDown(id, t)) return 0;
    const fl = fleetOf.get(id);
    if (fl?.length) return fl.reduce((a, x) => a + capacity(x, t), 0);
    const s = st.get(id)!;
    const healthy = Math.max(0, s.instances - s.lost);
    const f = (capMods.get(id)?.(t) ?? 1) * (slowCap.get(id) ?? 1);
    if (p.scale === 'instant') return healthy > 0 ? p.perInstance * f : 0;
    return p.perInstance * healthy * f;
  };
  const cacheHit = (id: string, t: number) => {
    if (isDown(id, t)) return 0;
    const s = st.get(id)!;
    if (t >= s.coldFrom && t < s.coldUntil && s.coldFrom >= 0) return CACHE_HIT * ((t - s.coldFrom) / (s.coldUntil - s.coldFrom));
    return CACHE_HIT;
  };

  // ── 4. Objetivo y eventos del escenario
  const autoTarget = ['load', 'spike', 'az-failure', 'region-failure', 'gameday', 'leaked-keys'].includes(sc.kind) ? null : pickDefaultTarget(nodes, edges, sc.kind);
  const targetId = sc.targetId && svcIds.has(sc.targetId) ? sc.targetId : autoTarget;
  const t0 = sc.eventAt;
  const t1 = sc.eventAt + sc.eventDuration;
  const down = (id: string, from: number, until: number, why: string, back?: string) => {
    const s = st.get(id)!;
    s.downFrom = from;
    s.downUntil = until;
    events.push({ t: from, label: `${label(id)}: ${why}`, kind: 'bad', nodeId: id });
    if (Number.isFinite(until) && until < sc.duration && back) events.push({ t: until, label: `${label(id)}: ${back}`, kind: 'good', nodeId: id });
  };
  // Failover hacia réplicas dibujadas en el diagrama
  const redirect = new Map<string, { to: string; from: number }>();
  const failovers: NonNullable<SimSummary['failovers']> = [];
  const failoverFrom = (primaryId: string, failure: FailureKind, at: number, downUntil: number, detectS?: number) => {
    const ls = links.filter((l) => l.primaryId === primaryId);
    if (!ls.length || redirect.has(primaryId)) return;
    const covs = ls.map((l) => ({ l, c: coverage(l, failure, { detectS }) }));
    const ok = covs.filter((x) => x.c.covers && !isDown(x.l.replicaId, at + x.c.rtoS)).sort((a, b) => a.c.rtoS - b.c.rtoS)[0];
    if (ok && at + ok.c.rtoS < downUntil) {
      const from = at + ok.c.rtoS;
      redirect.set(primaryId, { to: ok.l.replicaId, from });
      failovers.push({ primaryId, replicaId: ok.l.replicaId, ok: true, at: from, rtoS: ok.c.rtoS, rpoS: ok.c.rpoS, why: ok.c.why });
      if (from < sc.duration)
        events.push({
          t: from,
          label: `Failover ${ok.l.failover === 'auto' ? 'automático' : 'manual'}: ${label(ok.l.replicaId)} (${MODE_MAP[ok.l.mode].short}) atiende lo que iba a ${label(primaryId)}${ok.c.rpoS > 0 ? ` · se pierden ~${fmtDur(ok.c.rpoS)} de escrituras` : ' · sin pérdida de datos'}`,
          kind: 'good',
          nodeId: ok.l.replicaId,
        });
      return;
    }
    for (const x of covs) {
      const why = x.c.covers ? (isDown(x.l.replicaId, at + x.c.rtoS) ? 'también quedó fuera de servicio.' : 'la primaria vuelve antes de que termine la promoción.') : x.c.why;
      failovers.push({ primaryId, replicaId: x.l.replicaId, ok: false, late: x.c.covers, at, rtoS: Infinity, rpoS: Infinity, why });
      events.push({ t: at, label: `${label(x.l.replicaId)} no sirve como failover de ${label(primaryId)}: ${why}`, kind: x.c.covers ? 'info' : 'bad', nodeId: x.l.replicaId });
    }
  };
  /** Destino real de una llamada (la réplica, si la primaria ya hizo failover). */
  const route = (id: string, t: number) => {
    const r = redirect.get(id);
    return r && t >= r.from ? r.to : id;
  };

  const loseInstances = (id: string, k: number, t: number, cause: string, failure: FailureKind = 'instance') => {
    const p = prof.get(id)!;
    const s = st.get(id)!;
    const healthyBefore = s.instances - s.lost;
    k = Math.min(k, healthyBefore);
    if (k <= 0) return;
    if (p.stateful) {
      // Cae el primario (o el nodo): hay corte hasta el failover
      if (Number.isFinite(p.failoverTime)) {
        down(id, t, t + p.failoverTime, `${cause} — failover en curso`, healthyBefore > 1 ? 'failover completo, réplica promovida' : 'servicio restablecido');
        failoverFrom(id, failure, t, t + p.failoverTime);
        if (healthyBefore > 1) s.lost += Math.min(k, healthyBefore - 1);
        if (getService(lid(map.get(id) as ServiceNode)).role === 'cache' && healthyBefore <= 1) {
          s.coldFrom = t + p.failoverTime;
          s.coldUntil = t + p.failoverTime + 120;
        }
      } else {
        down(id, t, Infinity, `${cause} — sin Multi‑AZ propio, queda fuera de servicio`);
        failoverFrom(id, failure, t, Infinity);
      }
      return;
    }
    s.lost += k;
    const r = res.get(id)!;
    const detect = r.kind === 'fleet' ? r.detectS : UNDETECTED;
    s.undetectedUntil = t + detect;
    s.undetectedFrac = k / Math.max(1, healthyBefore);
    events.push({ t, label: `${label(id)}: ${cause} (${s.instances - s.lost}/${s.instances} sanas)`, kind: 'bad', nodeId: id });
    events.push({ t: t + detect, label: `${label(id)}: el health check saca ${k > 1 ? 'las instancias caídas' : 'la instancia caída'} del balanceo (${detect} s según su configuración)`, kind: 'info', nodeId: id });
    if (Number.isFinite(p.replaceTime)) {
      s.replaceAt = t + p.replaceTime;
      if (s.replaceAt < sc.duration) events.push({ t: s.replaceAt, label: `${label(id)}: instancia de reemplazo en servicio`, kind: 'good', nodeId: id });
    }
    if (s.instances - s.lost <= 0) {
      s.downFrom = t;
      s.downUntil = Number.isFinite(p.replaceTime) ? t + p.replaceTime : Infinity;
      if (!Number.isFinite(p.replaceTime)) events.push({ t, label: `${label(id)}: no hay Auto Scaling que la reemplace`, kind: 'bad', nodeId: id });
    }
  };

  if (sc.kind === 'instance-failure') {
    if (!targetId) warnings.push('No hay piezas con instancias (EC2, ECS, BD…) para hacer fallar.');
    else {
      const d = def(targetId);
      const p = prof.get(targetId)!;
      if (!d.vpcBound && !p.stateful) {
        warnings.push(`${label(targetId)} es un servicio administrado: AWS reemplaza su capacidad de forma transparente, no hay instancias que fallen. Prueba "Falla de una dependencia".`);
      }
    }
  }
  if (sc.kind === 'node-outage' && targetId) {
    down(targetId, t0, t1, 'deja de responder', 'vuelve a responder');
    failoverFrom(targetId, 'outage', t0, t1);
  }
  if (sc.kind === 'node-outage' && !targetId) warnings.push('Elige la pieza que va a fallar.');

  // DDoS L3/L4: los puntos de entrada administrados (Shield Standard) lo absorben
  let l34Mitigated = true;
  if (sc.kind === 'ddos-l34' && targetId) {
    const r = def(targetId).role;
    l34Mitigated = ['cdn', 'dns', 'lb', 'api'].includes(r);
    if (l34Mitigated) events.push({ t: t0, label: `${label(targetId)}: ${sc.gbps} Gbps absorbidos por AWS Shield Standard`, kind: 'good', nodeId: targetId });
    else down(targetId, t0, t1, `saturado por ${sc.gbps} Gbps (sin Shield delante)`, 'el ataque termina');
  }

  // Protección del objetivo (WAF / Shield Advanced asociados)
  const protectors = edges.filter((e) => e.target === targetId).map((e) => map.get(e.source)).filter(isService);
  const waf = protectors.find((n) => lid(n) === 'waf');
  const shieldAdv = protectors.find((n) => lid(n) === 'shield');
  const wp = waf?.data.props ?? {};
  const rateLimit = Number(wp.rateLimit) || 2000;
  const blockFrac = (flow: number, t: number): number => {
    if (!targetId) return 0;
    const since = t - t0;
    let pass = 1;
    if (waf) {
      if (flow === FLOOD) {
        const perIp = sc.attackRps / Math.max(1, sc.botIps);
        if (perIp * 300 > rateLimit && since >= 30) pass *= 0;
        if (wp.botControl && since >= 30) pass *= 0.4;
      } else if (flow === 2) pass *= 1 - (wp.sqliRules ? 0.95 : wp.managedRules ? 0.3 : 0);
      else if (flow === 3) pass *= 1 - (wp.managedRules ? 0.9 : 0);
      else if (flow === 4) pass *= 1 - (wp.managedRules ? 0.9 : 0);
      else if (flow === 5) {
        const perIp = sc.botsRps / Math.max(1, sc.botIps);
        if (perIp * 300 > rateLimit && since >= 30) pass *= 0;
        if (wp.botControl) pass *= 0.15;
      }
    }
    if (shieldAdv && waf && flow === FLOOD && since >= 120 && sc.kind === 'ddos-l7') pass *= 0.1;
    if (sc.kind === 'credential-stuffing' && flow === FLOOD) {
      if (waf && wp.atp && since >= 30) pass *= 0.1;
      if (security.captcha) pass *= 0.05;
      const tn = map.get(targetId) as ServiceNode | undefined;
      if (tn && lid(tn) === 'cognito' && tn.data.props.threatProtection && since >= 60) pass *= 0.25;
    }
    return 1 - pass;
  };
  if (sc.kind === 'ddos-l7' && targetId) {
    events.push({ t: t0, label: `Comienza el HTTP flood: ${fmtRps(sc.attackRps)} req/s desde ${sc.botIps} IPs contra ${label(targetId)}`, kind: 'bad', nodeId: targetId });
    if (waf) {
      const perIp = sc.attackRps / Math.max(1, sc.botIps);
      if (perIp * 300 > rateLimit) events.push({ t: t0 + 30, label: `WAF: la regla de rate limit bloquea las IPs atacantes (${Math.round(perIp * 300)} > ${rateLimit} req/5 min por IP)`, kind: 'good', nodeId: waf.id });
      else events.push({ t: t0 + 30, label: `WAF: cada IP envía ${Math.round(perIp * 300)} req/5 min, por debajo del límite (${rateLimit}): el rate limit no las detecta`, kind: 'bad', nodeId: waf.id });
      if (wp.botControl) events.push({ t: t0 + 30, label: 'WAF Bot Control identifica y bloquea ~60% de los bots', kind: 'good', nodeId: waf.id });
      if (shieldAdv) events.push({ t: t0 + 120, label: 'Shield Advanced aplica mitigación automática de capa 7', kind: 'good', nodeId: shieldAdv.id });
    }
    if (t1 < sc.duration) events.push({ t: t1, label: 'El ataque termina', kind: 'info' });
  }
  if (['web-attacks', 'ddos-l7', 'scraping', 'credential-stuffing'].includes(sc.kind))
    for (const [iid, ips] of ipsOf)
      events.push({
        t: t0 + 5,
        label: ips.mode === 'ids' ? `${label(ips.applianceId)} está en modo IDS: detecta y alerta, pero no bloquea` : !ips.sees ? `${label(ips.applianceId)} no ve el contenido: el tráfico llega cifrado (TLS) a ${label(iid)} y el firewall no descifra` : ips.mode === 'off' ? `${label(ips.applianceId)} no tiene perfiles de prevención de amenazas` : `El IPS de ${label(ips.applianceId)} inspecciona el tráfico en ${label(iid)} y bloquea exploits conocidos`,
        kind: ips.mode === 'ips' && ips.sees ? 'good' : 'bad',
        nodeId: ips.applianceId,
      });
  if (sc.kind === 'credential-stuffing' && targetId) {
    events.push({ t: t0, label: `Comienza el relleno de credenciales: ${fmtRps(sc.attackRps)} intentos de login/s desde ${sc.botIps} IPs contra ${label(targetId)}`, kind: 'bad', nodeId: targetId });
    const perIp = (sc.attackRps * 300) / Math.max(1, sc.botIps);
    if (waf) events.push({ t: t0 + 30, label: perIp > rateLimit ? `WAF: el rate limit bloquea las IPs (${Math.round(perIp)} intentos/5 min por IP)` : `WAF: cada IP hace ${Math.round(perIp)} intentos/5 min, por debajo del límite (${rateLimit}): el rate limit no lo ve`, kind: perIp > rateLimit ? 'good' : 'bad', nodeId: waf.id });
    if (waf?.data.props.atp) events.push({ t: t0 + 30, label: 'WAF ATP detecta credenciales filtradas y bloquea el ataque al login', kind: 'good', nodeId: waf.id });
    if (security.captcha) events.push({ t: t0, label: 'El CAPTCHA del login frena a casi todos los bots', kind: 'good', nodeId: targetId });
    const tn = map.get(targetId) as ServiceNode;
    if (lid(tn) === 'cognito' && tn.data.props.threatProtection) events.push({ t: t0 + 60, label: 'Cognito threat protection bloquea los inicios de sesión de riesgo', kind: 'good', nodeId: targetId });
    if (t1 < sc.duration) events.push({ t: t1, label: 'El ataque termina', kind: 'info' });
  }
  if (sc.kind === 'scraping' && targetId) {
    events.push({ t: t0, label: `Bots con cuentas válidas recorren los identificadores de la API: ${fmtRps(sc.botsRps)} req/s desde ${sc.botIps} IPs`, kind: 'bad', nodeId: targetId });
    if (t1 < sc.duration) events.push({ t: t1, label: 'El scraping termina', kind: 'info' });
  }
  if (sc.kind === 'web-attacks' && targetId) {
    events.push({ t: t0, label: `Comienzan los ataques web contra ${label(targetId)}`, kind: 'bad', nodeId: targetId });
    if (t1 < sc.duration) events.push({ t: t1, label: 'Los ataques terminan', kind: 'info' });
  }

  // Caída de AZ: se programa al inicio del evento
  const azFailure = (t: number) => {
    for (const n of services) {
      const place = placementOf(n, map);
      if (!place.startsWith('subnet-')) continue;
      const d = getService(n.data.serviceId);
      const p = prof.get(n.id)!;
      if (p.passive || ['lb', 'netgw', 'inspection'].includes(d.role) || lid(n) === 'lambda') continue;
      // Las réplicas dibujadas viven en otra AZ que la primaria
      if (replicaIds.has(n.id)) continue;
      const vpc = ancestors(n, map).find((z) => z.data.zoneKind === 'vpc');
      const azs = Number(vpc?.data.props.azs ?? 2);
      if (azs < 2) {
        down(n.id, t, Infinity, 'la VPC solo usa una AZ y esa AZ cayó');
        failoverFrom(n.id, 'az', t, Infinity);
        continue;
      }
      const s = st.get(n.id)!;
      const N = s.instances - s.lost;
      if (p.stateful) {
        if (p.multiAz) loseInstances(n.id, Math.max(1, Math.floor(N / 2)), t, 'la AZ del primario cayó', 'az');
        else {
          down(n.id, t, Infinity, 'estaba en una sola AZ (sin Multi‑AZ propio)');
          failoverFrom(n.id, 'az', t, Infinity);
        }
      } else {
        const r = res.get(n.id)!;
        const lose = r.kind === 'fleet' ? (r.azs <= 1 ? N : Math.ceil(N / r.azs)) : N >= 2 ? Math.floor(N / 2) : 1;
        loseInstances(n.id, lose, t, r.kind === 'fleet' && r.azs <= 1 ? 'todas sus instancias estaban en la AZ caída' : 'pierde las instancias de la AZ caída', 'az');
      }
    }
  };

  // ── Caída de la región: cada pieza vuelve en la región secundaria según la estrategia de DR
  const crit = criticalPath(nodes, edges);
  let regionLoss = (_t: number) => 0;
  let dataLossS: number | null | undefined;
  let dns: DnsCutover | null = null;
  const regionNoCopy: string[] = [];
  const regionSlow: { id: string; back: number }[] = [];
  const quietDown = (id: string, from: number, until: number) => {
    const s = st.get(id)!;
    s.downFrom = from;
    s.downUntil = until;
  };
  if (sc.kind === 'region-failure') {
    dns = dnsCutover(nodes, security);
    const where = opts.region ? `${opts.region}` : 'principal';
    events.push({ t: t0, label: `Cae la región ${where} completa: cómputo, bases de datos, colas y servicios regionales`, kind: 'bad' });
    let loss = 0;
    let anyData = false;
    const otherRegion = new Set(links.filter((l) => l.mode === 'cross-region' || l.mode === 'isolated').map((l) => l.replicaId));
    const regionPrimaries: string[] = [];
    for (const n of services) {
      const r = res.get(n.id)!;
      if (['actor', 'global', 'dns'].includes(r.kind)) continue;
      if (otherRegion.has(n.id)) continue;
      const rr = regionRecovery(n, r, dr, security);
      if (links.some((l) => l.primaryId === n.id)) regionPrimaries.push(n.id);
      if (holdsData(r.kind) && crit.has(n.id)) {
        anyData = true;
        const cov = links.filter((l) => l.primaryId === n.id).map((l) => coverage(l, 'region')).filter((c) => c.covers).sort((a, b) => a.rpoS - b.rpoS)[0];
        if (cov) loss = Math.max(loss, cov.rpoS);
        else if (!Number.isFinite(rr.rpoS)) regionNoCopy.push(n.id);
        else loss = Math.max(loss, rr.rpoS);
      }
      if (dr.strategy === 'active') {
        // La otra región ya atendía la mitad del tráfico: ahora lo atiende todo
        capMods.set(n.id, (t) => (t < t0 ? 2 : 1));
        if (rr.rtoS > 0) {
          quietDown(n.id, t0, t0 + rr.rtoS);
          if (crit.has(n.id)) regionSlow.push({ id: n.id, back: rr.rtoS });
        }
        continue;
      }
      const back = Number.isFinite(rr.rtoS) ? Math.max(rr.rtoS, dns.seconds) : Infinity;
      quietDown(n.id, t0, t0 + back);
      if (crit.has(n.id)) regionSlow.push({ id: n.id, back });
      if (Number.isFinite(back) && t0 + back < sc.duration && crit.has(n.id))
        events.push({ t: t0 + back, label: `${label(n.id)}: atiende desde ${dr.secondaryRegion}${rr.capacity0 < 1 ? ` con ~${Math.round(rr.capacity0 * 100)} % de capacidad (escala en ~${fmtDur(rr.rampS)})` : ''}`, kind: 'good', nodeId: n.id });
      if (rr.capacity0 < 1 && Number.isFinite(back)) {
        const from = t0 + back;
        capMods.set(n.id, (t) => (t < from ? 1 : Math.min(1, rr.capacity0 + ((1 - rr.capacity0) * (t - from)) / Math.max(1, rr.rampS))));
      }
    }
    for (const id of regionPrimaries) failoverFrom(id, 'region', t0, st.get(id)!.downUntil);
    if (dr.strategy === 'active') regionLoss = (t) => (t >= t0 && t < t0 + dns!.seconds ? 0.5 : 0);
    if (dr.strategy !== 'none' && t0 + dns.seconds < sc.duration)
      events.push({ t: t0 + dns.seconds, label: dns.automatic ? `Route 53: los health checks fallan y el DNS manda el tráfico a ${dr.secondaryRegion}` : `El equipo cambia el DNS a mano hacia ${dr.secondaryRegion}`, kind: dns.automatic ? 'good' : 'info', nodeId: dns.dnsId ?? undefined });
    if (dr.strategy === 'none') events.push({ t: t0, label: 'No hay región secundaria: el servicio espera a que el proveedor recupere la región', kind: 'bad' });
    dataLossS = dr.strategy === 'none' || !anyData ? null : regionNoCopy.length ? Infinity : loss;
  }

  // ── Dependencia lenta (también en el Game Day)
  const slowTarget = sc.kind === 'slow-dependency' ? targetId : sc.kind === 'gameday' ? pickDefaultTarget(nodes, edges, 'gameday') : null;
  const slowFrom = sc.kind === 'gameday' ? t0 + 240 : t0;
  const slowTo = sc.kind === 'gameday' ? t0 + 420 : t1;
  const slowOn = (t: number) => !!slowTarget && t >= slowFrom && t < slowTo;
  const slowEdge = new Map<string, { mult: number; ok: boolean; add: number }>();
  const slowCallers = slowTarget ? tedges.filter((e) => e.t === slowTarget && e.kind === 'sync') : [];
  const baseLat = (id: string) => {
    let l = prof.get(id)!.latency;
    for (const e of outE.get(id) ?? []) if (e.kind === 'sync') l += Math.min(1, e.w) * (prof.get(e.t)?.latency ?? 0);
    return Math.max(5, l);
  };
  const slowStats = new Map<string, { minCap: number; attempts: number; breaker: boolean; timesOut: boolean; timeout: number; retries: number }>();
  if (slowTarget) {
    const extra = sc.extraLatency;
    if (slowFrom < sc.duration) events.push({ t: slowFrom, label: `${label(slowTarget)} responde ${extra >= 1000 ? `${(extra / 1000).toFixed(1)} s` : `${extra} ms`} más lento (no se cae: se pone lenta)`, kind: 'bad', nodeId: slowTarget });
    for (const e of slowCallers) {
      const cfg = res.get(e.s)!.caller;
      const timesOut = extra > cfg.timeoutMs;
      const attempts = timesOut ? 1 + cfg.retries : 1;
      const held = Math.min(extra, cfg.timeoutMs) * attempts;
      const L0 = baseLat(e.s);
      const factor = L0 / (L0 + Math.min(1, e.w) * held);
      slowStats.set(e.s, { minCap: factor, attempts, breaker: cfg.breaker, timesOut, timeout: cfg.timeoutMs, retries: cfg.retries });
      const who = label(e.s);
      if (timesOut)
        events.push({ t: slowFrom, label: `${who}: cada llamada espera su timeout (${cfg.timeoutMs} ms)${cfg.retries ? ` y reintenta ${cfg.retries} vez/veces → ×${attempts} llamadas a ${label(slowTarget)}` : ''}; con los hilos ocupados su capacidad cae al ${Math.round(factor * 100)} %`, kind: 'bad', nodeId: e.s });
      else events.push({ t: slowFrom, label: `${who}: su timeout (${cfg.timeoutMs} ms) es mayor que la demora, así que espera; con los hilos ocupados su capacidad cae al ${Math.round(factor * 100)} %`, kind: 'bad', nodeId: e.s });
      if (cfg.breaker && slowFrom + 10 < sc.duration) events.push({ t: slowFrom + 10, label: `${who}: el circuit breaker se abre — falla rápido en lo que necesita a ${label(slowTarget)} y recupera su capacidad`, kind: 'good', nodeId: e.s });
    }
    if (slowTo < sc.duration) events.push({ t: slowTo, label: `${label(slowTarget)} vuelve a su latencia normal`, kind: 'good', nodeId: slowTarget });
  }

  // ── Corrupción de datos y ransomware
  let corruptUntil = -1;
  let dataRestore: { rtoS: number; rpoS: number; text: string } | null = null;
  if ((sc.kind === 'data-corruption' || sc.kind === 'ransomware') && targetId) {
    const n = map.get(targetId) as ServiceNode;
    const r = res.get(targetId)!;
    const rec = dataRecovery(n, r, { ransomware: sc.kind === 'ransomware', security });
    dataRestore = rec;
    const detect = sc.kind === 'ransomware' ? 0 : Math.max(0, sc.detectMin * 60);
    corruptUntil = t0 + detect;
    if (sc.kind === 'ransomware') events.push({ t: t0, label: `${label(targetId)}: un atacante con credenciales cifra los datos y borra snapshots y backups a su alcance`, kind: 'bad', nodeId: targetId });
    else {
      events.push({ t: t0, label: `${label(targetId)}: un despliegue con un bug (o un UPDATE sin WHERE) daña los datos. Multi‑AZ y las réplicas copian el daño al instante`, kind: 'bad', nodeId: targetId });
      if (detect > 0 && corruptUntil < sc.duration) events.push({ t: corruptUntil, label: `Alguien nota el problema (${sc.detectMin} min después). Se pone ${label(targetId)} en mantenimiento para restaurar`, kind: 'info', nodeId: targetId });
    }
    const until = corruptUntil + rec.rtoS;
    // Las réplicas en vivo (y en ransomware, todas las de la misma cuenta) reciben el mismo daño
    for (const l of links.filter((x) => x.primaryId === targetId)) {
      const c = coverage(l, sc.kind === 'ransomware' ? 'ransomware' : 'corruption', { detectS: detect });
      if (!c.covers) quietDown(l.replicaId, sc.kind === 'ransomware' ? t0 : corruptUntil, until);
    }
    failoverFrom(targetId, sc.kind === 'ransomware' ? 'ransomware' : 'corruption', t0, Number.isFinite(until) ? until : Infinity, detect);
    const fo = failovers.find((f) => f.primaryId === targetId && f.ok);
    if (r.kind === 'cache' && rec.rtoS === 0) {
      const s0 = st.get(targetId)!;
      s0.coldFrom = corruptUntil;
      s0.coldUntil = corruptUntil + 120;
      events.push({ t: corruptUntil, label: `${label(targetId)}: se vacía la caché y se vuelve a llenar desde la base de datos`, kind: 'good', nodeId: targetId });
    } else {
      quietDown(targetId, corruptUntil, until);
      if (Number.isFinite(until) && until < sc.duration) events.push({ t: until, label: `${label(targetId)}: restaurado y de vuelta en servicio`, kind: 'good', nodeId: targetId });
      else if (!Number.isFinite(rec.rtoS) && !fo) events.push({ t: corruptUntil, label: `${label(targetId)}: no hay copia de la que restaurar`, kind: 'bad', nodeId: targetId });
    }
    dataLossS = fo ? Math.min(rec.rpoS, fo.rpoS) : rec.rpoS;
  }

  const legitAt = (t: number) => {
    switch (sc.kind) {
      case 'load':
        return sc.baseRps + (sc.peakRps - sc.baseRps) * Math.min(1, t / Math.max(1, sc.duration * 0.85));
      case 'gameday':
      case 'spike': {
        if (t < t0 || t >= t1) return sc.baseRps;
        const ramp = Math.min(1, (t - t0) / 10);
        return sc.baseRps + (sc.peakRps - sc.baseRps) * ramp;
      }
      default:
        return sc.baseRps;
    }
  };
  const inWindow = (t: number) => t >= t0 && t < t1;

  // ── 5. Bucle de tiempo
  const frames: Frame[] = [];
  const steps = Math.max(1, Math.round(sc.duration / DT));
  const peakUtil = new Map<string, number>();
  const attackTotals = { sent: 0, blocked: 0, absorbed: 0, toApp: 0 };
  const perFlow = FLOWS.map((f) => ({ flow: f, sent: 0, blocked: 0, toApp: 0, toData: 0 }));
  let peakBacklog = 0;
  let lambdaFloodInvocations = 0;
  let stuffServed = 0;
  let ipsBlocked = 0;
  let lambdaGbSeconds = 0;
  let peakLambdaConc = 0;
  let lambdaToRdsMaxConn = Infinity;
  const lambdaToRds = services.filter((n) => lid(n) === 'lambda' && (outE.get(n.id) ?? []).some((e) => ['rds', 'aurora'].includes(lid(map.get(e.t) as ServiceNode))));
  for (const l of lambdaToRds) {
    for (const e of outE.get(l.id) ?? []) {
      const tgt = map.get(e.t) as ServiceNode;
      if (['rds', 'aurora'].includes(lid(tgt))) lambdaToRdsMaxConn = Math.min(lambdaToRdsMaxConn, Math.round(prof.get(tgt.id)!.perInstance / 3.5));
    }
  }

  for (let i = 0; i <= steps; i++) {
    const t = i * DT;

    // Eventos programados por el escenario
    if (sc.kind === 'instance-failure' && targetId && t === Math.round(t0 / DT) * DT) {
      const d = def(targetId);
      if (d.vpcBound || prof.get(targetId)!.stateful) loseInstances(targetId, 1, t, 'falla una instancia');
    }
    if (sc.kind === 'az-failure' && t === Math.round(t0 / DT) * DT) {
      events.push({ t, label: 'Cae una zona de disponibilidad completa', kind: 'bad' });
      azFailure(t);
    }
    if (sc.kind === 'gameday' && t === Math.round((t0 + 90) / DT) * DT) {
      events.push({ t, label: 'Game Day: en pleno pico cae una zona de disponibilidad', kind: 'bad' });
      azFailure(t);
    }
    // Dependencia lenta: capacidad de quien llama y carga extra por reintentos
    slowCap.clear();
    slowEdge.clear();
    if (slowOn(t)) {
      for (const e of slowCallers) {
        const cfg = res.get(e.s)!.caller;
        const timesOut = sc.extraLatency > cfg.timeoutMs;
        const open = cfg.breaker && t >= slowFrom + 10;
        const attempts = timesOut && !open ? 1 + cfg.retries : 1;
        const held = open ? 0 : Math.min(sc.extraLatency, cfg.timeoutMs) * attempts;
        const L0 = baseLat(e.s);
        slowCap.set(e.s, Math.min(slowCap.get(e.s) ?? 1, L0 / (L0 + Math.min(1, e.w) * held)));
        slowEdge.set(e.id, { mult: open ? 0.05 : attempts, ok: !timesOut && !open, add: open ? 0 : Math.min(sc.extraLatency, cfg.timeoutMs) * attempts });
      }
    }
    for (const n of services) {
      const s = st.get(n.id)!;
      if (s.replaceAt <= t) {
        s.lost = 0;
        s.replaceAt = Infinity;
      }
      if (s.pending && s.pending.at <= t) {
        s.instances = s.pending.to;
        s.pending = null;
      }
    }

    // Inyectar tráfico
    const offered = new Map<string, Float64Array>(services.map((n) => [n.id, new Float64Array(F)]));
    const legit = legitAt(t);
    let legitOffered = 0;
    for (const [src, entries] of sources) {
      const share = legit * srcShare.get(src)!;
      legitOffered += share;
      for (const e of entries) offered.get(e)![LEGIT] += share / entries.length;
      for (const id of loginEdges.get(src) ?? []) {
        offered.get(id)![LEGIT] += share * LOGIN_RATIO;
        legitOffered += share * LOGIN_RATIO;
      }
    }
    const blockedAt = new Float64Array(F);
    if (targetId && inWindow(t)) {
      const o = offered.get(targetId)!;
      if (sc.kind === 'ddos-l7' || sc.kind === 'credential-stuffing') o[FLOOD] += sc.attackRps;
      if (sc.kind === 'scraping') o[5] += sc.botsRps;
      if (sc.kind === 'web-attacks') {
        o[2] += sc.sqliRps;
        o[3] += sc.xssRps;
        o[4] += sc.lfiRps;
        o[5] += sc.botsRps;
      }
      for (let f = 1; f < F; f++) {
        if (!o[f]) continue;
        perFlow[f].sent += o[f] * DT;
        const b = o[f] * blockFrac(f, t);
        blockedAt[f] = b;
        perFlow[f].blocked += b * DT;
        o[f] -= b;
      }
    }

    // Propagar en orden topológico
    const served = new Map<string, number>();
    const sfEff = new Map<string, number>();
    const nodesF: Record<string, NodeFrame> = {};
    const edgesF: Record<string, { rps: number; attack: number }> = {};
    let absorbedAttack = 0;
    for (const id of order) {
      const o = offered.get(id)!;
      const p = prof.get(id)!;
      const s = st.get(id)!;
      const d = def(id);
      const total = sum(o);
      const cap = capacity(id, t);
      let sf = total > 0 ? Math.min(1, cap / total) : cap > 0 ? 1 : 0;
      const uf = t < s.undetectedUntil ? 1 - s.undetectedFrac : 1;
      sf *= uf;
      sfEff.set(id, total > 0 || cap > 0 ? sf : 0);
      const out = o.map((v) => v * sf);
      served.set(id, sum(out));
      const outs = (outE.get(id) ?? []).filter((e) => !isBack(e));
      let nodeAbsorbed = 0;

      if (d.role === 'queue') {
        // Cola: acumula y se drena a la velocidad de los consumidores
        for (let f = 0; f < F; f++) s.backlog[f] += out[f] * DT;
        const consumers = outs.filter((e) => e.kind === 'consume');
        const capSum = consumers.reduce((a, e) => a + capacity(e.t, t), 0);
        const bl = sum(s.backlog);
        const drain = Math.min(bl / DT, capSum);
        for (const e of consumers) {
          const share = capSum > 0 ? capacity(e.t, t) / capSum : 0;
          const add = offered.get(e.t)!;
          let r = 0;
          for (let f = 0; f < F; f++) {
            const v = bl > 0 ? (s.backlog[f] / bl) * drain * share : 0;
            add[f] += v;
            r += v;
          }
          edgesF[e.id] = { rps: r, attack: 0 };
        }
        if (bl > 0) for (let f = 0; f < F; f++) s.backlog[f] -= (s.backlog[f] / bl) * drain * DT;
        peakBacklog = Math.max(peakBacklog, sum(s.backlog));
      } else if (ROUTERS.includes(d.role)) {
        if (d.role === 'inspection') {
          // La flota de firewalls procesa lo que pasa; el IPS bloquea lo que alcanza a ver
          const fl = fleetOf.get(id) ?? [];
          const capT = fl.reduce((a, x) => a + capacity(x, t), 0);
          for (const a of fl) {
            const share = capT > 0 ? capacity(a, t) / capT : 1 / fl.length;
            const add = offered.get(a)!;
            for (let f = 0; f < F; f++) add[f] += out[f] * share;
          }
          const ips = ipsOf.get(id);
          if (ips)
            for (let f = 2; f < F; f++) {
              const b = out[f] * ips.block[f];
              if (b <= 0) continue;
              out[f] -= b;
              blockedAt[f] += b;
              perFlow[f].blocked += b * DT;
              ipsBlocked += b * DT;
            }
        }
        const routes = outs.filter((e) => e.kind === 'route');
        for (const e of routes) {
          const add = offered.get(e.t)!;
          const tRole = def(e.t).role;
          let r = 0;
          let a = 0;
          for (let f = 0; f < F; f++) {
            let miss = 1;
            if (d.role === 'cdn') {
              if (f === LEGIT) miss = tRole === 'storage' ? CDN_MISS_STATIC : CDN_MISS_DYNAMIC;
              else if (f === FLOOD) miss = 1 - sc.cacheablePct / 100;
            }
            const v = (out[f] / routes.length) * miss;
            add[f] += v;
            r += v;
            if (f > 0) a += v;
            nodeAbsorbed += (out[f] / routes.length) * (1 - miss) * (f > 0 ? 1 : 0);
          }
          edgesF[e.id] = { rps: r, attack: a };
        }
        if (d.role === 'cdn') absorbedAttack += nodeAbsorbed;
      } else {
        const cacheEdge = outs.find((e) => e.kind === 'cache');
        const hit = cacheEdge ? cacheHit(cacheEdge.t, t) : 0;
        for (const e of outs) {
          if (e.kind === 'consume') continue;
          let w = e.w;
          const tRole = def(e.t).role;
          if (cacheEdge && (tRole === 'datastore' || tRole === 'search')) w *= 1 - hit;
          if (e.kind === 'cache' && isDown(e.t, t)) w = 0;
          const se = slowEdge.get(e.id);
          if (se) w *= se.mult;
          const tgt = route(e.t, t);
          const add = offered.get(tgt)!;
          let r = 0;
          let a = 0;
          for (let f = 0; f < F; f++) {
            const v = out[f] * w;
            add[f] += v;
            r += v;
            if (f > 0) a += v;
          }
          if (tgt === e.t) edgesF[e.id] = { rps: r, attack: a };
          else {
            // Failover: la flecha a la primaria queda en 0 y el tráfico va a la réplica
            edgesF[e.id] = { rps: 0, attack: 0 };
            const real = tedges.find((x) => x.s === e.s && x.t === tgt);
            const key = real ? real.id : `fo:${e.s}>${tgt}`;
            const prev = edgesF[key] ?? { rps: 0, attack: 0 };
            edgesF[key] = { rps: prev.rps + r, attack: prev.attack + a };
          }
        }
      }

      // Métricas de la pieza
      const attack = sum(o) - o[LEGIT];
      const util = Number.isFinite(cap) ? (cap > 0 ? total / cap : total > 0 ? Infinity : 0) : 0;
      if (Number.isFinite(util) && cap > 0) peakUtil.set(id, Math.max(peakUtil.get(id) ?? 0, util));
      const downNow = !p.passive && cap === 0;
      const displayPassive = p.passive || (['dns', 'waf', 'secrets', 'kms', 'cert'].includes(d.role) && total === 0);
      let status: NodeStatus = displayPassive ? 'passive' : total === 0 && !downNow ? 'idle' : 'ok';
      if (downNow) status = 'down';
      else if (util > 1) status = 'saturated';
      else if (s.lost > 0 || t < s.undetectedUntil) status = 'degraded';
      else if (util > 0.85) status = 'hot';
      nodesF[id] = {
        offered: total,
        attack,
        cap,
        util,
        status,
        healthy: Math.max(0, s.instances - s.lost),
        instances: s.instances,
        ...(d.role === 'queue' ? { backlog: sum(s.backlog) } : {}),
        ...(nodeAbsorbed > 0 ? { absorbed: nodeAbsorbed } : {}),
      };
      if (id === targetId && sc.kind === 'credential-stuffing') stuffServed += out[FLOOD] * DT;
      if (d.role === 'compute') {
        for (let f = 1; f < F; f++) perFlow[f].toApp += o[f] * DT;
        attackTotals.toApp += attack * DT;
      }
      if (['datastore', 'search'].includes(d.role)) for (let f = 2; f < F; f++) perFlow[f].toData += o[f] * DT;
      if (map.get(id) && lid(map.get(id) as ServiceNode) === 'lambda') {
        const sv = served.get(id)!;
        const dur = p.latency;
        const mem = Number((map.get(id) as ServiceNode).data.props.memory) || 512;
        const fl = sum(out) > 0 ? (sum(out) - out[LEGIT]) : 0;
        lambdaFloodInvocations += fl * DT;
        lambdaGbSeconds += fl * DT * (dur / 1000) * (mem / 1024);
        if (lambdaToRds.some((l) => l.id === id)) peakLambdaConc = Math.max(peakLambdaConc, (sv * dur) / 1000);
      }

      // Autoscaling (decide al final del paso)
      if ((p.scale === 'asg' || p.scale === 'serverless-db') && !s.pending && !isDown(id, t)) {
        const healthy = s.instances - s.lost;
        const u = healthy > 0 ? total / (p.perInstance * healthy) : 0;
        const thr = p.targetUtil ?? 0.7;
        if (u > thr && s.instances < p.maxInstances) {
          const want = p.stepAdd ? Math.min(p.maxInstances, s.instances + p.stepAdd) : Math.min(p.maxInstances, Math.max(s.instances + 1, Math.ceil(total / (p.perInstance * Math.max(0.2, thr - 0.1))) + s.lost));
          s.pending = { at: t + p.scaleDelay, to: want };
          const why =
            p.scaleMetric === 'requests' ? `${Math.round(total / Math.max(1, healthy))} req/s por instancia (objetivo ${p.targetRequests})`
            : p.scaleMetric === 'step' ? `CPU ${Math.round(Math.min(u, 1) * 100)}% (umbral ${Math.round(thr * 100)}%) → +${p.stepAdd}`
            : p.scaleMetric === 'capacity' ? `capacidad al ${Math.round(u * 100)}%`
            : `CPU ${Math.round(Math.min(u, 1) * 100)}% (objetivo ${Math.round(thr * 100)}%)`;
          events.push({ t, label: `${label(id)}: ${why} → escala a ${want} ${p.scale === 'serverless-db' ? 'ACU' : 'instancias'} (listas en ~${p.scaleDelay} s, según tu configuración)`, kind: 'info', nodeId: id });
        } else if (u > 1 && s.instances >= p.maxInstances && !s.pending) {
          s.pending = { at: t + 120, to: s.instances }; // evita repetir el aviso cada paso
          events.push({ t, label: `${label(id)}: llegó al máximo configurado (${p.maxInstances}) y sigue saturado — sube el máximo en su sección «Escalado»`, kind: 'bad', nodeId: id });
        }
      }
    }

    // Éxito y latencia (en orden inverso)
    const succ = new Map<string, number>();
    const lat = new Map<string, number>();
    for (let k = order.length - 1; k >= 0; k--) {
      const id = order[k];
      const d = def(id);
      const p = prof.get(id)!;
      const outs = (outE.get(id) ?? []).filter((e) => !isBack(e));
      const nf = nodesF[id];
      const rho = Number.isFinite(nf.cap) && nf.cap > 0 ? nf.offered / nf.cap : 0;
      const qf = rho >= 1 ? 10 : 1 / (1 - Math.min(rho, 0.9));
      let ok = 1;
      let l = p.latency * qf;
      if (slowOn(t) && id === slowTarget) l += sc.extraLatency;
      if (d.role === 'queue') {
        ok = 1;
      } else if (ROUTERS.includes(d.role)) {
        const routes = outs.filter((e) => e.kind === 'route');
        if (routes.length) {
          let acc = 0;
          let la = 0;
          for (const e of routes) {
            const miss = d.role === 'cdn' ? (def(e.t).role === 'storage' ? CDN_MISS_STATIC : CDN_MISS_DYNAMIC) : 1;
            acc += (1 / routes.length) * ((1 - miss) + miss * via(id, e.t, succ.get(e.t) ?? sfEff.get(e.t) ?? 1));
            la += (1 / routes.length) * miss * (lat.get(e.t) ?? 0);
          }
          ok = acc;
          l += la;
        }
      } else {
        const cacheEdge = outs.find((e) => e.kind === 'cache');
        const hit = cacheEdge ? cacheHit(cacheEdge.t, t) : 0;
        for (const e of outs) {
          const tRole = def(e.t).role;
          let w = e.w;
          if (cacheEdge && (tRole === 'datastore' || tRole === 'search')) w *= 1 - hit;
          const se = slowEdge.get(e.id);
          const tg = route(e.t, t);
          if (e.kind === 'sync' && se) {
            ok *= depOk(w, se.ok ? via(id, e.t, succ.get(tg) ?? 1) : 0);
            l += Math.min(w, 1) * (se.ok ? lat.get(tg) ?? 0 : se.add);
          } else if (e.kind === 'sync') {
            ok *= depOk(w, tg === e.t ? via(id, e.t, succ.get(e.t) ?? 1) : succ.get(tg) ?? 1);
            l += Math.min(w, 1) * (lat.get(tg) ?? 0);
          } else if (e.kind === 'async') {
            ok *= depOk(Math.min(w, 1), sfEff.get(e.t) ?? 1);
            l += Math.min(w, 1) * (prof.get(e.t)?.latency ?? 0);
          } else if (e.kind === 'cache') {
            l += isDown(e.t, t) ? 0 : (prof.get(e.t)?.latency ?? 0);
          }
        }
      }
      succ.set(id, (sfEff.get(id) ?? 1) * ok);
      lat.set(id, Math.min(l, 30000));
    }
    // El WAF muestra lo que está bloqueando
    const wafBlocked = sum(blockedAt);
    if (waf && wafBlocked > 0 && nodesF[waf.id]) nodesF[waf.id] = { ...nodesF[waf.id], blocked: wafBlocked, status: 'ok' };
    if (shieldAdv && nodesF[shieldAdv.id] && sc.kind === 'ddos-l7' && inWindow(t) && t - t0 >= 120) nodesF[shieldAdv.id] = { ...nodesF[shieldAdv.id], status: 'ok' };
    let legitOk = 0;
    let latAcc = 0;
    let latW = 0;
    for (const [src, entries] of sources) {
      const share = legit * srcShare.get(src)!;
      for (const e of entries) {
        legitOk += (share / entries.length) * (blockedPair.has(`${src}>${e}`) || blockedInto.has(e) ? 0 : succ.get(e) ?? 0);
        latAcc += (share / entries.length) * (lat.get(e) ?? 0);
        latW += share / entries.length;
      }
      for (const id of loginEdges.get(src) ?? []) legitOk += share * LOGIN_RATIO * (blockedPair.has(`${src}>${id}`) ? 0 : succ.get(id) ?? 0);
    }
    legitOk *= 1 - regionLoss(t);
    for (const [pid, r] of redirect) {
      if (t < r.from) continue;
      if (nodesF[pid]) nodesF[pid] = { ...nodesF[pid], failoverTo: label(r.to) };
      if (nodesF[r.to]) nodesF[r.to] = { ...nodesF[r.to], promoted: true };
    }
    if (corruptUntil > 0 && targetId && t >= t0 && t < corruptUntil && nodesF[targetId]) nodesF[targetId] = { ...nodesF[targetId], status: 'degraded' };
    const attackSent = ['ddos-l7', 'web-attacks', 'credential-stuffing', 'scraping'].includes(sc.kind) && targetId && inWindow(t) ? (sc.kind === 'ddos-l7' || sc.kind === 'credential-stuffing' ? sc.attackRps : sc.kind === 'scraping' ? sc.botsRps : sc.sqliRps + sc.xssRps + sc.lfiRps + sc.botsRps) : 0;
    const blockedNow = sum(blockedAt);
    attackTotals.blocked += blockedNow * DT;
    attackTotals.absorbed += absorbedAttack * DT;
    const toAppNow = services.filter((n) => def(n.id).role === 'compute').reduce((a, n) => a + nodesF[n.id].attack, 0);
    frames.push({
      t,
      legitOffered,
      legitOk,
      success: legitOffered > 0 ? Math.min(1, legitOk / legitOffered) : 1,
      latency: latW > 0 ? latAcc / latW : 0,
      attackSent,
      attackBlocked: blockedNow,
      attackAbsorbed: absorbedAttack,
      attackToApp: toAppNow,
      nodes: nodesF,
      edges: edgesF,
    });
  }
  attackTotals.sent = perFlow.slice(1).reduce((a, f) => a + f.sent, 0);
  events.sort((a, b) => a.t - b.t);

  // ── 6. Resumen
  const totOff = frames.reduce((a, f) => a + f.legitOffered, 0);
  const totOk = frames.reduce((a, f) => a + f.legitOk, 0);
  const lats = frames.map((f) => f.latency).sort((a, b) => a - b);
  const bad = frames.filter((f) => f.success < 0.99);
  const evStart = sc.kind === 'load' ? 0 : t0;
  let recovery: number | null = null;
  const firstBad = frames.find((f) => f.t >= evStart && f.success < 0.99);
  if (firstBad) {
    const back = frames.find((f) => f.t > firstBad.t && f.success >= 0.99 && frames.filter((g) => g.t > f.t).every((g) => g.success >= 0.99));
    recovery = back ? back.t - firstBad.t : null;
  }
  let bottleneck: SimSummary['bottleneck'] = null;
  for (const [id, u] of peakUtil) {
    if (prof.get(id)!.passive) continue;
    if (!bottleneck || u > bottleneck.peakUtil) bottleneck = { id, label: label(id), peakUtil: u };
  }
  // ── Impacto de los ataques que no son solo tráfico
  let impact: SimSummary['impact'];
  const has = (id: string) => services.some((n) => lid(n) === id);
  if (sc.kind === 'credential-stuffing' && targetId) {
    const tn = map.get(targetId) as ServiceNode;
    const cognito = lid(tn) === 'cognito';
    const mfa = cognito ? String(tn.data.props.mfa ?? 'OPTIONAL') : 'OFF';
    const taken = Math.round(stuffServed * 0.005 * (mfa === 'ON' ? 0.02 : mfa === 'OPTIONAL' ? 0.7 : 1) * (cognito && tn.data.props.threatProtection ? 0.3 : 1) * (wp.atp ? 0.3 : 1));
    impact = { label: 'Cuentas tomadas', value: taken.toLocaleString('es-CO'), tone: taken === 0 ? 'good' : taken < 20 ? 'warn' : 'bad', detail: `${Math.round(stuffServed).toLocaleString('es-CO')} intentos llegaron a validar la contraseña; ~0,5 % de las credenciales filtradas suelen ser reutilizadas. MFA ${mfa}.` };
  }
  if (sc.kind === 'scraping') {
    const leaked = security.objectAuthz ? 0 : Math.round(perFlow[5].toApp);
    impact = { label: 'Registros expuestos', value: leaked.toLocaleString('es-CO'), tone: leaked === 0 ? 'good' : 'bad', detail: security.objectAuthz ? 'La autorización por objeto devuelve 403 a los identificadores ajenos.' : 'Cada petición que llega a la aplicación devuelve el registro de otro usuario.' };
  }
  let exfil: { gb: number; rate: number; detect: number; respond: number; egress: string } | null = null;
  if (sc.kind === 'exfiltration' && targetId) {
    const tn = map.get(targetId) as ServiceNode;
    const place = placementOf(tn, map);
    const egress = has('networkfirewall') || services.some((n) => lid(n) === 'ngfw' && n.data.props.urlFiltering !== false) ? 'filtered' : has('natgw') || place === 'subnet-public' || !place.startsWith('subnet-') ? 'open' : 'none';
    const rate = { open: 144, filtered: 2, none: 0.2 }[egress]!; // GB/h
    const detect = has('guardduty') ? 1200 : security.dataAuditLogs && security.siem ? 7200 : Infinity;
    const respond = security.siem ? 600 : 10800;
    const stop = detect + respond;
    const full = (sc.dataGb / rate) * 3600;
    const gb = Math.min(sc.dataGb, (rate * Math.min(stop, sc.duration - t0)) / 3600);
    exfil = { gb, rate, detect, respond, egress };
    events.push({ t: t0, label: `${label(targetId)} está comprometido: el atacante vuelca los datos a los que llega y los saca por ${egress === 'open' ? 'Internet (NAT / IP pública)' : egress === 'filtered' ? 'el único hueco que deja el Network Firewall (DNS / dominios permitidos)' : 'túneles DNS (sin salida directa a Internet)'}`, kind: 'bad', nodeId: targetId });
    if (Number.isFinite(detect) && t0 + detect < sc.duration) events.push({ t: t0 + detect, label: has('guardduty') ? 'GuardDuty genera un hallazgo de exfiltración (tráfico anómalo)' : 'Los logs de acceso a datos disparan una alerta', kind: 'good' });
    if (Number.isFinite(stop) && t0 + stop < sc.duration) events.push({ t: t0 + stop, label: `El equipo aísla ${label(targetId)} y revoca sus credenciales${security.siem ? '' : ' (nadie vio la alerta hasta horas después)'}`, kind: 'good', nodeId: targetId });
    if (full < Math.min(stop, sc.duration - t0)) events.push({ t: t0 + full, label: `Ya salió toda la base (${sc.dataGb} GB)`, kind: 'bad' });
    impact = { label: 'Datos exfiltrados', value: `${gb >= 10 ? Math.round(gb) : gb.toFixed(1)} de ${sc.dataGb} GB`, tone: gb < sc.dataGb * 0.01 ? 'good' : gb < sc.dataGb ? 'warn' : 'bad', detail: `Salida ${egress === 'open' ? 'abierta' : egress === 'filtered' ? 'filtrada' : 'cerrada'} (~${rate} GB/h).` };
  }
  let keys: { noKeys: boolean; revoke: number; rate: number; cost: number } | null = null;
  if (sc.kind === 'leaked-keys') {
    const noKeys = !!security.rootMfa;
    const gd = has('guardduty');
    const revoke = security.secretScan ? 300 : gd ? 900 + (security.siem ? 600 : 10800) : 86400;
    const rate = security.scp ? 60 : 600; // US$/h en instancias GPU
    const cost = noKeys ? 0 : (rate * revoke) / 3600;
    keys = { noKeys, revoke, rate, cost };
    if (noKeys) events.push({ t: t0, label: 'El equipo entra por SSO con credenciales temporales: no hay access keys de larga duración que filtrar', kind: 'good' });
    else {
      events.push({ t: t0, label: 'Unas access keys de un desarrollador quedan en un repositorio público', kind: 'bad' });
      events.push({ t: t0 + 60, label: `Un bot las encuentra y lanza instancias GPU de minería en varias regiones (~US$${rate}/h)${security.boundary ? '' : ' y lista S3, DynamoDB y los secretos'}`, kind: 'bad' });
      if (t0 + revoke < sc.duration) events.push({ t: t0 + revoke, label: security.secretScan ? 'El escaneo de secretos las detecta y AWS aplica la política de cuarentena: llaves revocadas' : 'GuardDuty detecta el uso anómalo y el equipo revoca las llaves', kind: 'good' });
    }
    impact = { label: 'Costo del ataque', value: `US$${Math.round(cost).toLocaleString('es-CO')}`, tone: cost < 50 ? 'good' : cost < 2000 ? 'warn' : 'bad', detail: noKeys ? 'Sin llaves de larga duración.' : `~US$${rate}/h durante ${fmtDur(revoke)} hasta revocarlas.` };
  }

  const lambdaCost = lambdaFloodInvocations > 0 ? (lambdaFloodInvocations / 1e6) * 0.2 + lambdaGbSeconds * 0.0000166667 : 0;
  const summary: SimSummary = {
    availability: totOff > 0 ? totOk / totOff : 1,
    minSuccess: Math.min(...frames.map((f) => f.success)),
    p95Latency: lats[Math.floor(lats.length * 0.95)] ?? 0,
    baseLatency: frames[0]?.latency ?? 0,
    badSeconds: bad.length * DT,
    recoverySeconds: recovery,
    bottleneck,
    peakBacklog,
    ...(['ddos-l7', 'web-attacks', 'credential-stuffing', 'scraping'].includes(sc.kind) ? { attack: { ...attackTotals, perFlow: perFlow.slice(1).filter((f) => f.sent > 0) } } : {}),
    ...(lambdaCost > 0 ? { lambdaCostUsd: lambdaCost } : {}),
    ...(dataLossS !== undefined ? { dataLossS } : {}),
    ...(['region-failure', 'data-corruption', 'ransomware', 'gameday', 'slow-dependency'].includes(sc.kind) ? { downtimeS: frames.filter((f) => f.t >= t0 && f.success < 0.99).length * DT } : {}),
    ...(corruptUntil > 0 ? { corruptS: Math.max(0, Math.min(corruptUntil, sc.duration) - t0) } : {}),
    ...(failovers.length ? { failovers } : {}),
    ...(impact ? { impact } : {}),
  };

  const findings = buildFindings({ sc, summary, frames, peakUtil, prof, map, targetId, waf, shieldAdv, perFlow, l34Mitigated, peakLambdaConc, lambdaToRdsMaxConn, services, outE, edges, warnings, dr, dns, regionNoCopy, regionSlow, slowTarget, slowStats, slowFrom, slowTo, dataRestore, res, crit, suggested: suggestLinks(nodes, edges), security, exfil, keys, ipsOf, fleetOf, ipsBlocked });
  if (opts.blocked?.size) {
    const list = [...opts.blocked].map(([eid, why]) => {
      const e = edges.find((x) => x.id === eid);
      return { e, why };
    }).filter((x) => x.e);
    findings.unshift({
      severity: 'error',
      title: `${list.length} conexión${list.length > 1 ? 'es' : ''} bloqueada${list.length > 1 ? 's' : ''} por la configuración de red`,
      detail: list.map(({ e, why }) => `${label(e!.source)} → ${label(e!.target)}: ${why}`).join(' · ') + '. Las peticiones que pasan por ahí fallan en toda la simulación. Usa «Petición de usuario» para ver el detalle.',
      nodeIds: [...new Set(list.flatMap(({ e }) => [e!.source, e!.target]))],
    });
  }
  const cloud = primaryCloud(nodes);
  if (cloud === 'azure') {
    for (const e of events) e.label = cloudText(e.label, cloud);
    for (const f of findings) {
      f.title = cloudText(f.title, cloud);
      f.detail = cloudText(f.detail, cloud);
    }
  }
  return { scenario: sc, targetId, frames, events, summary, findings, warnings };
}

/* ───────────────────────────── hallazgos */

function recommendFor(n: ServiceNode, p: SimProfile): string {
  const id = lid(n);
  switch (id) {
    case 'ec2':
    case 'ecs':
    case 'eks':
    case 'apprunner':
      return p.scale === 'none'
        ? `No tiene autoescalado (Escalado → «${n.data.props.scalePolicy === 'manual' || n.data.props.autoscaling === false ? 'Sin ASG' : 'Tamaño fijo'}»). Actívalo por CPU o por peticiones en su sección «Escalado».`
        : `En su sección «Escalado»: sube el máximo (hoy ${p.maxInstances}), baja el objetivo para que reaccione antes o reduce el calentamiento (hoy tarda ~${p.scaleDelay} s). También puedes usar instancias más grandes.`;
    case 'lambda':
      return 'Pide un aumento de la concurrencia de la cuenta, reserva concurrencia para esta función o reduce su duración.';
    case 'apigw':
      return 'Solicita aumento de la cuota de throttling o pon CloudFront con caché delante de la API.';
    case 'rds':
      return 'Agrega réplicas de lectura, una caché (ElastiCache) delante o una clase de instancia mayor.';
    case 'aurora':
      return 'Agrega réplicas de lectura o activa Serverless v2 para que la capacidad escale sola.';
    case 'dynamodb':
      return n.data.props.billing === 'PROVISIONED' ? 'Cambia a on‑demand o activa auto scaling de capacidad.' : 'Pre‑calienta la tabla (warm throughput) o distribuye mejor la partition key.';
    case 'cognito':
      return 'Solicita aumento de la cuota UserAuthentication y evita re‑autenticar en cada request (reutiliza tokens).';
    case 'bedrock':
      return 'Solicita más cuota de tokens, usa Provisioned Throughput o encola las peticiones al modelo.';
    case 'ngfw':
      return 'Sube el máximo del Auto Scaling Group de firewalls o usa instancias más grandes. El descifrado TLS reduce la capacidad a la mitad; una instancia nueva tarda ~10 min.';
    case 'external':
    case 'onprem':
      return 'Desacopla con una cola, aplica reintentos con backoff y un circuit breaker; no dependas en línea de un tercero.';
    case 'elasticache':
      return 'Agrega réplicas o shards (cluster mode).';
    case 'sqs':
      return 'Usa lotes (batch) o una cola estándar si no necesitas orden estricto.';
    case 'eventbridge':
    case 'sns':
    case 'kinesis':
    case 'stepfunctions':
      return 'Solicita aumento de cuota o distribuye la carga entre varios recursos.';
    case 's3':
      return 'Distribuye los objetos en más prefijos y sirve las lecturas por CloudFront.';
    default:
      return 'Aumenta la capacidad de esta pieza o agrega caché/colas delante.';
  }
}

interface FindingCtx {
  sc: Scenario;
  summary: SimSummary;
  frames: Frame[];
  peakUtil: Map<string, number>;
  prof: Map<string, SimProfile>;
  map: Map<string, AppNode>;
  targetId: string | null;
  waf?: ServiceNode;
  shieldAdv?: ServiceNode;
  perFlow: { flow: Flow; sent: number; blocked: number; toApp: number; toData: number }[];
  l34Mitigated: boolean;
  peakLambdaConc: number;
  lambdaToRdsMaxConn: number;
  services: ServiceNode[];
  outE: Map<string, TEdge[]>;
  edges: AppEdge[];
  warnings: string[];
  dr: DrConfig;
  dns: DnsCutover | null;
  regionNoCopy: string[];
  regionSlow: { id: string; back: number }[];
  slowTarget: string | null;
  slowStats: Map<string, { minCap: number; attempts: number; breaker: boolean; timesOut: boolean; timeout: number; retries: number }>;
  slowFrom: number;
  slowTo: number;
  dataRestore: { rtoS: number; rpoS: number; text: string } | null;
  res: Map<string, NodeRes>;
  crit: Set<string>;
  suggested: { primaryId: string; replicaId: string }[];
  security: Record<string, boolean>;
  exfil: { gb: number; rate: number; detect: number; respond: number; egress: string } | null;
  keys: { noKeys: boolean; revoke: number; rate: number; cost: number } | null;
  ipsOf: Map<string, { block: number[]; sees: boolean; mode: 'ips' | 'ids' | 'off'; applianceId: string }>;
  fleetOf: Map<string, string[]>;
  ipsBlocked: number;
}

function buildFindings(c: FindingCtx): Finding[] {
  const out: Finding[] = [];
  const { sc, summary: s, frames } = c;
  const label = (id: string) => (c.map.get(id) as ServiceNode)?.data.label ?? id;
  const pct = (v: number) => `${(v * 100).toFixed(v >= 0.9995 || v < 0.1 ? 1 : 2)}%`;

  // Disponibilidad general
  if (s.availability >= 0.999) out.push({ severity: 'ok', title: `Disponibilidad ${pct(s.availability)}`, detail: 'La arquitectura atendió prácticamente todo el tráfico legítimo durante el escenario.', nodeIds: [] });
  else if (s.availability >= 0.99) out.push({ severity: 'warn', title: `Disponibilidad ${pct(s.availability)}`, detail: `Hubo ${s.badSeconds} s con más de 1% de errores. Mínimo de éxito: ${pct(s.minSuccess)}.`, nodeIds: [] });
  else out.push({ severity: 'error', title: `Disponibilidad ${pct(s.availability)}`, detail: `Hubo ${s.badSeconds} s con más de 1% de errores; en el peor momento solo se atendió el ${pct(s.minSuccess)} de los usuarios.`, nodeIds: [] });

  if (s.recoverySeconds !== null && sc.kind !== 'load') out.push({ severity: s.recoverySeconds <= 60 ? 'ok' : 'warn', title: `Recuperación en ${s.recoverySeconds} s`, detail: 'Tiempo desde los primeros errores hasta volver a estar por encima de 99% de éxito de forma estable.', nodeIds: [] });
  else if (s.minSuccess < 0.99 && s.recoverySeconds === null && sc.kind !== 'load') out.push({ severity: 'error', title: 'No se recupera durante la simulación', detail: 'La arquitectura no volvió a estar sana antes del final del escenario.', nodeIds: [] });

  // Cuellos de botella
  // (los que se saturan por hilos esperando a una dependencia lenta tienen su propio hallazgo)
  const hot = [...c.peakUtil.entries()].filter(([id, u]) => u > 1 && !c.prof.get(id)!.passive && !c.slowStats.has(id)).sort((a, b) => b[1] - a[1]).slice(0, 4);
  for (const [id, u] of hot) {
    const n = c.map.get(id) as ServiceNode;
    const p = c.prof.get(id)!;
    const peak = Math.max(...frames.map((f) => f.nodes[id]?.offered ?? 0));
    const peakFrame = frames.reduce((a, f) => ((f.nodes[id]?.offered ?? 0) > (a.nodes[id]?.offered ?? 0) ? f : a));
    const attackShare = (peakFrame.nodes[id]?.attack ?? 0) / Math.max(1, peakFrame.nodes[id]?.offered ?? 1);
    out.push({
      severity: 'error',
      title: `${label(id)} se saturó (${Math.round(u * 100)}% de su capacidad)`,
      detail:
        attackShare > 0.5
          ? `Recibió hasta ${fmtRps(peak)} req/s, ${Math.round(attackShare * 100)}% del ataque. Escalar no es la defensa: el tráfico malicioso debe frenarse en el borde (WAF, rate limit, Shield) antes de llegar aquí.`
          : `Recibió hasta ${fmtRps(peak)} req/s. ${p.quota ? `Límite: ${p.quota}. ` : ''}${recommendFor(n, p)}`,
      nodeIds: [id],
    });
  }
  if (!hot.length && (sc.kind === 'load' || sc.kind === 'spike') && s.bottleneck) {
    out.push({ severity: 'info', title: `Pieza más exigida: ${s.bottleneck.label} (${Math.round(s.bottleneck.peakUtil * 100)}%)`, detail: 'Será el primer cuello de botella si el tráfico sigue creciendo.', nodeIds: [s.bottleneck.id] });
  }

  // Piezas caídas sin recuperación (puntos únicos de falla)
  const last = frames[frames.length - 1];
  for (const n of c.services) {
    const wasDown = frames.some((f) => f.nodes[n.id]?.status === 'down');
    if (!wasDown) continue;
    const endsDown = last.nodes[n.id]?.status === 'down';
    if (endsDown && s.failovers?.some((f) => f.ok && f.primaryId === n.id)) continue;
    if (endsDown && !['node-outage', 'ddos-l34', 'region-failure', 'data-corruption', 'ransomware'].includes(sc.kind)) out.push({ severity: 'error', title: `${label(n.id)} es un punto único de falla`, detail: 'Cayó y no se recuperó: no tiene réplica, Multi‑AZ ni Auto Scaling que la reemplace.', nodeIds: [n.id] });
  }

  // Colas
  if (s.peakBacklog > 0) {
    const q = c.services.find((n) => getService(n.data.serviceId).role === 'queue' && frames.some((f) => (f.nodes[n.id]?.backlog ?? 0) > 1));
    if (q) {
      const peakF = frames.reduce((a, f) => ((f.nodes[q.id]?.backlog ?? 0) > (a.nodes[q.id]?.backlog ?? 0) ? f : a));
      const drained = frames.find((f) => f.t > peakF.t && (f.nodes[q.id]?.backlog ?? 0) < 1);
      out.push({
        severity: drained ? 'ok' : 'warn',
        title: `${label(q.id)} absorbió ${fmtRps(s.peakBacklog)} mensajes en espera`,
        detail: drained ? `La cola protegió a los consumidores del pico y se vació en ${drained.t - peakF.t} s.` : 'La cola sigue creciendo al final: los consumidores no alcanzan. Escala los workers o aumenta su concurrencia.',
        nodeIds: [q.id],
      });
    }
  }

  // Lambda → RDS (conexiones)
  if (c.peakLambdaConc > c.lambdaToRdsMaxConn) {
    out.push({ severity: 'warn', title: `Lambda abre ~${Math.round(c.peakLambdaConc)} conexiones a la BD`, detail: `La base de datos acepta ~${c.lambdaToRdsMaxConn} conexiones. Usa RDS Proxy para reutilizarlas o vas a ver errores "too many connections".`, nodeIds: [] });
  }

  // Escenarios de falla
  if (sc.kind === 'instance-failure' && c.targetId) {
    const p = c.prof.get(c.targetId)!;
    if (s.minSuccess >= 0.999) out.push({ severity: 'ok', title: 'Failover transparente', detail: `La caída de una instancia de ${label(c.targetId)} no afectó a los usuarios.`, nodeIds: [c.targetId] });
    else if (p.stateful && Number.isFinite(p.failoverTime)) out.push({ severity: 'warn', title: `Corte de ~${p.failoverTime} s durante el failover`, detail: `Mientras ${label(c.targetId)} promueve su réplica/standby, las operaciones que dependen de ella fallan. Usa reintentos en la aplicación${['rds', 'aurora'].includes(lid(c.map.get(c.targetId) as ServiceNode)) ? ' y RDS Proxy (reduce el failover a segundos)' : ''}.`, nodeIds: [c.targetId] });
  }
  if (sc.kind === 'node-outage' && c.targetId) {
    const affected = frames.find((f) => f.t >= sc.eventAt && f.t < sc.eventAt + sc.eventDuration);
    const impact = affected ? 1 - affected.success : 0;
    const n = c.map.get(c.targetId) as ServiceNode;
    const role = getService(n.data.serviceId).role;
    if (impact < 0.01) out.push({ severity: 'ok', title: `La caída de ${label(c.targetId)} no afecta a los usuarios`, detail: role === 'queue' || role === 'cache' ? 'Está fuera de la ruta crítica o la aplicación tiene alternativa.' : 'Ninguna operación síncrona depende de ella.', nodeIds: [c.targetId] });
    else out.push({ severity: impact > 0.5 ? 'error' : 'warn', title: `Radio de impacto: ${Math.round(impact * 100)}% de los requests fallan`, detail: `${label(c.targetId)} está en la ruta síncrona. ${role === 'external' || role === 'ai' ? 'Desacopla con una cola, timeouts cortos y circuit breaker.' : role === 'identity' ? 'Solo fallan los logins nuevos: los tokens ya emitidos se validan localmente.' : 'Considera degradación elegante (respuestas en caché, modo lectura) cuando falle.'}`, nodeIds: [c.targetId] });
  }
  if (sc.kind === 'az-failure') {
    const vpcSingle = c.services.some((n) => {
      const z = ancestors(n, c.map).find((x) => x.data.zoneKind === 'vpc');
      return z && Number(z.data.props.azs) < 2;
    });
    if (vpcSingle) out.push({ severity: 'error', title: 'La VPC usa una sola zona de disponibilidad', detail: 'Al caer esa AZ cae todo lo que está dentro de la VPC. Configura al menos 2 AZ.', nodeIds: [] });
  }

  // Failover a réplicas dibujadas
  for (const f of s.failovers ?? []) {
    if (f.ok)
      out.push({ severity: 'ok', title: `Failover a ${label(f.replicaId)} en ${fmtDur(f.rtoS)}`, detail: `${f.why} ${f.rpoS > 0 ? `Se pierden ~${fmtDur(f.rpoS)} de escrituras.` : 'Sin pérdida de datos.'} Mira en el lienzo cómo el tráfico de ${label(f.primaryId)} pasa a la réplica.`, nodeIds: [f.replicaId, f.primaryId] });
    else if (f.late) out.push({ severity: 'warn', title: `${label(f.replicaId)} no llegó a tomar el tráfico`, detail: `${label(f.primaryId)} volvió antes de que terminara la promoción. Con failover automático la réplica entra en segundos.`, nodeIds: [f.replicaId, f.primaryId] });
    else out.push({ severity: 'error', title: `${label(f.replicaId)} no sirve como failover en este escenario`, detail: `${f.why} Cambia el tipo de réplica en Resiliencia → Replicación y failover (p. ej. «copia aislada en otra cuenta» contra ransomware, «réplica con retraso» contra borrados).`, nodeIds: [f.replicaId, f.primaryId] });
  }
  if (c.suggested.length && ['instance-failure', 'az-failure', 'node-outage', 'region-failure', 'data-corruption', 'ransomware'].includes(sc.kind))
    for (const g of c.suggested) out.push({ severity: 'warn', title: `¿${label(g.replicaId)} es réplica de ${label(g.primaryId)}?`, detail: 'Están conectadas, pero no está configurado qué tipo de réplica es ni cómo hace failover, así que la simulación no la usa. Configúralo en ⛑ Resiliencia → Replicación y failover.', nodeIds: [g.replicaId, g.primaryId] });

  // Caída de región
  if (sc.kind === 'region-failure') {
    const dr = c.dr;
    const dns = c.dns;
    const dt = s.downtimeS ?? 0;
    const end = frames[frames.length - 1];
    const recovered = end.success >= 0.99;
    if (dr.strategy === 'none') {
      out.push({ severity: 'error', title: 'Sin plan de recuperación ante desastres', detail: 'Todo vive en una sola región: el servicio queda caído hasta que el proveedor la recupere (las caídas regionales reales han durado de horas a un día). Elige una estrategia en «Resiliencia y DR».', nodeIds: [] });
    } else {
      const slowest = [...c.regionSlow].sort((a, b) => b.back - a.back)[0];
      out.push({
        severity: recovered && dt <= dr.rtoMin * 60 ? 'ok' : recovered ? 'warn' : 'error',
        title: recovered ? `El servicio volvió en ${fmtDur(dt)} (objetivo ${dr.rtoMin} min)` : 'El servicio no vuelve durante la simulación',
        detail: recovered
          ? `Con «${dr.strategy}» el tráfico pasó a ${dr.secondaryRegion}.${slowest ? ` Lo que más tardó: ${label(slowest.id)} (${fmtDur(slowest.back)}).` : ''}`
          : `${c.regionNoCopy.length ? `${c.regionNoCopy.map(label).join(', ')} no tiene${c.regionNoCopy.length > 1 ? 'n' : ''} copia en ${dr.secondaryRegion}: sin datos, la región secundaria no puede atender.` : 'Alguna pieza crítica no tiene cómo volver en la región secundaria.'}`,
        nodeIds: c.regionNoCopy.length ? c.regionNoCopy : slowest ? [slowest.id] : [],
      });
      if (dns && !dns.automatic) out.push({ severity: 'warn', title: `El cambio de región depende de una persona (~${fmtDur(dns.seconds)})`, detail: dns.text + ' Configura Route 53 con política de failover (o latencia) y health checks para que sea automático.', nodeIds: dns.dnsId ? [dns.dnsId] : [] });
      else if (dns) out.push({ severity: 'ok', title: `DNS automático: ${fmtDur(dns.seconds)} para cambiar de región`, detail: dns.text, nodeIds: dns.dnsId ? [dns.dnsId] : [] });
      if (s.dataLossS !== undefined && s.dataLossS !== null) {
        if (!Number.isFinite(s.dataLossS)) out.push({ severity: 'error', title: 'Datos sin copia en otra región', detail: `${c.regionNoCopy.map(label).join(', ')}: si la región no vuelve, esos datos se pierden.`, nodeIds: c.regionNoCopy });
        else out.push({ severity: s.dataLossS <= dr.rpoMin * 60 ? 'ok' : 'warn', title: `Pérdida de datos estimada: ${fmtDur(s.dataLossS)} (objetivo ${dr.rpoMin} min)`, detail: s.dataLossS <= 1 ? 'La replicación entre regiones es casi síncrona.' : 'Es el retraso de la replicación (o de la última copia de backup) hacia la región secundaria.', nodeIds: [] });
      }
      if (dr.strategy === 'active') out.push({ severity: 'info', title: 'Activo‑activo: la otra región absorbe todo el tráfico', detail: 'Mientras el DNS detecta la caída, la mitad de las peticiones van a la región caída. Después, la región sana recibe el doble de carga: revisa que su autoescalado alcance.', nodeIds: [] });
    }
  }

  // Dependencia lenta
  if ((sc.kind === 'slow-dependency' || sc.kind === 'gameday') && c.slowTarget) {
    const window = frames.filter((f) => f.t >= c.slowFrom && f.t < c.slowTo);
    const minS = window.length ? Math.min(...window.map((f) => f.success)) : 1;
    if (!c.slowStats.size) out.push({ severity: 'ok', title: `Nadie espera a ${label(c.slowTarget)} en la ruta síncrona`, detail: 'La lentitud no se propaga: la pieza está detrás de una cola o fuera del camino de las peticiones.', nodeIds: [c.slowTarget] });
    for (const [id, st] of c.slowStats) {
      const who = label(id);
      if (st.breaker) out.push({ severity: 'ok', title: `${who}: el circuit breaker contuvo la falla`, detail: `A los ~10 s dejó de esperar a ${label(c.slowTarget)} y falla rápido solo en lo que la necesita; el resto de la aplicación sigue atendiendo.`, nodeIds: [id] });
      else if (st.minCap < 0.5)
        out.push({
          severity: 'error',
          title: `Falla en cascada: ${who} se quedó sin hilos (capacidad al ${Math.round(st.minCap * 100)} %)`,
          detail: `Cada petición espera ${st.timesOut ? `su timeout de ${st.timeout} ms${st.retries ? ` × ${st.attempts} intentos` : ''}` : `los ${sc.extraLatency} ms extra`}. Pon un timeout corto (≈ p99 de la dependencia), reintentos con backoff y jitter, y un circuit breaker (Resiliencia → Llamadas a dependencias).`,
          nodeIds: [id, c.slowTarget],
        });
      if (st.timesOut && st.attempts > 1 && !st.breaker) out.push({ severity: 'warn', title: `Tormenta de reintentos: ×${st.attempts} llamadas a ${label(c.slowTarget)}`, detail: `${who} reintenta ${st.retries} vez/veces cada llamada que vence. Justo cuando la dependencia está mal, recibe ${st.attempts} veces más carga. Limita los reintentos y usa backoff exponencial con un presupuesto de reintentos.`, nodeIds: [c.slowTarget] });
    }
    if (sc.kind === 'slow-dependency') out.push({ severity: minS >= 0.99 ? 'ok' : minS >= 0.8 ? 'warn' : 'error', title: `Durante la lentitud se atendió como mínimo el ${(minS * 100).toFixed(1)} % de los usuarios`, detail: minS >= 0.99 ? 'La aplicación absorbió la lentitud.' : 'Lo que no se atendió fueron peticiones que esperaron de más o que necesitaban a la dependencia.', nodeIds: [] });
  }

  // Corrupción / ransomware
  if ((sc.kind === 'data-corruption' || sc.kind === 'ransomware') && c.targetId && c.dataRestore) {
    const r = c.dataRestore;
    const id = c.targetId;
    if (sc.kind === 'data-corruption') {
      const rr = c.res.get(id)!;
      if (rr.azs >= 2 || rr.readReplicas > 0 || rr.crossRegion) out.push({ severity: 'info', title: 'Multi‑AZ y las réplicas no protegen de esto', detail: `${label(id)} tiene redundancia, pero copia el daño al instante. Contra errores humanos y bugs solo sirven los backups, PITR y el versionado.`, nodeIds: [id] });
      if ((s.corruptS ?? 0) > 0) out.push({ severity: 'warn', title: `Durante ${fmtDur(s.corruptS ?? 0)} se sirvieron datos dañados sin saberlo`, detail: 'Hasta que alguien lo notó. Alarmas sobre métricas de negocio (pedidos, pagos, errores 5xx) y validaciones de integridad acortan este tiempo.', nodeIds: [id] });
    }
    const fo = s.failovers?.find((f) => f.ok && f.primaryId === id);
    if (fo) out.push({ severity: 'ok', title: `El servicio sigue con ${label(fo.replicaId)} mientras se recupera ${label(id)}`, detail: fo.why, nodeIds: [fo.replicaId] });
    else if (!Number.isFinite(r.rtoS)) out.push({ severity: 'error', title: sc.kind === 'ransomware' ? 'Los datos se pierden: no hay copia fuera del alcance del atacante' : `${label(id)}: los datos no se pueden recuperar`, detail: r.text, nodeIds: [id] });
    else out.push({ severity: r.rtoS <= c.dr.rtoMin * 60 ? 'ok' : 'warn', title: `Restauración en ${fmtDur(r.rtoS)}; se pierden ${fmtDur(r.rpoS)} de datos`, detail: `${r.text}${sc.kind === 'data-corruption' ? ' Lo escrito entre el daño y la restauración hay que reconciliarlo a mano.' : ''}`, nodeIds: [id] });
  }

  // Game Day
  if (sc.kind === 'gameday') {
    const phase = (a: number, b: number) => {
      const fs = frames.filter((f) => f.t >= a && f.t < b);
      return fs.length ? Math.min(...fs.map((f) => f.success)) : 1;
    };
    const t0 = sc.eventAt;
    const ph = [
      { name: 'Pico de tráfico', v: phase(t0, t0 + 90) },
      { name: 'Pico + caída de AZ', v: phase(t0 + 90, t0 + 240) },
      { name: `Pico + AZ + ${c.slowTarget ? label(c.slowTarget) : 'dependencia'} lenta`, v: phase(t0 + 240, t0 + 420) },
      { name: 'Recuperación', v: phase(t0 + 420, sc.duration + 1) },
    ];
    const worst = ph.reduce((a, b) => (b.v < a.v ? b : a));
    out.push({ severity: worst.v >= 0.99 ? 'ok' : worst.v >= 0.9 ? 'warn' : 'error', title: worst.v >= 0.99 ? 'Pasó el Game Day' : `La fase más dura: ${worst.name} (${(worst.v * 100).toFixed(1)} % mínimo)`, detail: ph.map((x) => `${x.name}: ${(x.v * 100).toFixed(1)} %`).join(' · '), nodeIds: [] });
  }

  // Inspección con firewalls virtuales (GWLB)
  if (['web-attacks', 'scraping', 'ddos-l7', 'credential-stuffing'].includes(sc.kind))
    for (const [iid, ips] of c.ipsOf) {
      if (ips.mode === 'ips' && ips.sees) out.push({ severity: 'ok', title: `El IPS de ${label(ips.applianceId)} bloqueó ${Math.round(c.ipsBlocked).toLocaleString('es-CO')} peticiones maliciosas`, detail: `Inspecciona en ${label(iid)}, donde el tráfico ya viene en texto claro o lo descifra. Las firmas detienen exploits conocidos; los bots, el HTTP flood y el abuso de la lógica de negocio siguen siendo trabajo del WAF y del código.`, nodeIds: [ips.applianceId] });
      else if (ips.mode === 'ids') out.push({ severity: 'warn', title: `${label(ips.applianceId)} solo alerta (IDS)`, detail: 'En modo IDS ve los ataques pero no los detiene. Pásalo a IPS cuando las firmas estén afinadas, o asegúrate de que alguien responde las alertas.', nodeIds: [ips.applianceId] });
      else if (!ips.sees) out.push({ severity: 'warn', title: `${label(ips.applianceId)} está ciego ante HTTPS`, detail: `En ${label(iid)} el tráfico todavía va cifrado: el IPS solo ve IPs, puertos y el SNI. Activa el descifrado TLS (cuesta ~50 % de capacidad) o pon la inspección después del balanceador, donde el tráfico ya es texto claro.`, nodeIds: [ips.applianceId, iid] });
    }
  for (const [iid, fl] of c.fleetOf) {
    if (!fl.length) {
      out.push({ severity: 'warn', title: `${label(iid)} no tiene firewalls detrás`, detail: 'Conecta el Gateway Load Balancer a una flota de firewalls virtuales (NGFW / IDS‑IPS); sin ella no inspecciona nada.', nodeIds: [iid] });
      continue;
    }
    if (frames.some((f) => fl.every((a) => f.nodes[a]?.status === 'down')))
      out.push({ severity: 'error', title: `Sin firewalls sanos, se corta todo lo que pasa por ${label(iid)}`, detail: 'Toda la flota quedó fuera de servicio. Ojo: si los firewalls siguen vivos pero fallan el health check, el GWLB les sigue enviando tráfico (fail‑open) y podría pasar sin inspección. Pon una alarma sobre UnHealthyHostCount y reparte la flota en varias AZ.', nodeIds: [...fl, iid] });
  }

  // Ataques nuevos
  const sec = c.security;
  const T0 = c.targetId ? (c.map.get(c.targetId) as ServiceNode) : undefined;
  if (sc.kind === 'credential-stuffing' && T0) {
    const cognito = lid(T0) === 'cognito';
    const mfa = cognito ? String(T0.data.props.mfa ?? 'OPTIONAL') : 'OFF';
    if (s.impact) out.push({ severity: s.impact.tone === 'good' ? 'ok' : s.impact.tone === 'warn' ? 'warn' : 'error', title: `${s.impact.value} cuentas tomadas`, detail: s.impact.detail, nodeIds: [T0.id] });
    if (mfa !== 'ON') out.push({ severity: 'error', title: cognito ? `MFA ${mfa === 'OFF' ? 'apagado' : 'opcional'} en ${label(T0.id)}` : 'El login no tiene MFA', detail: 'Con MFA obligatorio una contraseña filtrada no basta para entrar. Es el control que más baja la toma de cuentas.', nodeIds: [T0.id] });
    if (!sec.captcha && !c.waf?.data.props.atp) out.push({ severity: 'warn', title: 'Nada frena a los bots en el login', detail: 'El rate limit por IP no ve un ataque repartido en miles de IPs. Agrega CAPTCHA/challenge en el login o WAF Account Takeover Prevention.', nodeIds: [T0.id] });
    if (cognito && (c.peakUtil.get(T0.id) ?? 0) > 1) out.push({ severity: 'error', title: `El ataque agota la cuota de ${label(T0.id)}`, detail: 'Cognito tiene una cuota de logins por segundo: los usuarios reales tampoco pueden entrar (denegación de servicio como efecto colateral).', nodeIds: [T0.id] });
  }
  if (sc.kind === 'scraping' && s.impact) {
    out.push({ severity: s.impact.tone === 'good' ? 'ok' : 'error', title: `${s.impact.value} registros de otros usuarios expuestos`, detail: `${s.impact.detail}${sec.objectAuthz ? '' : ' Verifica en cada consulta que el recurso pertenece al usuario (Seguridad del proyecto → Autorización por objeto).'}`, nodeIds: c.targetId ? [c.targetId] : [] });
    if (!c.waf?.data.props.botControl) out.push({ severity: 'warn', title: 'El scraping se reparte en muchas IPs', detail: 'Bot Control del WAF y límites por usuario (no solo por IP) en API Gateway frenan la enumeración.', nodeIds: c.waf ? [c.waf.id] : [] });
  }
  if (sc.kind === 'exfiltration' && c.exfil && s.impact) {
    const x = c.exfil;
    out.push({ severity: s.impact.tone === 'good' ? 'ok' : s.impact.tone === 'warn' ? 'warn' : 'error', title: `Salieron ${s.impact.value}`, detail: `${s.impact.detail} ${Number.isFinite(x.detect) ? `Se detectó a los ${fmtDur(x.detect)} y se contuvo ${fmtDur(x.respond)} después.` : 'Nadie lo detectó durante la simulación.'}`, nodeIds: c.targetId ? [c.targetId] : [] });
    if (x.egress === 'open') out.push({ severity: 'warn', title: 'Salida a Internet sin filtro', detail: 'El NAT Gateway deja salir a cualquier destino. Un Network Firewall con lista de dominios permitidos y VPC Endpoints para los servicios de AWS dejan al atacante sin camino directo.', nodeIds: [] });
    if (!Number.isFinite(x.detect)) out.push({ severity: 'error', title: 'Sin detección', detail: 'Agrega Amazon GuardDuty al diagrama y envía sus hallazgos al equipo (Seguridad del proyecto → Hallazgos enviados al equipo).', nodeIds: [] });
    else if (!sec.siem) out.push({ severity: 'warn', title: 'La alerta existe pero nadie la ve a tiempo', detail: 'Envía los hallazgos a un canal de guardia (EventBridge → SNS / SIEM) para contener en minutos y no en horas.', nodeIds: [] });
  }
  if (sc.kind === 'leaked-keys' && c.keys && s.impact) {
    const k = c.keys;
    if (k.noKeys) out.push({ severity: 'ok', title: 'No hay llaves de larga duración que filtrar', detail: 'El equipo entra por SSO (IAM Identity Center) con credenciales temporales.', nodeIds: [] });
    else {
      out.push({ severity: s.impact.tone === 'good' ? 'ok' : s.impact.tone === 'warn' ? 'warn' : 'error', title: `Costo del ataque: ${s.impact.value}`, detail: `${s.impact.detail} Extrapolado a un día sin revocarlas: ~US$${(k.rate * 24).toLocaleString('es-CO')}.`, nodeIds: [] });
      if (!sec.secretScan) out.push({ severity: 'warn', title: 'Sin escaneo de secretos', detail: 'Pre-commit y escaneo en CI (gitleaks, GitHub secret scanning) atrapan la llave antes de que salga; AWS además pone en cuarentena las llaves que aparecen en GitHub.', nodeIds: [] });
      if (!sec.scp) out.push({ severity: 'warn', title: 'Sin límites en la organización', detail: 'Una SCP que niegue regiones que no usas y tipos de instancia GPU baja el costo del ataque a una fracción.', nodeIds: [] });
      if (!sec.boundary) out.push({ severity: 'error', title: 'Las llaves también abren los datos', detail: 'Sin permission boundary, las llaves de un desarrollador suelen poder leer S3, DynamoDB y Secrets Manager. Mira «▶ Simular → Ataque → Llaves filtradas».', nodeIds: [] });
      if (!sec.rootMfa) out.push({ severity: 'info', title: 'La solución de fondo: no tener access keys', detail: 'Acceso humano por SSO con MFA y credenciales temporales (Seguridad del proyecto).', nodeIds: [] });
    }
  }

  // Seguridad: DDoS
  const tgt = c.targetId ? (c.map.get(c.targetId) as ServiceNode) : undefined;
  if (sc.kind === 'ddos-l7' && tgt) {
    const a = s.attack!;
    const blockedPct = a.sent > 0 ? a.blocked / a.sent : 0;
    const absorbedPct = a.sent > 0 ? a.absorbed / a.sent : 0;
    if (!c.waf) {
      const viaCdn = c.edges.some((e) => e.target === tgt.id && lid(c.map.get(e.source) as ServiceNode) === 'cloudfront');
      out.push({ severity: 'error', title: `${label(tgt.id)} no tiene WAF`, detail: `El 100% del flood pasó la entrada${absorbedPct > 0 ? ` (la CDN absorbió ${Math.round(absorbedPct * 100)}% desde caché)` : ''}. Asocia un WAF con regla de rate limit${viaCdn ? ' y restringe el origen para que solo acepte tráfico de CloudFront' : ''}.`, nodeIds: [tgt.id] });
    } else {
      const perIp = sc.attackRps / Math.max(1, sc.botIps);
      const rl = Number(c.waf.data.props.rateLimit) || 2000;
      out.push({ severity: blockedPct > 0.9 ? 'ok' : blockedPct > 0.5 ? 'warn' : 'error', title: `El WAF bloqueó ${Math.round(blockedPct * 100)}% del ataque`, detail: perIp * 300 > rl ? `Cada IP superó el límite (${Math.round(perIp * 300)} vs ${rl} req/5 min). Los primeros ~30 s, antes de la detección, sí pasaron.` : `Ataque distribuido: cada IP envía solo ${Math.round(perIp * 300)} req/5 min, por debajo del límite de ${rl}. ${c.waf.data.props.botControl ? 'Bot Control ayudó parcialmente.' : 'Activa Bot Control,'} ${c.shieldAdv ? '' : 'considera Shield Advanced (mitigación automática L7)'} o baja el límite para rutas sensibles.`, nodeIds: [c.waf.id] });
    }
    if (s.lambdaCostUsd && s.lambdaCostUsd > 0.01) out.push({ severity: 'warn', title: `Costo del ataque en Lambda: ~US$${s.lambdaCostUsd.toFixed(2)}`, detail: `El flood que llegó al backend generó invocaciones pagas ("denial of wallet"). Extrapolado a 24 h: ~US$${((s.lambdaCostUsd * 86400) / Math.max(1, sc.eventDuration)).toFixed(0)}.`, nodeIds: [] });
    const apigw = c.services.find((n) => lid(n) === 'apigw' && (c.peakUtil.get(n.id) ?? 0) > 1);
    if (apigw) out.push({ severity: 'warn', title: 'API Gateway throttleó (HTTP 429)', detail: 'El throttling protege al backend, pero también rechaza a usuarios legítimos: el ataque igual causa denegación de servicio.', nodeIds: [apigw.id] });
  }
  if (sc.kind === 'ddos-l34' && tgt) {
    if (c.l34Mitigated) out.push({ severity: 'ok', title: `${label(tgt.id)} está protegido por Shield Standard`, detail: `AWS absorbe los ataques volumétricos L3/L4 contra ${getService(tgt.data.serviceId).name} sin costo extra. ${c.services.some((n) => lid(n) === 'shield') ? 'Shield Advanced además cubre los costos de escalado y da acceso al equipo de respuesta (SRT).' : 'Shield Advanced agrega protección de costos y el equipo de respuesta de AWS (SRT).'}`, nodeIds: [tgt.id] });
    else out.push({ severity: 'error', title: `${label(tgt.id)} queda expuesto a ataques volumétricos`, detail: 'Recibe tráfico directo de Internet sin CloudFront, balanceador ni API Gateway delante. Pon un punto de entrada administrado.', nodeIds: [tgt.id] });
  }

  // Seguridad: ataques web
  if (sc.kind === 'web-attacks' && tgt) {
    const pf = s.attack?.perFlow ?? [];
    if (!c.waf) out.push({ severity: 'error', title: `${label(tgt.id)} no tiene WAF`, detail: 'Todos los payloads maliciosos llegan a la aplicación. La única defensa es el código (validación y consultas parametrizadas).', nodeIds: [tgt.id] });
    for (const f of pf) {
      const passed = f.sent > 0 ? 1 - f.blocked / f.sent : 0;
      const name = FLOW_LABEL[f.flow];
      if (passed <= 0.05) out.push({ severity: 'ok', title: `${name}: ${Math.round((1 - passed) * 100)}% bloqueado`, detail: 'Las reglas del WAF detienen este tipo de ataque en el borde.', nodeIds: c.waf ? [c.waf.id] : [] });
      else {
        const why = !c.waf
          ? ''
          : f.flow === 'sqli' ? (c.waf?.data.props.sqliRules ? '' : 'Activa el grupo de reglas de inyección SQL. ')
          : f.flow === 'bots' ? (c.waf?.data.props.botControl ? '' : 'Activa Bot Control; el rate limit solo frena bots muy agresivos. ')
          : c.waf?.data.props.managedRules ? '' : 'Activa el Core Rule Set (OWASP). ';
        const code =
          f.flow === 'sqli'
            ? f.toData > 0
              ? 'Estos payloads alcanzan consultas a la base de datos: usa consultas parametrizadas y mínimo privilegio en el usuario de BD.'
              : 'Usa consultas parametrizadas en la aplicación.'
            : f.flow === 'xss'
              ? 'Codifica la salida (output encoding) y define una Content‑Security‑Policy.'
              : f.flow === 'lfi'
                ? 'Valida y normaliza rutas; nunca construyas rutas de archivo con entrada del usuario.'
                : 'Agrega CAPTCHA/challenge en rutas sensibles (login, registro, búsqueda).';
        out.push({ severity: passed > 0.5 ? 'error' : 'warn', title: `${name}: ${Math.round(passed * 100)}% llega a la aplicación`, detail: `${why}${code}`, nodeIds: c.waf ? [c.waf.id] : [tgt.id] });
      }
    }
    out.push({ severity: 'info', title: 'El WAF no reemplaza el código seguro', detail: 'Las reglas administradas detectan patrones conocidos; ataques ofuscados o de lógica de negocio requieren validación en la aplicación.', nodeIds: [] });
  }

  for (const w of c.warnings) out.unshift({ severity: 'info', title: 'Nota', detail: w, nodeIds: [] });
  const order = { error: 0, warn: 1, info: 2, ok: 3 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}
