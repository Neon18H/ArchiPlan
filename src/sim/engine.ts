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
import { getService } from '../catalog/catalog';
import { ancestors, byId, isService, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, Role, ServiceNode } from '../types';
import { fmtRps, profileFor, type SimProfile } from './profiles';
import type { Scenario } from './scenarios';

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
const ROUTERS: Role[] = ['cdn', 'lb', 'api', 'dns'];
const MESSAGING: Role[] = ['queue', 'topic', 'eventbus', 'stream', 'workflow'];

function sourceWeight(n: ServiceNode) {
  return { user: 1, admin: 0.05, external: 0.2, onprem: 0.2 }[n.data.serviceId] ?? 0.2;
}

function classify(s: ServiceNode, t: ServiceNode, ps: SimProfile, pt: SimProfile): { kind: EdgeKind | 'entry' | 'login'; w: number } | null {
  const sd = getService(s.data.serviceId);
  const td = getService(t.data.serviceId);
  if (td.role === 'actor') return null;
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
  if (kind === 'node-outage') {
    return (services.find((n) => role(n) === 'external' && edges.some((e) => e.target === n.id)) ?? services.find((n) => role(n) === 'datastore') ?? services.find((n) => role(n) === 'compute'))?.id ?? null;
  }
  // Punto de entrada: el primer destino del usuario (resolviendo el DNS)
  const user = services.find((n) => n.data.serviceId === 'user') ?? services.find((n) => role(n) === 'actor' || role(n) === 'external');
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
  if (kind === 'instance-failure') return services.filter((n) => getService(n.data.serviceId).vpcBound && !['lb', 'netgw'].includes(role(n)) || profileFor(n).stateful);
  if (kind === 'node-outage') return services.filter((n) => !['actor'].includes(role(n)) && !profileFor(n).passive);
  return services.filter((n) => ['cdn', 'lb', 'api', 'compute', 'external'].includes(role(n)) && n.data.serviceId !== 'lambda');
}

/* ───────────────────────────── simulación */

export function simulate(nodes: AppNode[], edges: AppEdge[], sc: Scenario): SimResult {
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const svcIds = new Set(services.map((n) => n.id));
  const prof = new Map<string, SimProfile>(services.map((n) => [n.id, profileFor(n)]));
  const def = (id: string) => getService((map.get(id) as ServiceNode).data.serviceId);
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
  const capacity = (id: string, t: number) => {
    const p = prof.get(id)!;
    if (p.passive) return Infinity;
    if (isDown(id, t)) return 0;
    const s = st.get(id)!;
    const healthy = Math.max(0, s.instances - s.lost);
    if (p.scale === 'instant') return healthy > 0 ? p.perInstance : 0;
    return p.perInstance * healthy;
  };
  const cacheHit = (id: string, t: number) => {
    if (isDown(id, t)) return 0;
    const s = st.get(id)!;
    if (t >= s.coldFrom && t < s.coldUntil && s.coldFrom >= 0) return CACHE_HIT * ((t - s.coldFrom) / (s.coldUntil - s.coldFrom));
    return CACHE_HIT;
  };

  // ── 4. Objetivo y eventos del escenario
  const autoTarget = sc.kind === 'load' || sc.kind === 'spike' || sc.kind === 'az-failure' ? null : pickDefaultTarget(nodes, edges, sc.kind);
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
  const loseInstances = (id: string, k: number, t: number, cause: string) => {
    const p = prof.get(id)!;
    const s = st.get(id)!;
    const healthyBefore = s.instances - s.lost;
    k = Math.min(k, healthyBefore);
    if (k <= 0) return;
    if (p.stateful) {
      // Cae el primario (o el nodo): hay corte hasta el failover
      if (Number.isFinite(p.failoverTime)) {
        down(id, t, t + p.failoverTime, `${cause} — failover en curso`, healthyBefore > 1 ? 'failover completo, réplica promovida' : 'servicio restablecido');
        if (healthyBefore > 1) s.lost += Math.min(k, healthyBefore - 1);
        if (getService((map.get(id) as ServiceNode).data.serviceId).role === 'cache' && healthyBefore <= 1) {
          s.coldFrom = t + p.failoverTime;
          s.coldUntil = t + p.failoverTime + 120;
        }
      } else {
        down(id, t, Infinity, `${cause} — sin réplica ni Multi‑AZ, queda fuera de servicio`);
      }
      return;
    }
    s.lost += k;
    s.undetectedUntil = t + UNDETECTED;
    s.undetectedFrac = k / Math.max(1, healthyBefore);
    events.push({ t, label: `${label(id)}: ${cause} (${s.instances - s.lost}/${s.instances} sanas)`, kind: 'bad', nodeId: id });
    events.push({ t: t + UNDETECTED, label: `${label(id)}: el health check saca la instancia del balanceo`, kind: 'info', nodeId: id });
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
  if (sc.kind === 'node-outage' && targetId) down(targetId, t0, t1, 'deja de responder', 'vuelve a responder');
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
  const waf = protectors.find((n) => n.data.serviceId === 'waf');
  const shieldAdv = protectors.find((n) => n.data.serviceId === 'shield');
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
    if (shieldAdv && waf && flow === FLOOD && since >= 120) pass *= 0.1;
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
      if (p.passive || ['lb', 'netgw'].includes(d.role) || n.data.serviceId === 'lambda') continue;
      const vpc = ancestors(n, map).find((z) => z.data.zoneKind === 'vpc');
      const azs = Number(vpc?.data.props.azs ?? 2);
      if (azs < 2) {
        down(n.id, t, Infinity, 'la VPC solo usa una AZ y esa AZ cayó');
        continue;
      }
      const s = st.get(n.id)!;
      const N = s.instances - s.lost;
      if (p.stateful) {
        if (p.multiAz) loseInstances(n.id, Math.max(1, Math.floor(N / 2)), t, 'la AZ del primario cayó');
        else down(n.id, t, Infinity, 'estaba en una sola AZ (sin Multi‑AZ / réplica)');
      } else {
        loseInstances(n.id, N >= 2 ? Math.floor(N / 2) : 1, t, 'pierde las instancias de la AZ caída');
      }
    }
  };

  const legitAt = (t: number) => {
    switch (sc.kind) {
      case 'load':
        return sc.baseRps + (sc.peakRps - sc.baseRps) * Math.min(1, t / Math.max(1, sc.duration * 0.85));
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
  let lambdaGbSeconds = 0;
  let peakLambdaConc = 0;
  let lambdaToRdsMaxConn = Infinity;
  const lambdaToRds = services.filter((n) => n.data.serviceId === 'lambda' && (outE.get(n.id) ?? []).some((e) => ['rds', 'aurora'].includes((map.get(e.t) as ServiceNode).data.serviceId)));
  for (const l of lambdaToRds) {
    for (const e of outE.get(l.id) ?? []) {
      const tgt = map.get(e.t) as ServiceNode;
      if (['rds', 'aurora'].includes(tgt.data.serviceId)) lambdaToRdsMaxConn = Math.min(lambdaToRdsMaxConn, Math.round(prof.get(tgt.id)!.perInstance / 3.5));
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
      if (sc.kind === 'ddos-l7') o[FLOOD] += sc.attackRps;
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
          const add = offered.get(e.t)!;
          let r = 0;
          let a = 0;
          for (let f = 0; f < F; f++) {
            const v = out[f] * w;
            add[f] += v;
            r += v;
            if (f > 0) a += v;
          }
          edgesF[e.id] = { rps: r, attack: a };
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
      if (d.role === 'compute') {
        for (let f = 1; f < F; f++) perFlow[f].toApp += o[f] * DT;
        attackTotals.toApp += attack * DT;
      }
      if (['datastore', 'search'].includes(d.role)) for (let f = 2; f < F; f++) perFlow[f].toData += o[f] * DT;
      if (map.get(id) && (map.get(id) as ServiceNode).data.serviceId === 'lambda') {
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
        if (u > 0.7 && s.instances < p.maxInstances) {
          const want = Math.min(p.maxInstances, Math.max(s.instances + 1, Math.ceil(total / (p.perInstance * 0.6)) + s.lost));
          s.pending = { at: t + p.scaleDelay, to: want };
          events.push({ t, label: `${label(id)}: utilización ${Math.round(u * 100)}% → escala a ${want} ${p.scale === 'serverless-db' ? 'ACU (×)' : 'instancias'} (listas en ~${p.scaleDelay} s)`, kind: 'info', nodeId: id });
        } else if (u > 1 && s.instances >= p.maxInstances && !s.pending) {
          s.pending = { at: t + 120, to: s.instances }; // evita repetir el aviso cada paso
          events.push({ t, label: `${label(id)}: llegó al máximo de ${p.maxInstances} instancias y sigue saturado`, kind: 'bad', nodeId: id });
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
      if (d.role === 'queue') {
        ok = 1;
      } else if (ROUTERS.includes(d.role)) {
        const routes = outs.filter((e) => e.kind === 'route');
        if (routes.length) {
          let acc = 0;
          let la = 0;
          for (const e of routes) {
            const miss = d.role === 'cdn' ? (def(e.t).role === 'storage' ? CDN_MISS_STATIC : CDN_MISS_DYNAMIC) : 1;
            acc += (1 / routes.length) * ((1 - miss) + miss * (succ.get(e.t) ?? sfEff.get(e.t) ?? 1));
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
          if (e.kind === 'sync') {
            ok *= depOk(w, succ.get(e.t) ?? 1);
            l += Math.min(w, 1) * (lat.get(e.t) ?? 0);
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
        legitOk += (share / entries.length) * (succ.get(e) ?? 0);
        latAcc += (share / entries.length) * (lat.get(e) ?? 0);
        latW += share / entries.length;
      }
      for (const id of loginEdges.get(src) ?? []) legitOk += share * LOGIN_RATIO * (succ.get(id) ?? 0);
    }
    const attackSent = (sc.kind === 'ddos-l7' || sc.kind === 'web-attacks') && targetId && inWindow(t) ? (sc.kind === 'ddos-l7' ? sc.attackRps : sc.sqliRps + sc.xssRps + sc.lfiRps + sc.botsRps) : 0;
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
    ...(sc.kind === 'ddos-l7' || sc.kind === 'web-attacks' ? { attack: { ...attackTotals, perFlow: perFlow.slice(1).filter((f) => f.sent > 0) } } : {}),
    ...(lambdaCost > 0 ? { lambdaCostUsd: lambdaCost } : {}),
  };

  const findings = buildFindings({ sc, summary, frames, peakUtil, prof, map, targetId, waf, shieldAdv, perFlow, l34Mitigated, peakLambdaConc, lambdaToRdsMaxConn, services, outE, edges, warnings });
  return { scenario: sc, targetId, frames, events, summary, findings, warnings };
}

/* ───────────────────────────── hallazgos */

function recommendFor(n: ServiceNode, p: SimProfile): string {
  const id = n.data.serviceId;
  switch (id) {
    case 'ec2':
      return n.data.props.autoscaling ? `Aumenta el máximo del Auto Scaling Group (hoy ${p.maxInstances}) o usa instancias más grandes; el escalado tarda ~3 min, considera escalado predictivo.` : 'Activa Auto Scaling y usa al menos 2 instancias en AZ distintas.';
    case 'ecs':
    case 'eks':
    case 'apprunner':
      return `Sube el máximo de tareas/nodos (hoy ${p.maxInstances}) o la CPU por tarea.`;
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
  const hot = [...c.peakUtil.entries()].filter(([id, u]) => u > 1 && !c.prof.get(id)!.passive).sort((a, b) => b[1] - a[1]).slice(0, 4);
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
    if (endsDown && sc.kind !== 'node-outage' && sc.kind !== 'ddos-l34') out.push({ severity: 'error', title: `${label(n.id)} es un punto único de falla`, detail: 'Cayó y no se recuperó: no tiene réplica, Multi‑AZ ni Auto Scaling que la reemplace.', nodeIds: [n.id] });
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
    else if (p.stateful && Number.isFinite(p.failoverTime)) out.push({ severity: 'warn', title: `Corte de ~${p.failoverTime} s durante el failover`, detail: `Mientras ${label(c.targetId)} promueve su réplica/standby, las operaciones que dependen de ella fallan. Usa reintentos en la aplicación${['rds', 'aurora'].includes((c.map.get(c.targetId) as ServiceNode).data.serviceId) ? ' y RDS Proxy (reduce el failover a segundos)' : ''}.`, nodeIds: [c.targetId] });
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

  // Seguridad: DDoS
  const tgt = c.targetId ? (c.map.get(c.targetId) as ServiceNode) : undefined;
  if (sc.kind === 'ddos-l7' && tgt) {
    const a = s.attack!;
    const blockedPct = a.sent > 0 ? a.blocked / a.sent : 0;
    const absorbedPct = a.sent > 0 ? a.absorbed / a.sent : 0;
    if (!c.waf) {
      const viaCdn = c.edges.some((e) => e.target === tgt.id && (c.map.get(e.source) as ServiceNode)?.data?.serviceId === 'cloudfront');
      out.push({ severity: 'error', title: `${label(tgt.id)} no tiene WAF`, detail: `El 100% del flood pasó la entrada${absorbedPct > 0 ? ` (la CDN absorbió ${Math.round(absorbedPct * 100)}% desde caché)` : ''}. Asocia un WAF con regla de rate limit${viaCdn ? ' y restringe el origen para que solo acepte tráfico de CloudFront' : ''}.`, nodeIds: [tgt.id] });
    } else {
      const perIp = sc.attackRps / Math.max(1, sc.botIps);
      const rl = Number(c.waf.data.props.rateLimit) || 2000;
      out.push({ severity: blockedPct > 0.9 ? 'ok' : blockedPct > 0.5 ? 'warn' : 'error', title: `El WAF bloqueó ${Math.round(blockedPct * 100)}% del ataque`, detail: perIp * 300 > rl ? `Cada IP superó el límite (${Math.round(perIp * 300)} vs ${rl} req/5 min). Los primeros ~30 s, antes de la detección, sí pasaron.` : `Ataque distribuido: cada IP envía solo ${Math.round(perIp * 300)} req/5 min, por debajo del límite de ${rl}. ${c.waf.data.props.botControl ? 'Bot Control ayudó parcialmente.' : 'Activa Bot Control,'} ${c.shieldAdv ? '' : 'considera Shield Advanced (mitigación automática L7)'} o baja el límite para rutas sensibles.`, nodeIds: [c.waf.id] });
    }
    if (s.lambdaCostUsd && s.lambdaCostUsd > 0.01) out.push({ severity: 'warn', title: `Costo del ataque en Lambda: ~US$${s.lambdaCostUsd.toFixed(2)}`, detail: `El flood que llegó al backend generó invocaciones pagas ("denial of wallet"). Extrapolado a 24 h: ~US$${((s.lambdaCostUsd * 86400) / Math.max(1, sc.eventDuration)).toFixed(0)}.`, nodeIds: [] });
    const apigw = c.services.find((n) => n.data.serviceId === 'apigw' && (c.peakUtil.get(n.id) ?? 0) > 1);
    if (apigw) out.push({ severity: 'warn', title: 'API Gateway throttleó (HTTP 429)', detail: 'El throttling protege al backend, pero también rechaza a usuarios legítimos: el ataque igual causa denegación de servicio.', nodeIds: [apigw.id] });
  }
  if (sc.kind === 'ddos-l34' && tgt) {
    if (c.l34Mitigated) out.push({ severity: 'ok', title: `${label(tgt.id)} está protegido por Shield Standard`, detail: `AWS absorbe los ataques volumétricos L3/L4 contra ${getService(tgt.data.serviceId).name} sin costo extra. ${c.services.some((n) => n.data.serviceId === 'shield') ? 'Shield Advanced además cubre los costos de escalado y da acceso al equipo de respuesta (SRT).' : 'Shield Advanced agrega protección de costos y el equipo de respuesta de AWS (SRT).'}`, nodeIds: [tgt.id] });
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
