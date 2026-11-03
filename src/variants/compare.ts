import { buildPlan, DEFAULT_DR, type DrConfig } from '../resilience/model';
/**
 * Compara variantes del diseño corriendo las mismas pruebas a cada una: simulaciones de
 * carga y fallas, peticiones de usuario, modelo de amenazas, análisis de red, validación,
 * costo estimado y complejidad. Calcula un puntaje por pilar y uno total ponderado.
 */
import { getService, lid } from '../catalog/catalog';
import { estimateCost, type CostItem } from '../cost/model';
import { isService } from '../lib/graph';
import { analyzeNetwork } from '../net/reach';
import { REQUESTS, traceRequest } from '../net/trace';
import { validate } from '../rules/validate';
import { simulate } from '../sim/engine';
import { defaultScenario, SCENARIO_MAP, type ScenarioKind } from '../sim/scenarios';
import { buildThreats } from '../threats/model';
import type { AppEdge, AppNode, ConnData, ServiceNode, Variant } from '../types';

export type Pillar = 'disponibilidad' | 'rendimiento' | 'seguridad' | 'costo' | 'operacion' | 'salud';

export const PILLARS: { id: Pillar; label: string; help: string }[] = [
  { id: 'disponibilidad', label: 'Disponibilidad', help: 'Cómo aguanta caídas de instancias, de una AZ y de dependencias.' },
  { id: 'rendimiento', label: 'Rendimiento', help: 'Latencia p95 y éxito bajo carga y picos.' },
  { id: 'seguridad', label: 'Seguridad', help: 'Amenazas abiertas, ataques simulados y peticiones sin autenticación.' },
  { id: 'costo', label: 'Costo', help: 'Costo mensual estimado (la más barata = 100).' },
  { id: 'operacion', label: 'Operación', help: 'Complejidad: cuántas piezas y de qué tipo hay que operar.' },
  { id: 'salud', label: 'Salud del diseño', help: 'Errores de validación, conexiones bloqueadas y peticiones que fallan.' },
];

export type Weights = Record<Pillar, number>;

export const WEIGHT_PRESETS: { id: string; label: string; weights: Weights }[] = [
  { id: 'equilibrado', label: 'Equilibrado', weights: { disponibilidad: 25, rendimiento: 10, seguridad: 25, costo: 20, operacion: 10, salud: 10 } },
  { id: 'startup', label: 'Startup (costo y simplicidad)', weights: { disponibilidad: 15, rendimiento: 10, seguridad: 15, costo: 35, operacion: 20, salud: 5 } },
  { id: 'regulado', label: 'Banca / regulado', weights: { disponibilidad: 30, rendimiento: 5, seguridad: 40, costo: 5, operacion: 10, salud: 10 } },
  { id: 'trafico', label: 'Alto tráfico', weights: { disponibilidad: 30, rendimiento: 30, seguridad: 15, costo: 15, operacion: 5, salud: 5 } },
];

const FAILURE_SCENARIOS: ScenarioKind[] = ['instance-failure', 'az-failure', 'node-outage'];
const FAILURE_LABEL: Partial<Record<ScenarioKind, string>> = { 'instance-failure': 'Cae una instancia', 'az-failure': 'Cae una zona (AZ)', 'node-outage': 'Falla la dependencia principal' };

export interface VariantMetrics {
  id: string;
  name: string;
  note?: string;
  pieces: number;
  serviceTypes: number;
  connections: number;
  availability: { kind: ScenarioKind; label: string; value: number }[];
  availFailures: number;
  p95Load: number;
  p95Spike: number;
  successSpike: number;
  battery: { id: string; label: string; ok: boolean; status: string }[];
  attack: { webBlockedPct: number | null; ddosAvail: number };
  validation: { errors: number; warns: number };
  blocked: number;
  threats: { critical: number; high: number; medium: number; low: number; open: number; total: number };
  cost: { total: number; perMillion: number; items: CostItem[] };
  complexity: { points: number; label: 'Baja' | 'Media' | 'Alta' };
  /** RTO/RPO estimados por el plan de resiliencia (s). */
  recovery: { region: { rtoS: number; rpoS: number }; data: { rtoS: number; rpoS: number }; ransomware: { rtoS: number; rpoS: number } };
  scores: Record<Pillar, number>;
  total: number;
}

const clamp = (v: number) => Math.max(0, Math.min(100, Math.round(v)));

/** Disponibilidad medida en la ventana de la simulación: 90 % → 0, 95 % → 50, 100 % → 100. */
const availScore = (a: number) => clamp(((a - 0.9) / 0.1) * 100);
/** Peso de cada escenario de falla en el promedio (la caída de la dependencia principal es la menos probable). */
const FAILURE_WEIGHT: Record<string, number> = { 'instance-failure': 0.4, 'az-failure': 0.4, 'node-outage': 0.2 };

/** Peso operativo de cada tipo de pieza (servidores propios pesan más que servicios administrados). */
const OPS_WEIGHT: Record<string, number> = {
  ec2: 3, eks: 4, ecs: 2, beanstalk: 2, lightsail: 2, apprunner: 1, lambda: 1, batch: 1.5,
  rds: 2, aurora: 1.5, documentdb: 2, opensearch: 2.5, elasticache: 1.5, memorydb: 1.5, msk: 3, kinesis: 1.5, redshift: 2.5, neptune: 2, mq: 2, emr: 3,
  dynamodb: 0.5, s3: 0.3, sqs: 0.5, sns: 0.5, eventbridge: 0.7, stepfunctions: 1,
  natgw: 0.5, alb: 0.5, nlb: 0.5, cloudfront: 0.5, apigw: 0.7, waf: 0.7, cognito: 1, vpn: 1.5, transitgw: 1.5, networkfirewall: 1.5,
};

function complexity(nodes: AppNode[], edges: AppEdge[]) {
  const svcs = nodes.filter(isService).filter((n) => !['actor', 'external'].includes(getService(n.data.serviceId).role));
  const types = new Set(svcs.map((n) => lid(n)));
  const asyncEdges = edges.filter((e) => (e.data as ConnData | undefined)?.async).length;
  const points = svcs.reduce((a, n) => a + (OPS_WEIGHT[lid(n)] ?? 0.4), 0) + edges.length * 0.2 + asyncEdges * 0.4 + types.size * 0.3;
  return { points: Math.round(points * 10) / 10, label: (points <= 12 ? 'Baja' : points <= 24 ? 'Media' : 'Alta') as 'Baja' | 'Media' | 'Alta', types: types.size, pieces: svcs.length };
}

export function evaluateVariant(v: Variant, opts: { security: Record<string, boolean>; avgRps: number; respKb?: number; dr?: DrConfig }): Omit<VariantMetrics, 'scores' | 'total'> & { rawCost: number } {
  const { nodes, edges, securityGroups } = v;
  const blocked = new Map<string, string>();
  const net = analyzeNetwork(nodes, edges, securityGroups);
  for (const x of net.verdicts.values()) if (!x.ok) blocked.set(x.edgeId, x.summary);
  const run = (kind: ScenarioKind, patch: Partial<ReturnType<typeof defaultScenario>> = {}) => simulate(nodes, edges, { ...defaultScenario(kind), ...patch }, { blocked });

  // Disponibilidad ante fallas
  const availability = FAILURE_SCENARIOS.map((kind) => ({ kind, label: FAILURE_LABEL[kind] ?? SCENARIO_MAP[kind].label, value: run(kind).summary.availability }));
  const availFailures = availability.reduce((a, x) => a + x.value * (FAILURE_WEIGHT[x.kind] ?? 0), 0);

  // Rendimiento
  const load = run('load');
  const spike = run('spike');

  // Costo con el tráfico promedio (un escenario de carga plana para saber qué recibe cada pieza)
  const flat = run('load', { baseRps: opts.avgRps, peakRps: opts.avgRps, duration: 120 });
  const perNode = new Map<string, number>();
  for (const f of flat.frames) for (const [id, nf] of Object.entries(f.nodes)) perNode.set(id, (perNode.get(id) ?? 0) + nf.offered / flat.frames.length);
  const respKb = opts.respKb ?? 20;
  const items = nodes.filter(isService).map((n) => estimateCost(n as ServiceNode, perNode.get(n.id) ?? 0, { respKb }));
  // Transferencia a Internet: si no hay CDN delante, la paga el punto de entrada (la CDN ya incluye la suya)
  const hasCdnEntry = nodes.filter(isService).some((n) => getService(n.data.serviceId).role === 'cdn' && (perNode.get(n.id) ?? 0) > 0);
  if (!hasCdnEntry && opts.avgRps > 0) {
    const gb = (opts.avgRps * 2.628e6 * respKb) / 1e6;
    items.push({ nodeId: '', label: 'Transferencia a Internet', monthly: Math.max(0, gb - 100) * 0.09, basis: `~${Math.round(gb).toLocaleString('es-CO')} GB de respuestas (${respKb} KB c/u; 100 GB gratis)` });
  }
  const total = items.reduce((a, i) => a + i.monthly, 0);

  // Seguridad
  const web = run('web-attacks');
  const ddos = run('ddos-l7');
  const tm = buildThreats(nodes, edges, {}, { security: opts.security, securityGroups });
  const open = tm.threats.filter((t) => t.status === 'abierta' || t.status === 'parcial');
  const battery = REQUESTS.map((r) => {
    const t = traceRequest(nodes, edges, securityGroups, { kind: r.id }, net);
    return { id: r.id, label: r.label, ok: t.asExpected, status: t.outcome === 'na' ? 'N/A' : t.status ? String(t.status) : t.statusText };
  });
  const issues = validate(nodes, edges);
  const cx = complexity(nodes, edges);
  const atk = web.summary.attack;
  const plan = buildPlan(nodes, edges, { dr: opts.dr ?? DEFAULT_DR, security: opts.security });
  const rr = (t: { rtoS: number; rpoS: number }) => ({ rtoS: t.rtoS, rpoS: t.rpoS });

  return {
    id: v.id,
    name: v.name,
    note: v.note,
    pieces: cx.pieces,
    serviceTypes: cx.types,
    connections: edges.length,
    availability,
    availFailures,
    p95Load: load.summary.p95Latency,
    p95Spike: spike.summary.p95Latency,
    successSpike: spike.summary.availability,
    battery,
    attack: { webBlockedPct: atk && atk.sent > 0 ? atk.blocked / atk.sent : null, ddosAvail: ddos.summary.availability },
    validation: { errors: issues.filter((i) => i.severity === 'error').length, warns: issues.filter((i) => i.severity === 'warn').length },
    blocked: blocked.size,
    recovery: { region: rr(plan.totals.region), data: rr(plan.totals.data), ransomware: rr(plan.totals.ransomware) },
    threats: {
      critical: open.filter((t) => t.risk === 'Crítico').length,
      high: open.filter((t) => t.risk === 'Alto').length,
      medium: open.filter((t) => t.risk === 'Medio').length,
      low: open.filter((t) => t.risk === 'Bajo').length,
      open: open.length,
      total: tm.threats.length,
    },
    cost: { total, perMillion: opts.avgRps > 0 ? total / ((opts.avgRps * 2.628e6) / 1e6) : 0, items: items.filter((i) => i.monthly > 0.01).sort((a, b) => b.monthly - a.monthly) },
    complexity: { points: cx.points, label: cx.label },
    rawCost: total,
  };
}

export interface Comparison {
  metrics: VariantMetrics[];
  winnerId: string;
  weights: Weights;
  avgRps: number;
}

export function compareVariants(variants: Variant[], opts: { security: Record<string, boolean>; avgRps: number; respKb?: number; weights: Weights; dr?: DrConfig }): Comparison {
  const raw = variants.map((v) => evaluateVariant(v, opts));
  const cheapest = Math.min(...raw.map((r) => r.rawCost).filter((c) => c > 0), Infinity);
  const metrics: VariantMetrics[] = raw.map((r) => {
    const funcFails = r.battery.filter((b) => !b.ok && ['browse', 'api', 'login'].includes(b.id)).length;
    const secFails = r.battery.filter((b) => !b.ok && ['api-noauth', 'sqli'].includes(b.id)).length;
    const scores: Record<Pillar, number> = {
      disponibilidad: availScore(r.availFailures),
      rendimiento: clamp((100 - Math.max(0, (Math.max(r.p95Load, r.p95Spike) - 100) / 9)) * 0.6 + availScore(r.successSpike) * 0.4),
      seguridad: clamp(100 - r.threats.critical * 10 - r.threats.high * 5 - r.threats.medium * 1.5 - r.threats.low * 0.3 - secFails * 10 - (r.attack.webBlockedPct !== null ? (1 - r.attack.webBlockedPct) * 20 : 0)),
      costo: r.rawCost > 0 && Number.isFinite(cheapest) ? clamp((cheapest / r.rawCost) * 100) : 100,
      operacion: clamp(100 - r.complexity.points * 2.2),
      salud: clamp(100 - r.validation.errors * 15 - r.validation.warns * 2 - r.blocked * 20 - funcFails * 15),
    };
    const { rawCost: _r, ...rest } = r;
    void _r;
    return { ...rest, scores, total: 0 };
  });
  return rescore({ metrics, winnerId: '', weights: opts.weights, avgRps: opts.avgRps }, opts.weights);
}

/** Recalcula el puntaje total y la ganadora con otros pesos, sin volver a simular (empate → la más barata). */
export function rescore(c: Comparison, weights: Weights): Comparison {
  const sum = PILLARS.reduce((a, p) => a + weights[p.id], 0) || 1;
  const metrics = c.metrics.map((m) => ({ ...m, total: Math.round(PILLARS.reduce((a, p) => a + m.scores[p.id] * weights[p.id], 0) / sum) }));
  const winner = [...metrics].sort((a, b) => b.total - a.total || a.cost.total - b.cost.total)[0];
  return { ...c, metrics, weights, winnerId: winner?.id ?? '' };
}

/* ───────────────────────── diferencias entre variantes */

export interface VariantDiff {
  /** Casi no comparten piezas: se resume como «diseño distinto». */
  distinct: boolean;
  added: string[];
  removed: string[];
  changed: string[];
}

export function diffVariants(base: Variant, other: Variant): VariantDiff {
  const name = (n: ServiceNode) => `${n.data.label} (${getService(n.data.serviceId).short})`;
  const bs = base.nodes.filter(isService) as ServiceNode[];
  const os = other.nodes.filter(isService) as ServiceNode[];
  // Empareja piezas: primero por id (variantes clonadas), luego por servicio + nombre y por último por servicio.
  const match = new Map<string, string>(); // id en other → id en base
  const used = new Set<string>();
  const pair = (test: (b: ServiceNode, o: ServiceNode) => boolean) => {
    for (const o of os) {
      if (match.has(o.id)) continue;
      const b = bs.find((x) => !used.has(x.id) && test(x, o));
      if (b) { match.set(o.id, b.id); used.add(b.id); }
    }
  };
  pair((b, o) => b.id === o.id);
  pair((b, o) => b.data.serviceId === o.data.serviceId && b.data.label === o.data.label);
  pair((b, o) => b.data.serviceId === o.data.serviceId);
  pair((b, o) => b.data.label === o.data.label); // misma pieza con otro servicio (p. ej. RDS → Aurora)
  const bById = new Map(bs.map((n) => [n.id, n]));
  const added = os.filter((o) => !match.has(o.id)).map(name);
  const removed = bs.filter((b) => !used.has(b.id)).map(name);
  const changed: string[] = [];
  for (const o of os) {
    const b = bById.get(match.get(o.id) ?? '');
    if (!b) continue;
    if (b.data.serviceId !== o.data.serviceId) changed.push(`${b.data.label}: ${getService(b.data.serviceId).short} → ${getService(o.data.serviceId).short}`);
    else if (JSON.stringify(b.data.props) !== JSON.stringify(o.data.props) || JSON.stringify(b.data.net ?? {}) !== JSON.stringify(o.data.net ?? {})) changed.push(`${o.data.label}: configuración`);
  }
  const toBase = (id: string) => match.get(id) ?? `new:${id}`;
  const bE = new Set(base.edges.map((e) => `${e.source}>${e.target}`));
  const oE = new Set(other.edges.map((e) => `${toBase(e.source)}>${toBase(e.target)}`));
  const newEdges = [...oE].filter((k) => !bE.has(k)).length;
  const goneEdges = [...bE].filter((k) => !oE.has(k)).length;
  if (newEdges || goneEdges) changed.push(`conexiones: +${newEdges} / −${goneEdges}`);
  if (base.securityGroups.length !== other.securityGroups.length) changed.push(`Security Groups: ${base.securityGroups.length} → ${other.securityGroups.length}`);
  const shared = match.size / Math.max(1, Math.max(bs.length, os.length));
  return { added, removed, changed, distinct: shared < 0.3 };
}

/* ───────────────────────── ADR a partir de la comparación */

const money = (n: number) => `US$${Math.round(n).toLocaleString('es-CO')}`;
const pct = (n: number) => `${(n * 100).toFixed(2)} %`;

export function buildAdr(c: Comparison, variants: Variant[]): { title: string; context: string; decision: string; consequences: string } {
  const W = c.metrics.find((m) => m.id === c.winnerId)!;
  const others = c.metrics.filter((m) => m.id !== W.id);
  const wv = variants.find((v) => v.id === W.id)!;
  const prio = PILLARS.filter((p) => c.weights[p.id] > 0)
    .sort((a, b) => c.weights[b.id] - c.weights[a.id])
    .map((p) => `${p.label} ${c.weights[p.id]} %`)
    .join(', ');
  const line = (m: VariantMetrics) =>
    `- «${m.name}»: puntaje ${m.total}/100 · disponibilidad ante fallas ${pct(m.availFailures)} · p95 en pico ${Math.round(m.p95Spike)} ms · ${m.threats.open} amenazas abiertas (${m.threats.critical} críticas, ${m.threats.high} altas) · ${money(m.cost.total)}/mes · complejidad ${m.complexity.label.toLowerCase()} (${m.pieces} piezas)`;
  const diffs = others
    .map((o) => {
      const d = diffVariants(wv, variants.find((v) => v.id === o.id)!);
      if (d.distinct) return `- «${W.name}» y «${o.name}» son diseños distintos (comparten pocas piezas): ${W.pieces} vs ${o.pieces} piezas.`;
      const list = (xs: string[]) => (xs.length > 6 ? `${xs.slice(0, 5).join(', ')} y ${xs.length - 5} más` : xs.join(', '));
      const parts = [d.added.length ? `agrega ${list(d.added)}` : '', d.removed.length ? `quita ${list(d.removed)}` : '', d.changed.length ? `cambia ${list(d.changed)}` : ''].filter(Boolean);
      return parts.length ? `- «${o.name}» respecto a «${W.name}»: ${parts.join('; ')}.` : '';
    })
    .filter(Boolean);

  const context = [
    `Se evaluaron ${c.metrics.length} alternativas del diseño con las mismas pruebas en ArchiPlan: caída de instancia, caída de AZ, falla de una dependencia, carga, pico, ataques web y DDoS, la batería de peticiones de usuario, el modelo de amenazas STRIDE, el análisis de red y un costo mensual estimado con ${c.avgRps} req/s promedio.`,
    `Prioridades acordadas: ${prio}.`,
    '',
    ...c.metrics.map(line),
    ...(diffs.length ? ['', 'Diferencias:', ...diffs] : []),
  ].join('\n');

  const wins: string[] = [];
  const losses: string[] = [];
  for (const o of others) {
    for (const p of PILLARS) {
      const d = W.scores[p.id] - o.scores[p.id];
      const detail =
        p.id === 'disponibilidad' ? `${pct(W.availFailures)} vs ${pct(o.availFailures)} ante fallas`
        : p.id === 'rendimiento' ? `éxito en el pico ${pct(W.successSpike)} vs ${pct(o.successSpike)}, p95 ${Math.round(W.p95Spike)} ms vs ${Math.round(o.p95Spike)} ms`
        : p.id === 'seguridad' ? `${W.threats.open} vs ${o.threats.open} amenazas abiertas (${W.threats.critical + W.threats.high} vs ${o.threats.critical + o.threats.high} críticas/altas)`
        : p.id === 'costo' ? `${money(W.cost.total)} vs ${money(o.cost.total)} al mes`
        : p.id === 'operacion' ? `complejidad ${W.complexity.label.toLowerCase()} (${W.complexity.points}) vs ${o.complexity.label.toLowerCase()} (${o.complexity.points})`
        : `${W.validation.errors + W.blocked} vs ${o.validation.errors + o.blocked} errores o conexiones bloqueadas`;
      if (d >= 5) wins.push(`- ${p.label} mejor que «${o.name}»: ${detail}.`);
      else if (d <= -5) losses.push(`- ${p.label} peor que «${o.name}»: ${detail}.`);
    }
  }
  const decision = [
    `Se elige «${W.name}» (puntaje ${W.total}/100 frente a ${others.map((o) => `«${o.name}» ${o.total}`).join(', ')}).`,
    '',
    'Razones:',
    ...(wins.length ? wins : ['- Las alternativas quedan parejas en todos los pilares; se elige por el puntaje total ponderado.']),
  ].join('\n');
  const pending = W.threats.critical + W.threats.high;
  const consequences = [
    ...(losses.length ? ['Lo que se acepta a cambio:', ...losses, ''] : ['No empeora en ningún pilar de forma relevante frente a las alternativas.', '']),
    'Pendientes de la variante elegida:',
    `- ${pending ? `${pending} amenazas críticas/altas abiertas: revisar la pestaña Amenazas.` : 'Sin amenazas críticas ni altas abiertas.'}`,
    ...(W.validation.errors || W.blocked ? [`- ${W.validation.errors} errores de validación y ${W.blocked} conexiones bloqueadas por resolver.`] : []),
    ...(W.battery.some((b) => !b.ok) ? [`- Peticiones de usuario que no se comportan como se espera: ${W.battery.filter((b) => !b.ok).map((b) => `${b.label} (${b.status})`).join(', ')}.`] : []),
    '- El costo es una estimación con precios de lista: validarlo con AWS Pricing Calculator antes de comprometer presupuesto.',
  ].join('\n');
  return { title: `Elegir «${W.name}» frente a ${others.map((o) => `«${o.name}»`).join(', ')}`, context, decision, consequences };
}
