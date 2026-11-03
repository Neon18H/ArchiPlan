/**
 * Arma el contexto que «lee» el asistente: el diagrama, la red, el escalado, los problemas,
 * las amenazas y los últimos resultados de simulación, en texto compacto.
 */
import { CLOUD_LABEL, getService, PLACEMENT_LABEL, primaryCloud } from '../catalog/catalog';
import { byId, isService, placementOf } from '../lib/graph';
import { effectiveNet, isLb, listenersOf, listenPort, needsSg, ruleSentence } from '../net/model';
import type { NetAnalysis } from '../net/reach';
import type { TraceResult } from '../net/trace';
import { describeScaling, SCALING_KEYS, scalingKind } from '../scaling/model';
import { SECURITY_SETTINGS } from '../security/settings';
import { SCENARIO_MAP } from '../sim/scenarios';
import type { SimResult } from '../sim/engine';
import type { Threat } from '../threats/model';
import type { AppEdge, AppNode, ConnData, Issue, ProjectMeta, SecurityGroup, ServiceNode } from '../types';

export interface AiContextInput {
  meta: ProjectMeta;
  nodes: AppNode[];
  edges: AppEdge[];
  securityGroups: SecurityGroup[];
  security: Record<string, boolean>;
  issues: Issue[];
  threats: Threat[];
  net: NetAnalysis;
  sim?: SimResult | null;
  trace?: TraceResult | null;
  /** Variantes A/B del proyecto, si las hay. */
  variant?: { names: string[]; active: string } | null;
}

const MAX = 24000;

export function buildContext(x: AiContextInput): string {
  const { meta, nodes, edges } = x;
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const cloud = primaryCloud(nodes, meta.provider ?? 'aws');
  const L: string[] = [];
  const label = (id: string) => (map.get(id)?.data as { label?: string } | undefined)?.label ?? id;

  L.push(`# Arquitectura: ${meta.name} (${CLOUD_LABEL[cloud]}, región ${meta.region}, ambiente ${meta.environment})`);
  if (meta.description) L.push(`Objetivo: ${meta.description}`);
  if (x.variant) L.push(`Variantes A/B del proyecto: ${x.variant.names.map((n) => `«${n}»`).join(', ')}. El diagrama de abajo es «${x.variant.active}»; las demás se comparan con ⚖ Comparar.`);
  if (!services.length) {
    L.push('El diagrama está vacío.');
    return L.join('\n');
  }

  // Piezas
  const eff = effectiveNet(nodes, edges, x.securityGroups);
  L.push('', `## Piezas (${services.length})`);
  for (const n of services) {
    const def = getService(n.data.serviceId);
    const parts = [`[[${n.data.label}]] — ${def.name} (${def.role})`, `ubicación: ${PLACEMENT_LABEL[placementOf(n, map)]}`];
    const props = Object.entries(n.data.props)
      .filter(([k, v]) => !k.startsWith('sim.') && !(scalingKind(n) && SCALING_KEYS.has(k)) && v !== '' && v !== undefined)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');
    if (props) parts.push(`config: ${props}`);
    if (needsSg(n, map)) {
      parts.push(isLb(n) ? `listeners: ${listenersOf(n).map((l) => `${l.protocol} ${l.port}${l.action === 'redirect-https' ? '→redirige' : ''}${(l.protocol === 'HTTPS' || l.protocol === 'TLS') && !l.cert ? ' (sin certificado)' : ''}`).join(', ')}` : `escucha :${listenPort(n)}`);
      const sgs = eff.sgIdsOf(n).map((id) => eff.groups.find((g) => g.id === id)?.name).filter(Boolean);
      parts.push(`grupos: ${sgs.join(', ') || 'ninguno'}`);
    }
    const sc = describeScaling(n);
    if (sc) parts.push(`escalado: ${sc}`);
    if (n.data.notes) parts.push(`notas: ${n.data.notes}`);
    L.push(`- ${parts.join(' · ')}`);
  }

  // Conexiones
  L.push('', `## Conexiones (${edges.length})`);
  for (const e of edges) {
    const d = (e.data ?? {}) as ConnData;
    const v = x.net.verdicts.get(e.id);
    const netTxt = !v || v.kind === 'none' ? '' : v.kind === 'managed' ? ' · red: la gestiona la nube' : v.ok ? ` · red: ✓ ${v.kind === 'egress' ? 'salida HTTPS' : `TCP ${v.port}`}` : ` · red: ✗ BLOQUEADA (${v.summary}; efecto: ${v.failure ?? 'falla'})`;
    L.push(`- [[${label(e.source)}]] → [[${label(e.target)}]] · ${d.protocol || 'sin protocolo'}${d.async ? ' · asíncrona' : ''}${d.description ? ` · ${d.description}` : ''}${netTxt}`);
  }

  // Red
  if (eff.groups.length) {
    L.push('', `## Security Groups (${eff.mode === 'manual' ? 'personalizados por el arquitecto' : 'automáticos, derivados de las flechas'})`);
    for (const g of eff.groups) {
      const users = services.filter((n) => eff.sgIdsOf(n).includes(g.id)).map((n) => n.data.label);
      const inb = g.inbound.map((r) => ruleSentence(r, 'inbound', nodes, eff.groups, eff.sgIdsOf)).join('; ') || 'nada';
      const out = g.outbound.map((r) => ruleSentence(r, 'outbound', nodes, eff.groups, eff.sgIdsOf)).join('; ') || 'nada';
      L.push(`- ${g.name} (aplica a: ${users.join(', ') || 'ninguna pieza'}) · entra: ${inb} · sale: ${out}`);
    }
  }

  // Validación
  const errs = x.issues.filter((i) => i.severity === 'error');
  const warns = x.issues.filter((i) => i.severity === 'warn');
  L.push('', `## Validación: ${errs.length} errores, ${warns.length} avisos`);
  for (const i of [...errs, ...warns].slice(0, 25)) L.push(`- [${i.severity === 'error' ? 'error' : 'aviso'}] ${i.title} — ${i.detail}`);

  // Amenazas
  const order = { Crítico: 0, Alto: 1, Medio: 2, Bajo: 3 } as Record<string, number>;
  const open = x.threats.filter((t) => t.status === 'abierta' || t.status === 'parcial').sort((a, b) => order[a.risk] - order[b.risk]);
  L.push('', `## Modelo de amenazas: ${open.length} abiertas o parciales de ${x.threats.length}`);
  for (const t of open.slice(0, 14)) {
    const pend = t.controls.filter((c) => c.required && !c.ok).map((c) => c.label);
    L.push(`- [${t.risk}] ${t.title}${pend.length ? ` — falta: ${pend.slice(0, 3).join('; ')}` : ''}`);
  }

  // Seguridad del proyecto
  const on = SECURITY_SETTINGS.filter((s) => x.security[s.key]).map((s) => s.label);
  L.push('', `## Seguridad del proyecto: ${on.length ? on.join('; ') : 'ningún guardrail ni práctica marcada'}`);

  // Simulaciones
  if (x.sim) {
    const s = x.sim.summary;
    L.push('', `## Última simulación: ${SCENARIO_MAP[x.sim.scenario.kind].label}`);
    L.push(`Disponibilidad ${(s.availability * 100).toFixed(2)} %, p95 ${Math.round(s.p95Latency)} ms${s.bottleneck ? `, pieza más exigida: ${s.bottleneck.label} (${Math.round(s.bottleneck.peakUtil * 100)} %)` : ''}.`);
    for (const f of x.sim.findings.slice(0, 5)) L.push(`- [${f.severity}] ${f.title} — ${f.detail}`);
  }
  if (x.trace && x.trace.hops.length) {
    L.push('', `## Última petición de usuario simulada (${x.trace.request.label}): ${x.trace.headline}`);
    for (const p of x.trace.problems.slice(0, 4)) L.push(`- ${p.title} — ${p.detail}`);
  }

  // Selección
  const sel = [...services.filter((n) => n.selected).map((n) => n.data.label), ...edges.filter((e) => e.selected).map((e) => `${label(e.source)} → ${label(e.target)}`)];
  if (sel.length) L.push('', `## Selección actual del usuario: ${sel.map((s) => `[[${s}]]`).join(', ')}`);

  let txt = L.join('\n');
  if (txt.length > MAX) txt = `${txt.slice(0, MAX)}\n…(contexto recortado)`;
  return txt;
}

export const SYSTEM_PROMPT = `Eres el asistente de ArchiPlan: un arquitecto de soluciones cloud senior (AWS y Azure) y experto en seguridad que acompaña al usuario mientras diseña.

Cómo respondes:
- En español, directo y concreto. Markdown corto: viñetas, **negritas** para lo importante. Máximo ~250 palabras salvo que pidan más detalle.
- Al mencionar una pieza del diagrama escribe su nombre exacto entre dobles corchetes, por ejemplo [[BD principal]]; la interfaz lo convierte en un enlace.
- Prioriza por impacto: primero lo que rompe (conexiones bloqueadas, errores, puntos únicos de falla), luego seguridad, luego costo y mejoras.
- Cuando propongas un cambio, di dónde se hace en ArchiPlan: «Propiedades → Red», «Propiedades → Escalado», el botón «⛨ Red» (vista de red, tabla de accesos y Security Groups), «Amenazas → ⚙ Seguridad del proyecto», la pestaña «Validación» (botones ⚡) o «▶ Simular → Petición de usuario».
- Básate solo en el contexto. No inventes piezas, puertos ni reglas que no aparecen; si falta información, dilo y pregunta.
- Si el usuario se equivoca, díselo con claridad y explica por qué.

Contexto actual del diagrama (se actualiza en cada mensaje):`;

export const REVIEW_PROMPT =
  'Revisa el diseño actual como lo haría un revisor de arquitectura. Dame máximo 5 observaciones accionables, ordenadas por impacto, cada una en una viñeta con el formato: **título corto** — por qué importa — qué hacer en ArchiPlan. Si no hay nada relevante, dilo en una línea.';

export const QUICK_ACTIONS: { label: string; prompt: string; needsSelection?: boolean }[] = [
  { label: 'Revisa mi arquitectura', prompt: REVIEW_PROMPT },
  { label: '¿Qué me falta para producción?', prompt: '¿Qué le falta a esta arquitectura para estar lista para producción? Agrúpalo en: disponibilidad, seguridad, observabilidad y operación.' },
  { label: 'Revisa la red y los SG', prompt: 'Revisa la red: Security Groups, puertos, listeners, conexiones bloqueadas y exposición a Internet. ¿Qué está mal configurado o demasiado abierto?' },
  { label: '¿Aguanta un pico?', prompt: '¿Cómo se comporta esta arquitectura ante un pico de 10x de tráfico? Revisa el escalado configurado de cada pieza y dime dónde está el cuello de botella y qué ajustar.' },
  { label: 'Riesgos de seguridad', prompt: '¿Cuáles son los 5 riesgos de seguridad más importantes de este diseño y cómo los mitigo?' },
  { label: '¿Cómo bajo costos?', prompt: '¿Dónde puedo bajar costos sin perder disponibilidad ni seguridad?' },
  { label: 'Explícame la selección', prompt: 'Explícame la pieza o conexión seleccionada: para qué sirve en este diseño, si está bien configurada y qué mejorarías.', needsSelection: true },
];
