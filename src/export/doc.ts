import { CATEGORIES, CLOUD_LABEL, getService, LAYERS, primaryCloud, zoneLabel } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import { buildGuide } from '../rules/guide';
import { COMPONENT_KINDS } from '../c3/model';
import { validate } from '../rules/validate';
import type { ConnData, Project, ServiceNode } from '../types';
import { buildThreats, STATUS_LABEL, STRIDE, summarizeThreats, type Stride, type Threat } from '../threats/model';

const PLACE: Record<string, string> = { outside: 'Global / fuera de VPC', region: 'Regional', 'subnet-public': 'Subnet pública', 'subnet-private': 'Subnet privada', 'subnet-data': 'Subnet de datos' };
const SEV: Record<string, string> = { error: 'Crítico', warn: 'Advertencia', info: 'Sugerencia' };

interface DocModel {
  title: string;
  summary: [string, string][];
  description: string;
  context: { actors: string[]; externals: string[]; interactions: string[] };
  layers: { layer: string; rows: string[][] }[];
  c3: { service: string; kind: string; rows: string[][]; rels: string[] }[];
  network: string[];
  flows: string[][];
  decisions: Project['decisions'];
  risks: { sev: string; title: string; detail: string }[];
  checklist: { title: string; done: boolean; optional?: boolean }[];
  next: string[];
  threats: Threat[];
  boundaries: string[];
  tsum: ReturnType<typeof summarizeThreats>;
}

function model(p: Project): DocModel {
  const { nodes, edges, meta, decisions } = p;
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const label = (id: string) => (map.get(id)?.data as { label?: string })?.label ?? id;
  const issues = validate(nodes, edges);
  const cloud = primaryCloud(nodes, meta.provider ?? 'aws');
  const tm = buildThreats(nodes, edges, p.threats ?? {});
  const guide = buildGuide(nodes, edges, decisions, issues, tm.threats);
  const role = (n: ServiceNode) => getService(n.data.serviceId).role;
  const actors = services.filter((n) => role(n) === 'actor');
  const externals = services.filter((n) => role(n) === 'external');
  const outsideIds = new Set([...actors, ...externals].map((n) => n.id));

  const propsText = (n: ServiceNode) => {
    const defs = getService(n.data.serviceId).props ?? [];
    return defs.map((d) => `${d.label}: ${typeof n.data.props[d.key] === 'boolean' ? (n.data.props[d.key] ? 'sí' : 'no') : n.data.props[d.key]}`).join('; ');
  };

  const layers = (Object.keys(LAYERS) as (keyof typeof LAYERS)[])
    .sort((a, b) => LAYERS[a].order - LAYERS[b].order)
    .map((l) => ({
      layer: LAYERS[l].label,
      rows: services
        .filter((n) => getService(n.data.serviceId).layer === l)
        .map((n) => [n.data.label, getService(n.data.serviceId).name, PLACE[placementOf(n, map)], propsText(n), n.data.notes ?? '']),
    }))
    .filter((x) => x.rows.length);

  const network: string[] = [];
  const walk = (parent: string | undefined, depth: number) => {
    for (const n of nodes.filter((x) => x.parentId === parent)) {
      if (isZone(n)) {
        const extra = Object.entries(n.data.props).map(([k, v]) => `${k}=${v}`).join(', ');
        network.push(`${'  '.repeat(depth)}- **${n.data.label}** (${zoneLabel(n.data.zoneKind, cloud)}${extra ? `; ${extra}` : ''})`);
        walk(n.id, depth + 1);
      } else if (isService(n) && parent) {
        network.push(`${'  '.repeat(depth)}- ${n.data.label}`);
      }
    }
  };
  walk(undefined, 0);

  const total = services.length;
  const cats = new Set(services.map((n) => CATEGORIES[getService(n.data.serviceId).category].label));
  return {
    title: meta.name,
    description: meta.description,
    summary: [
      ['Proyecto', meta.name],
      ['Autor', meta.author || '—'],
      ['Ambiente', meta.environment || '—'],
      ['Proveedor / región', `${CLOUD_LABEL[cloud]} / ${meta.region}`],
      ['Fecha', new Date().toLocaleDateString('es-CO', { year: 'numeric', month: 'long', day: 'numeric' })],
      ['Componentes', `${total} piezas, ${edges.length} conexiones, ${nodes.filter(isZone).length} zonas`],
      ['Categorías', [...cats].join(', ') || '—'],
      ['Estado de validación', `${issues.filter((i) => i.severity === 'error').length} críticos, ${issues.filter((i) => i.severity === 'warn').length} advertencias, ${issues.filter((i) => i.severity === 'info').length} sugerencias`],
    ],
    context: {
      actors: actors.map((n) => `${n.data.label}${n.data.notes ? ` — ${n.data.notes}` : ''}`),
      externals: externals.map((n) => `${n.data.label} (${String(n.data.props.kind ?? 'externo')})`),
      interactions: edges
        .filter((e) => outsideIds.has(e.source) || outsideIds.has(e.target))
        .map((e) => `${label(e.source)} → ${label(e.target)} (${(e.data as ConnData)?.protocol || 'HTTPS'})`),
    },
    layers,
    network,
    flows: edges.map((e) => {
      const d = (e.data ?? {}) as ConnData;
      return [label(e.source), label(e.target), d.protocol || '', d.async ? 'Asíncrona' : 'Síncrona', d.description || ''];
    }),
    decisions,
    risks: issues.map((i) => ({ sev: SEV[i.severity], title: i.title, detail: i.detail })),
    checklist: guide.map((g) => ({ title: g.title, done: g.done, optional: g.optional })),
    c3: services
      .filter((n) => n.data.c3?.components.length)
      .map((n) => {
        const m = n.data.c3!;
        const nameOf = (ref: string) => (ref.startsWith('ext:') ? `${label(ref.slice(4))} (externo)` : m.components.find((c) => c.id === ref)?.label ?? '?');
        return {
          service: n.data.label,
          kind: getService(n.data.serviceId).name,
          rows: m.components.map((c) => [c.label, COMPONENT_KINDS[c.kind].label, c.tech ?? '', c.description ?? '']),
          rels: m.links.map((l) => `${nameOf(l.source)} → ${nameOf(l.target)}${l.label ? ` (${l.label})` : ''}`),
        };
      }),
    threats: tm.threats,
    boundaries: [...new Set(tm.boundaries.filter((b) => b.inbound).map((b) => b.label))],
    tsum: summarizeThreats(tm.threats),
    next: [
      ...issues.filter((i) => i.severity === 'error').map((i) => `Resolver: ${i.title}`),
      ...tm.threats.filter((t) => (t.status === 'abierta' || t.status === 'parcial') && t.risk === 'Crítico').map((t) => `Mitigar amenaza crítica: ${t.title}`),
      ...guide.filter((g) => !g.done && !g.optional).map((g) => `${g.title.replace(/^\d+\.\s*/, '')}: ${g.question}`),
    ],
  };
}

const mdEsc = (s: string) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(p: Project, diagramFile = 'diagrama.png'): string {
  const m = model(p);
  const L: string[] = [];
  L.push(`# Documento de arquitectura: ${m.title}`, '');
  L.push('## 1. Resumen', '');
  L.push('| Campo | Valor |', '|---|---|', ...m.summary.map(([k, v]) => `| ${k} | ${mdEsc(v)} |`), '');
  if (m.description) L.push(m.description, '');
  L.push('## 2. Diagrama', '', `![Diagrama de arquitectura](${diagramFile})`, '');
  L.push('## 3. Contexto (C4 nivel 1)', '');
  L.push('**Actores:** ' + (m.context.actors.join('; ') || 'no definidos'), '');
  L.push('**Sistemas externos:** ' + (m.context.externals.join('; ') || 'ninguno'), '');
  if (m.context.interactions.length) L.push('**Interacciones con el sistema:**', '', ...m.context.interactions.map((i) => `- ${i}`), '');
  L.push('## 4. Componentes por capa (C4 nivel 2)', '');
  for (const l of m.layers) {
    L.push(`### ${l.layer}`, '', '| Componente | Servicio | Ubicación | Configuración | Notas |', '|---|---|---|---|---|');
    L.push(...l.rows.map((r) => `| ${r.map(mdEsc).join(' | ')} |`), '');
  }
  for (const c of m.c3) {
    L.push(`### Componentes internos de ${c.service} (C4 nivel 3)`, '', `_Contenedor: ${c.kind}_`, '', '| Componente | Tipo | Tecnología | Responsabilidad |', '|---|---|---|---|');
    L.push(...c.rows.map((r) => `| ${r.map(mdEsc).join(' | ')} |`), '');
    if (c.rels.length) L.push('**Relaciones:**', '', ...c.rels.map((r) => `- ${r}`), '');
  }
  L.push('## 5. Red y ubicación', '');
  L.push(...(m.network.length ? m.network : ['Sin zonas de red definidas.']), '');
  L.push('## 6. Flujos y conexiones', '');
  if (m.flows.length) L.push('| Origen | Destino | Protocolo | Tipo | Descripción |', '|---|---|---|---|---|', ...m.flows.map((r) => `| ${r.map(mdEsc).join(' | ')} |`), '');
  else L.push('Sin conexiones.', '');
  L.push('## 7. Decisiones de arquitectura (ADR)', '');
  if (!m.decisions.length) L.push('_No hay decisiones registradas._', '');
  m.decisions.forEach((d, i) => {
    L.push(`### ADR‑${String(i + 1).padStart(3, '0')}: ${d.title}`, '', `**Estado:** ${d.status}`, '', `**Contexto.** ${d.context || '—'}`, '', `**Decisión.** ${d.decision || '—'}`, '', `**Consecuencias.** ${d.consequences || '—'}`, '');
  });
  L.push('## 8. Riesgos y hallazgos', '');
  if (m.risks.length) L.push('| Severidad | Hallazgo | Detalle |', '|---|---|---|', ...m.risks.map((r) => `| ${r.sev} | ${mdEsc(r.title)} | ${mdEsc(r.detail)} |`), '');
  else L.push('Sin hallazgos: el diagrama cumple todas las reglas.', '');
  L.push('## 9. Modelo de amenazas (STRIDE)', '');
  if (!m.threats.length) L.push('Sin elementos para modelar.', '');
  else {
    L.push(`${m.tsum.total} amenazas identificadas: **${m.tsum.open} pendientes** (${m.tsum.critical} críticas, ${m.tsum.high} altas, ${m.tsum.medium} medias, ${m.tsum.low} bajas) y ${m.tsum.handled} mitigadas, aceptadas o no aplicables.`, '');
    if (m.boundaries.length) L.push('**Límites de confianza:** ' + m.boundaries.join(' · '), '');
    L.push('| Categoría | Propiedad | Total | Pendientes |', '|---|---|---|---|', ...m.tsum.byStride.map((b) => `| ${b.k} — ${STRIDE[b.k as Stride].es} | ${STRIDE[b.k as Stride].property} | ${b.total} | ${b.open} |`), '');
    L.push('| STRIDE | Amenaza | Elemento | Riesgo | Estado | Controles pendientes | Ref. |', '|---|---|---|---|---|---|---|');
    for (const t of m.threats) {
      const pend = t.controls.filter((c) => c.required && !c.ok).map((c) => c.label).join('; ');
      L.push(`| ${t.stride.join('')} | ${mdEsc(t.title)} | ${mdEsc(t.element)} | ${t.risk} | ${STATUS_LABEL[t.status]}${t.note ? ` — ${mdEsc(t.note)}` : ''} | ${mdEsc(pend || '—')} | ${mdEsc(t.refs.slice(0, 2).join(', '))} |`);
    }
    L.push('');
  }
  L.push('## 10. Checklist de diseño', '', ...m.checklist.map((c) => `- [${c.done ? 'x' : ' '}] ${c.title}${c.optional ? ' _(opcional)_' : ''}`), '');
  L.push('## 11. Próximos pasos', '', ...(m.next.length ? m.next.map((n) => `- ${n}`) : ['- Revisar con el equipo y pasar a implementación.']), '');
  L.push('---', `_Generado con ArchiPlan el ${new Date().toISOString().slice(0, 16).replace('T', ' ')}._`, '');
  return L.join('\n');
}

const h = (s: string) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const md = (s: string) => h(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

export function toHtmlDoc(p: Project, diagramDataUrl?: string): string {
  const m = model(p);
  const table = (head: string[], rows: string[][]) => `<table><thead><tr>${head.map((x) => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${h(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  const sevClass: Record<string, string> = { Crítico: 'err', Advertencia: 'warn', Sugerencia: 'info' };
  return `<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>${h(m.title)} — Documento de arquitectura</title>
<style>
  :root { --ink:#1b1f24; --muted:#5b6470; --line:#e3e6ea; --accent:#e8590c; }
  * { box-sizing: border-box; }
  body { font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--ink); max-width: 1000px; margin: 40px auto; padding: 0 32px; }
  h1 { font-size: 28px; margin: 0 0 4px; letter-spacing: -0.02em; }
  .sub { color: var(--muted); margin-bottom: 28px; }
  h2 { font-size: 18px; margin: 36px 0 12px; padding-bottom: 6px; border-bottom: 2px solid var(--ink); }
  h3 { font-size: 15px; margin: 22px 0 8px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 13px; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { background: #f6f7f9; font-weight: 600; }
  img.diagram { width: 100%; border: 1px solid var(--line); border-radius: 8px; }
  .adr { border: 1px solid var(--line); border-left: 4px solid var(--accent); border-radius: 6px; padding: 12px 16px; margin: 10px 0; }
  .adr .st { display: inline-block; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; background: #f1f3f5; padding: 2px 8px; border-radius: 99px; }
  .pill { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 99px; white-space: nowrap; }
  .err { background: #ffe3e3; color: #c92a2a; } .warn { background: #fff3bf; color: #8a5a00; } .info { background: #e7f5ff; color: #1864ab; }
  ul.tree { list-style: none; padding-left: 0; } ul.tree li { padding: 2px 0; }
  .check li { list-style: none; } .check { padding-left: 4px; }
  .toolbar { position: sticky; top: 0; background: #fff; padding: 10px 0; text-align: right; }
  .toolbar button { font: inherit; padding: 6px 14px; border-radius: 6px; border: 1px solid var(--ink); background: var(--ink); color: #fff; cursor: pointer; }
  .stride { display: inline-block; width: 16px; height: 16px; border-radius: 3px; color: #fff; font-size: 10px; font-weight: 800; text-align: center; line-height: 16px; margin-right: 1px; }
  .muted { color: var(--muted); } .refs { font-family: ui-monospace, Consolas, monospace; font-size: 11px; color: var(--muted); }
  .risk-Crítico { background: #9b1c1c; color: #fff; } .risk-Alto { background: #ffe3e3; color: #b02525; } .risk-Medio { background: #fff3bf; color: #8a5a00; } .risk-Bajo { background: #ebfbee; color: #0b7a0b; }
  ul.ctl { margin: 0; padding: 0; list-style: none; font-size: 12px; } ul.ctl li.ok { color: #0b7a0b; } ul.ctl li.no { color: #b02525; } ul.ctl li.opt { color: var(--muted); }
  @media print { .toolbar { display: none; } body { margin: 0; max-width: none; } h2 { break-after: avoid; } table, .adr { break-inside: avoid; } }
</style></head><body>
<div class="toolbar"><button onclick="window.print()">Imprimir / Guardar como PDF</button></div>
<h1>${h(m.title)}</h1>
<div class="sub">Documento de arquitectura de solución</div>
<h2>1. Resumen</h2>
${table(['Campo', 'Valor'], m.summary)}
${m.description ? `<p>${md(m.description)}</p>` : ''}
<h2>2. Diagrama</h2>
${diagramDataUrl ? `<img class="diagram" src="${diagramDataUrl}" alt="Diagrama de arquitectura">` : '<p><em>Diagrama no disponible.</em></p>'}
<h2>3. Contexto (C4 nivel 1)</h2>
<p><strong>Actores:</strong> ${h(m.context.actors.join('; ') || 'no definidos')}</p>
<p><strong>Sistemas externos:</strong> ${h(m.context.externals.join('; ') || 'ninguno')}</p>
${m.context.interactions.length ? `<ul>${m.context.interactions.map((i) => `<li>${h(i)}</li>`).join('')}</ul>` : ''}
<h2>4. Componentes por capa (C4 nivel 2)</h2>
${m.layers.map((l) => `<h3>${h(l.layer)}</h3>${table(['Componente', 'Servicio', 'Ubicación', 'Configuración', 'Notas'], l.rows)}`).join('')}
${m.c3.map((c) => `<h3>Componentes internos de ${h(c.service)} (C4 nivel 3)</h3><p class="muted">Contenedor: ${h(c.kind)}</p>${table(['Componente', 'Tipo', 'Tecnología', 'Responsabilidad'], c.rows)}${c.rels.length ? `<ul>${c.rels.map((r) => `<li>${h(r)}</li>`).join('')}</ul>` : ''}`).join('')}
<h2>5. Red y ubicación</h2>
${m.network.length ? `<ul class="tree">${m.network.map((n) => `<li style="padding-left:${(n.match(/^ */)?.[0].length ?? 0) * 10}px">${md(n.trim().replace(/^- /, ''))}</li>`).join('')}</ul>` : '<p>Sin zonas de red definidas.</p>'}
<h2>6. Flujos y conexiones</h2>
${m.flows.length ? table(['Origen', 'Destino', 'Protocolo', 'Tipo', 'Descripción'], m.flows) : '<p>Sin conexiones.</p>'}
<h2>7. Decisiones de arquitectura (ADR)</h2>
${m.decisions.length ? m.decisions.map((d, i) => `<div class="adr"><h3>ADR‑${String(i + 1).padStart(3, '0')}: ${h(d.title)} <span class="st">${h(d.status)}</span></h3><p><strong>Contexto.</strong> ${h(d.context || '—')}</p><p><strong>Decisión.</strong> ${h(d.decision || '—')}</p><p><strong>Consecuencias.</strong> ${h(d.consequences || '—')}</p></div>`).join('') : '<p><em>No hay decisiones registradas.</em></p>'}
<h2>8. Riesgos y hallazgos</h2>
${m.risks.length ? `<table><thead><tr><th>Severidad</th><th>Hallazgo</th><th>Detalle</th></tr></thead><tbody>${m.risks.map((r) => `<tr><td><span class="pill ${sevClass[r.sev]}">${h(r.sev)}</span></td><td>${h(r.title)}</td><td>${h(r.detail)}</td></tr>`).join('')}</tbody></table>` : '<p>Sin hallazgos: el diagrama cumple todas las reglas.</p>'}
<h2>9. Modelo de amenazas (STRIDE)</h2>
${m.threats.length ? `
<p>${m.tsum.total} amenazas identificadas: <strong>${m.tsum.open} pendientes</strong> (${m.tsum.critical} críticas, ${m.tsum.high} altas, ${m.tsum.medium} medias, ${m.tsum.low} bajas) y ${m.tsum.handled} mitigadas, aceptadas o no aplicables.</p>
${m.boundaries.length ? `<p><strong>Límites de confianza:</strong> ${m.boundaries.map(h).join(' · ')}</p>` : ''}
<table><thead><tr><th>Categoría</th><th>Propiedad</th><th>Total</th><th>Pendientes</th></tr></thead><tbody>${m.tsum.byStride.map((b) => `<tr><td><span class="stride" style="background:${STRIDE[b.k as Stride].color}">${b.k}</span> ${h(STRIDE[b.k as Stride].es)}</td><td>${h(STRIDE[b.k as Stride].property)}</td><td>${b.total}</td><td>${b.open}</td></tr>`).join('')}</tbody></table>
<table><thead><tr><th>STRIDE</th><th>Amenaza</th><th>Riesgo</th><th>Estado</th><th>Controles</th></tr></thead><tbody>${m.threats
  .map(
    (t) => `<tr><td>${t.stride.map((k) => `<span class="stride" style="background:${STRIDE[k].color}">${k}</span>`).join('')}</td><td><strong>${h(t.title)}</strong><br><span class="muted">${h(t.element)}${t.boundary ? ` · límite ${h(t.boundary)}` : ''}</span><br><span class="refs">${h(t.refs.join(' · '))}</span></td><td><span class="pill risk-${h(t.risk)}">${h(t.risk)}</span></td><td>${h(STATUS_LABEL[t.status])}${t.owner ? `<br><span class="muted">${h(t.owner)}</span>` : ''}${t.note ? `<br><em>${h(t.note)}</em>` : ''}</td><td><ul class="ctl">${t.controls.map((c) => `<li class="${c.ok ? 'ok' : c.required ? 'no' : 'opt'}">${c.ok ? '✓' : c.required ? '✗' : '○'} ${h(c.label)}</li>`).join('')}</ul></td></tr>`,
  )
  .join('')}</tbody></table>` : '<p>Sin elementos para modelar.</p>'}
<h2>10. Checklist de diseño</h2>
<ul class="check">${m.checklist.map((c) => `<li>${c.done ? '✅' : '⬜'} ${h(c.title)}${c.optional ? ' <em>(opcional)</em>' : ''}</li>`).join('')}</ul>
<h2>11. Próximos pasos</h2>
<ul>${(m.next.length ? m.next : ['Revisar con el equipo y pasar a implementación.']).map((n) => `<li>${h(n)}</li>`).join('')}</ul>
<p class="sub" style="margin-top:40px">Generado con ArchiPlan · ${new Date().toISOString().slice(0, 16).replace('T', ' ')}</p>
</body></html>`;
}

