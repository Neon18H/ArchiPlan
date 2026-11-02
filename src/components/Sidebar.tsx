import { useEffect, useState } from 'react';
import { CATEGORIES, getService, LAYERS, PLACEMENT_LABEL, SERVICE_MAP, ZONES } from '../catalog/catalog';
import { byId, isService, isZone, placementOf } from '../lib/graph';
import { evaluateConnection } from '../rules/connections';
import { validate } from '../rules/validate';
import type { GuideStep } from '../rules/guide';
import { useStore } from '../store';
import type { AppEdge, AppNode, ConnData, Decision, Issue, PropDef, PropValue, ServiceNode, ZoneNode } from '../types';
import { ServiceIcon } from './ServiceIcon';
import { fmtRps, profileFor } from '../sim/profiles';
import { useSim } from '../sim/store';

type Tab = 'props' | 'issues' | 'guide' | 'adr';

export function Sidebar({ issues, guide }: { issues: Issue[]; guide: GuideStep[] }) {
  const [tab, setTab] = useState<Tab>('guide');
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const decisions = useStore((s) => s.decisions);
  const selNodes = nodes.filter((n) => n.selected);
  const selEdges = edges.filter((e) => e.selected);
  const counts = { error: issues.filter((i) => i.severity === 'error').length, warn: issues.filter((i) => i.severity === 'warn').length };
  const done = guide.filter((g) => g.done).length;
  useEffect(() => {
    const h = (e: Event) => setTab((e as CustomEvent).detail as Tab);
    window.addEventListener('archiplan:tab', h);
    return () => window.removeEventListener('archiplan:tab', h);
  }, []);

  // Al seleccionar algo, mostrar propiedades automáticamente
  const selKey = selNodes.map((n) => n.id).join(',') + selEdges.map((e) => e.id).join(',');
  const [lastSel, setLastSel] = useState('');
  if (selKey !== lastSel) {
    setLastSel(selKey);
    if (selKey && tab !== 'props') setTab('props');
  }

  return (
    <aside className="sidebar">
      <nav className="tabs">
        <button className={tab === 'props' ? 'on' : ''} onClick={() => setTab('props')}>
          Propiedades
        </button>
        <button className={tab === 'issues' ? 'on' : ''} onClick={() => setTab('issues')}>
          Validación
          {counts.error > 0 && <span className="count err">{counts.error}</span>}
          {counts.error === 0 && counts.warn > 0 && <span className="count warn">{counts.warn}</span>}
        </button>
        <button className={tab === 'guide' ? 'on' : ''} onClick={() => setTab('guide')}>
          Guía <span className="count plain">{done}/{guide.length}</span>
        </button>
        <button className={tab === 'adr' ? 'on' : ''} onClick={() => setTab('adr')}>
          ADR {decisions.length > 0 && <span className="count plain">{decisions.length}</span>}
        </button>
      </nav>
      <div className="side-body">
        {tab === 'props' && <Inspector selNodes={selNodes} selEdges={selEdges} issues={issues} />}
        {tab === 'issues' && <IssuesPanel issues={issues} />}
        {tab === 'guide' && <GuidePanel guide={guide} />}
        {tab === 'adr' && <DecisionsPanel decisions={decisions} />}
      </div>
    </aside>
  );
}

/* ───────────────────────── Inspector */

function Field({ label, children, help }: { label: string; children: React.ReactNode; help?: string }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

function PropInput({ def, value, onChange }: { def: PropDef; value: PropValue | undefined; onChange: (v: PropValue) => void }) {
  if (def.type === 'bool')
    return (
      <label className="toggle">
        <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
        <span>{def.label}</span>
      </label>
    );
  if (def.type === 'select')
    return (
      <Field label={def.label} help={def.help}>
        <select value={String(value ?? def.default)} onChange={(e) => onChange(e.target.value)}>
          {def.options.map((o) => (
            <option key={o}>{o}</option>
          ))}
        </select>
      </Field>
    );
  if (def.type === 'number')
    return (
      <Field label={def.label} help={def.help}>
        <input type="number" min={def.min} max={def.max} value={Number(value ?? def.default)} onChange={(e) => onChange(Number(e.target.value))} />
      </Field>
    );
  return (
    <Field label={def.label} help={def.help}>
      <input value={String(value ?? def.default)} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
}

function Inspector({ selNodes, selEdges, issues }: { selNodes: AppNode[]; selEdges: AppEdge[]; issues: Issue[] }) {
  if (selNodes.length + selEdges.length > 1) {
    return (
      <div className="pad">
        <p className="muted">
          {selNodes.length} piezas y {selEdges.length} conexiones seleccionadas.
        </p>
        <button className="btn danger" onClick={() => useStore.getState().deleteIds([...selNodes.map((n) => n.id), ...selEdges.map((e) => e.id)])}>
          Eliminar selección
        </button>
      </div>
    );
  }
  if (selNodes[0] && isService(selNodes[0])) return <ServiceInspector node={selNodes[0]} issues={issues} />;
  if (selNodes[0] && isZone(selNodes[0])) return <ZoneInspector node={selNodes[0]} issues={issues} />;
  if (selEdges[0]) return <EdgeInspector edge={selEdges[0]} />;
  return <ProjectInspector />;
}

function NodeIssues({ id, issues }: { id: string; issues: Issue[] }) {
  const mine = issues.filter((i) => i.nodeIds.includes(id) && !i.edgeIds?.length);
  if (!mine.length) return null;
  return (
    <div className="mini-issues">
      {mine.map((i) => (
        <IssueCard key={i.id} issue={i} compact />
      ))}
    </div>
  );
}

function ServiceInspector({ node, issues }: { node: ServiceNode; issues: Issue[] }) {
  const { updateNode, deleteIds, focus } = useStore.getState();
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const def = getService(node.data.serviceId);
  const map = byId(nodes);
  const place = placementOf(node, map);
  const conns = edges.filter((e) => e.source === node.id || e.target === node.id);
  return (
    <div className="inspector">
      <div className="insp-head">
        <ServiceIcon def={def} size={40} />
        <div>
          <div className="insp-title">{def.name}</div>
          <div className="insp-sub">
            {CATEGORIES[def.category].label} · Capa {LAYERS[def.layer].label.toLowerCase()}
          </div>
        </div>
      </div>
      <p className="insp-desc">{def.description}</p>
      <Field label="Nombre en el diagrama">
        <input value={node.data.label} onChange={(e) => updateNode(node.id, { label: e.target.value })} />
      </Field>
      <div className="insp-place">
        <span>Ubicación actual:</span> <b>{PLACEMENT_LABEL[place]}</b>
        <div className="muted small">Válidas: {def.zones.map((z) => PLACEMENT_LABEL[z]).join(' · ')}</div>
      </div>
      <NodeIssues id={node.id} issues={issues} />
      {def.props?.length ? (
        <div className="insp-section">
          <div className="insp-section-title">Configuración</div>
          {def.props.map((p) => (
            <PropInput key={p.key} def={p} value={node.data.props[p.key]} onChange={(v) => updateNode(node.id, { props: { [p.key]: v } })} />
          ))}
        </div>
      ) : null}
      <SimSection node={node} />
      <Field label="Notas / responsabilidad">
        <textarea rows={3} placeholder="¿Qué hace esta pieza? ¿Quién es dueño?" value={node.data.notes ?? ''} onChange={(e) => updateNode(node.id, { notes: e.target.value })} />
      </Field>
      <div className="insp-section">
        <div className="insp-section-title">Conexiones ({conns.length})</div>
        {conns.length === 0 && <div className="muted small">Arrastra desde un punto del borde de la pieza hacia otra.</div>}
        {conns.map((e) => {
          const other = map.get(e.source === node.id ? e.target : e.source);
          const label = (other?.data as { label?: string })?.label ?? '?';
          return (
            <button key={e.id} className="conn-row" onClick={() => focus([e.id, e.source, e.target])}>
              <span>{e.source === node.id ? '→' : '←'}</span>
              <span className="conn-name">{label}</span>
              <span className="conn-proto">{(e.data as ConnData)?.protocol}</span>
            </button>
          );
        })}
      </div>
      <button className="btn danger block" onClick={() => deleteIds([node.id])}>
        Eliminar pieza
      </button>
    </div>
  );
}

function SimSection({ node }: { node: ServiceNode }) {
  const { updateNode } = useStore.getState();
  const simOpen = useSim((s) => s.open);
  const frame = useSim((s) => (s.open && s.result ? s.result.frames[s.idx] : null));
  const p = profileFor(node);
  if (p.passive || ['user', 'admin'].includes(node.data.serviceId)) return null;
  const f = frame?.nodes[node.id];
  const capTotal = Number.isFinite(p.perInstance) ? p.perInstance * (p.scale === 'instant' ? 1 : p.instances) : Infinity;
  const ov = node.data.props['sim.capacity'];
  const setProp = (k: string, v: string | number | boolean) => updateNode(node.id, { props: { [k]: v } });
  return (
    <div className="insp-section sim-section">
      <div className="insp-section-title">Simulación</div>
      <div className="sim-cap">
        <div>
          <b>{fmtRps(capTotal)}</b> req/s de capacidad inicial
          {p.instances > 1 && p.scale !== 'instant' ? ` (${fmtRps(p.perInstance)} × ${p.instances})` : ''}
          {p.maxInstances > p.instances ? ` · escala hasta ×${p.maxInstances}` : ''}
        </div>
        <div className="muted small">{p.basis}</div>
        {p.quota && <div className="muted small">Cuota: {p.quota}</div>}
      </div>
      {simOpen && f && (
        <div className={`sim-now-node st-${f.status}`}>
          Ahora: <b>{fmtRps(f.offered)} req/s</b>
          {Number.isFinite(f.cap) && f.cap > 0 ? ` de ${fmtRps(f.cap)} (${Math.round(f.util * 100)}%)` : f.status === 'down' ? ' — caído' : ''}
        </div>
      )}
      <Field label="Capacidad por instancia (req/s)" help="Déjalo vacío para usar la estimación. Pon aquí el resultado de tus pruebas de carga.">
        <input type="number" min={0} placeholder={Number.isFinite(p.perInstance) ? String(Math.round(p.perInstance)) : '∞'} value={ov === undefined || ov === '' ? '' : Number(ov)} onChange={(e) => setProp('sim.capacity', e.target.value === '' ? '' : Number(e.target.value))} />
      </Field>
      {node.data.serviceId === 'lambda' && (
        <div className="row gap">
          <Field label="Duración media (ms)">
            <input type="number" min={1} value={Number(node.data.props['sim.durationMs'] ?? 120)} onChange={(e) => setProp('sim.durationMs', Number(e.target.value))} />
          </Field>
          <Field label="Concurrencia máx.">
            <input type="number" min={1} value={Number(node.data.props['sim.concurrency'] ?? 1000)} onChange={(e) => setProp('sim.concurrency', Number(e.target.value))} />
          </Field>
        </div>
      )}
      {node.data.serviceId === 'ecs' && (
        <label className="toggle">
          <input type="checkbox" checked={node.data.props['sim.autoscaling'] === undefined ? true : !!node.data.props['sim.autoscaling']} onChange={(e) => setProp('sim.autoscaling', e.target.checked)} />
          <span>Service Auto Scaling</span>
        </label>
      )}
    </div>
  );
}

function ZoneInspector({ node, issues }: { node: ZoneNode; issues: Issue[] }) {
  const { updateNode, deleteIds } = useStore.getState();
  const z = ZONES[node.data.zoneKind];
  const kids = useStore((s) => s.nodes.filter((n) => n.parentId === node.id).length);
  return (
    <div className="inspector">
      <div className="insp-head">
        <div className="zone-swatch" style={{ borderColor: z.color }} />
        <div>
          <div className="insp-title">{z.label}</div>
          <div className="insp-sub">{kids} elementos dentro</div>
        </div>
      </div>
      <p className="insp-desc">{z.help}</p>
      <Field label="Nombre">
        <input value={node.data.label} onChange={(e) => updateNode(node.id, { label: e.target.value })} />
      </Field>
      {z.props.map((p) => (
        <PropInput key={p.key} def={p} value={node.data.props[p.key]} onChange={(v) => updateNode(node.id, { props: { [p.key]: v } })} />
      ))}
      <NodeIssues id={node.id} issues={issues} />
      <p className="muted small">Redimensiona la zona desde sus esquinas. Al eliminarla, su contenido se conserva.</p>
      <button className="btn danger block" onClick={() => deleteIds([node.id])}>
        Eliminar zona
      </button>
    </div>
  );
}

function EdgeInspector({ edge }: { edge: AppEdge }) {
  const { updateEdge, deleteIds, reverseEdge } = useStore.getState();
  const nodes = useStore((s) => s.nodes);
  const map = byId(nodes);
  const s = map.get(edge.source);
  const t = map.get(edge.target);
  const d = (edge.data ?? {}) as ConnData;
  const v = s && t ? evaluateConnection(s, t, map) : null;
  return (
    <div className="inspector">
      <div className="insp-title">Conexión</div>
      <div className="edge-ends">
        <b>{(s?.data as { label: string })?.label}</b> → <b>{(t?.data as { label: string })?.label}</b>
      </div>
      {v && v.level !== 'ok' && v.msg && <div className={`rule-msg ${v.level}`}>{v.msg}</div>}
      {v && v.level === 'ok' && <div className="rule-msg ok">Conexión válida según las reglas.</div>}
      <Field label="Protocolo / interacción">
        <input value={d.protocol ?? ''} onChange={(e) => updateEdge(edge.id, { protocol: e.target.value })} list="protocols" />
        <datalist id="protocols">
          {['HTTPS', 'HTTP 8080', 'gRPC', 'GraphQL', 'WebSocket', 'PostgreSQL 5432', 'MySQL 3306', 'Redis 6379', 'async (SendMessage)', 'evento', 'logs/métricas', 'SFTP', 'VPN/IPsec'].map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
      </Field>
      <label className="toggle">
        <input type="checkbox" checked={!!d.async} onChange={(e) => updateEdge(edge.id, { async: e.target.checked })} />
        <span>Asíncrona (línea punteada)</span>
      </label>
      <Field label="Descripción del flujo">
        <textarea rows={3} placeholder="Ej.: consulta de catálogo, publica OrdenCreada…" value={d.description ?? ''} onChange={(e) => updateEdge(edge.id, { description: e.target.value })} />
      </Field>
      <div className="row gap">
        <button className="btn" onClick={() => reverseEdge(edge.id)}>
          Invertir dirección
        </button>
        <button className="btn danger" onClick={() => deleteIds([edge.id])}>
          Eliminar
        </button>
      </div>
    </div>
  );
}

function ProjectInspector() {
  const meta = useStore((s) => s.meta);
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const setMeta = useStore((s) => s.setMeta);
  const services = nodes.filter(isService);
  return (
    <div className="inspector">
      <div className="insp-title">Proyecto</div>
      <p className="muted small">Selecciona una pieza, zona o conexión para editarla.</p>
      <Field label="Nombre">
        <input value={meta.name} onChange={(e) => setMeta({ name: e.target.value })} />
      </Field>
      <Field label="Descripción / objetivo de negocio">
        <textarea rows={4} value={meta.description} placeholder="¿Qué problema resuelve esta solución?" onChange={(e) => setMeta({ description: e.target.value })} />
      </Field>
      <div className="row gap">
        <Field label="Autor">
          <input value={meta.author} onChange={(e) => setMeta({ author: e.target.value })} />
        </Field>
        <Field label="Ambiente">
          <select value={meta.environment} onChange={(e) => setMeta({ environment: e.target.value })}>
            {['producción', 'staging', 'desarrollo', 'pruebas'].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Región AWS por defecto">
        <input value={meta.region} onChange={(e) => setMeta({ region: e.target.value })} />
      </Field>
      <div className="stats">
        <div>
          <b>{services.length}</b>
          <span>piezas</span>
        </div>
        <div>
          <b>{edges.length}</b>
          <span>conexiones</span>
        </div>
        <div>
          <b>{nodes.length - services.length}</b>
          <span>zonas</span>
        </div>
      </div>
      <div className="insp-section">
        <div className="insp-section-title">Atajos</div>
        <ul className="shortcuts">
          <li><kbd>Ctrl</kbd>+<kbd>Z</kbd> / <kbd>Ctrl</kbd>+<kbd>Y</kbd> deshacer / rehacer</li>
          <li><kbd>Ctrl</kbd>+<kbd>S</kbd> guardar</li>
          <li><kbd>Supr</kbd> eliminar selección</li>
          <li><kbd>Shift</kbd>+arrastrar: selección múltiple</li>
        </ul>
      </div>
    </div>
  );
}

/* ───────────────────────── Validación */

function IssueCard({ issue, compact }: { issue: Issue; compact?: boolean }) {
  const { focus, applyFix } = useStore.getState();
  return (
    <div className={`issue ${issue.severity}`}>
      <button className="issue-main" onClick={() => (issue.nodeIds.length || issue.edgeIds?.length) && focus([...(issue.edgeIds ?? []), ...issue.nodeIds])}>
        <span className={`sev ${issue.severity}`}>{issue.severity === 'error' ? 'Error' : issue.severity === 'warn' ? 'Aviso' : 'Sugerencia'}</span>
        {!compact && <span className="issue-title">{issue.title}</span>}
        <span className="issue-detail">{issue.detail}</span>
      </button>
      {issue.fix && (
        <button className="btn small fix" onClick={() => applyFix(issue.fix!)}>
          ⚡ {issue.fix.label}
        </button>
      )}
    </div>
  );
}

function IssuesPanel({ issues }: { issues: Issue[] }) {
  const [show, setShow] = useState<{ error: boolean; warn: boolean; info: boolean }>({ error: true, warn: true, info: true });
  const list = issues.filter((i) => show[i.severity]);
  const fixable = issues.filter((i) => i.fix && i.severity !== 'info');
  return (
    <div className="issues-panel">
      <div className="filters">
        {(['error', 'warn', 'info'] as const).map((s) => (
          <button key={s} className={`chip ${s} ${show[s] ? 'on' : ''}`} onClick={() => setShow({ ...show, [s]: !show[s] })}>
            {s === 'error' ? 'Errores' : s === 'warn' ? 'Avisos' : 'Sugerencias'} · {issues.filter((i) => i.severity === s).length}
          </button>
        ))}
      </div>
      {fixable.length > 1 && (
        <button
          className="btn block"
          onClick={() => {
            // Aplica uno a uno y revalida tras cada arreglo (evita duplicar piezas, p. ej. dos WAF)
            const tried = new Set<string>();
            for (let k = 0; k < 30; k++) {
              const st = useStore.getState();
              const next = validate(st.nodes, st.edges).find((i) => i.fix && i.severity !== 'info' && !tried.has(i.id));
              if (!next) break;
              tried.add(next.id);
              st.applyFix(next.fix!);
            }
          }}
        >
          ⚡ Aplicar {fixable.length} arreglos automáticos
        </button>
      )}
      {issues.length === 0 && (
        <div className="all-good">
          <div className="big">✓</div>
          <div>Sin hallazgos. La arquitectura cumple todas las reglas.</div>
        </div>
      )}
      {list.map((i) => (
        <IssueCard key={i.id} issue={i} />
      ))}
    </div>
  );
}

/* ───────────────────────── Guía paso a paso */

function GuidePanel({ guide }: { guide: GuideStep[] }) {
  const { addService, addZone, focus } = useStore.getState();
  const view = useStore((s) => s.view);
  const current = guide.find((g) => !g.done && !g.optional) ?? guide.find((g) => !g.done);
  const [open, setOpen] = useState<string | null>(null);
  const expanded = open ?? current?.id ?? null;
  const pct = Math.round((guide.filter((g) => g.done).length / guide.length) * 100);
  return (
    <div className="guide">
      <div className="progress">
        <div className="progress-bar" style={{ width: `${pct}%` }} />
      </div>
      <div className="muted small" style={{ marginBottom: 10 }}>
        {current ? (
          <>
            Siguiente paso: <b>{current.title.replace(/^\d+\.\s*/, '')}</b>
          </>
        ) : (
          '¡Checklist completo! Exporta el documento de arquitectura.'
        )}
      </div>
      {guide.map((g) => (
        <div key={g.id} className={`step ${g.done ? 'done' : ''} ${current?.id === g.id ? 'current' : ''}`}>
          <button className="step-head" onClick={() => setOpen(expanded === g.id ? '' : g.id)}>
            <span className="step-check">{g.done ? '✓' : ''}</span>
            <span className="step-title">
              {g.title}
              {g.optional && <em> (opcional)</em>}
            </span>
          </button>
          {expanded === g.id && (
            <div className="step-body">
              <div className="step-q">{g.question}</div>
              <div className="step-tip">{g.tip}</div>
              {g.suggest.length > 0 && (
                <div className="sugs">
                  {g.suggest.map((id) => {
                    const def = SERVICE_MAP[id];
                    return (
                      <button key={id} className="sug" disabled={view !== 'c2'} onClick={() => focus([addService(id)])} title={def.description}>
                        <ServiceIcon def={def} size={20} />
                        {def.name.replace(/^(Amazon|AWS) /, '')}
                      </button>
                    );
                  })}
                </div>
              )}
              {g.zones && (
                <div className="sugs">
                  {g.zones.map((z) => (
                    <button key={z} className="sug zone-sug" style={{ ['--zc' as string]: ZONES[z].color }} disabled={view !== 'c2'} onClick={() => focus([addZone(z)])}>
                      + {ZONES[z].label}
                    </button>
                  ))}
                </div>
              )}
              {g.id === 'adr' && (
                <button className="btn small" onClick={() => window.dispatchEvent(new CustomEvent('archiplan:tab', { detail: 'adr' }))}>
                  Ir a decisiones
                </button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ───────────────────────── Decisiones (ADR) */

function DecisionsPanel({ decisions }: { decisions: Decision[] }) {
  const { addDecision, updateDecision, deleteDecision } = useStore.getState();
  const [open, setOpen] = useState<string | null>(decisions[0]?.id ?? null);
  return (
    <div className="adrs">
      <p className="muted small">Registra por qué tomaste cada decisión importante. Aparecen en el documento de arquitectura.</p>
      <button className="btn primary block" onClick={() => addDecision()}>
        + Nueva decisión
      </button>
      {decisions.map((d, i) => (
        <div key={d.id} className={`adr-card ${open === d.id ? 'open' : ''}`}>
          <button className="adr-head" onClick={() => setOpen(open === d.id ? null : d.id)}>
            <span className="adr-num">ADR‑{String(i + 1).padStart(3, '0')}</span>
            <span className="adr-title">{d.title}</span>
            <span className={`adr-status ${d.status}`}>{d.status}</span>
          </button>
          {open === d.id && (
            <div className="adr-body">
              <Field label="Título">
                <input value={d.title} onChange={(e) => updateDecision(d.id, { title: e.target.value })} />
              </Field>
              <Field label="Estado">
                <select value={d.status} onChange={(e) => updateDecision(d.id, { status: e.target.value as Decision['status'] })}>
                  {['propuesta', 'aceptada', 'reemplazada', 'rechazada'].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </Field>
              <Field label="Contexto">
                <textarea rows={3} value={d.context} onChange={(e) => updateDecision(d.id, { context: e.target.value })} />
              </Field>
              <Field label="Decisión">
                <textarea rows={3} value={d.decision} onChange={(e) => updateDecision(d.id, { decision: e.target.value })} />
              </Field>
              <Field label="Consecuencias">
                <textarea rows={3} value={d.consequences} onChange={(e) => updateDecision(d.id, { consequences: e.target.value })} />
              </Field>
              <button className="btn danger small" onClick={() => deleteDecision(d.id)}>
                Eliminar
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
