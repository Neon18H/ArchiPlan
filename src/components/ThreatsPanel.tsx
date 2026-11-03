import { useMemo, useState } from 'react';
import { download } from '../export/image';
import { slugify } from '../lib/api';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import { STATUS_LABEL, STRIDE, summarizeThreats, threatsToCsv, type Stride, type Threat, type ThreatStatus } from '../threats/model';
import type { ThreatStatusOverride } from '../types';
import { SETTING_MAP, SECURITY_GROUPS, SECURITY_SETTINGS } from '../security/settings';
import { Switch, useNetUi } from './NetInspector';
import { openSecurity } from './SecurityPanel';

const RISK_ORDER = ['Crítico', 'Alto', 'Medio', 'Bajo'] as const;

export function StrideLetters({ s }: { s: Stride[] }) {
  return (
    <span className="stride-letters">
      {(Object.keys(STRIDE) as Stride[]).map((k) => (
        <i key={k} className={s.includes(k) ? 'on' : ''} style={s.includes(k) ? { background: STRIDE[k].color } : undefined} title={`${STRIDE[k].es} (${STRIDE[k].name}) — ${STRIDE[k].property}`}>
          {k}
        </i>
      ))}
    </span>
  );
}

function ThreatCard({ t, open, onToggle }: { t: Threat; open: boolean; onToggle: () => void }) {
  const { setThreatState, setThreatControl, applyFix, focus, setView } = useStore.getState();
  const pending = t.controls.filter((c) => c.required && !c.ok).length;
  const override = (t.status === t.computedStatus ? '' : t.status) as ThreatStatusOverride | '';
  return (
    <div className={`threat ${open ? 'open' : ''} st-${t.status}`}>
      <button className="threat-head" onClick={onToggle}>
        <StrideLetters s={t.stride} />
        <span className="threat-title">{t.title}</span>
        <span className={`risk-pill r-${t.risk}`}>{t.risk}</span>
        <span className={`status-pill s-${t.status}`}>{STATUS_LABEL[t.status]}</span>
      </button>
      {open && (
        <div className="threat-body">
          <p>{t.description}</p>
          {t.boundary && (
            <div className="boundary-chip" title="Este flujo cruza un límite de confianza">
              ⛨ Límite de confianza: {t.boundary}
            </div>
          )}
          <div className="threat-meta">
            <span>
              Probabilidad <b>{t.likelihood}</b>/3
            </span>
            <span>
              Impacto <b>{t.impact}</b>/3
            </span>
            <span>
              Riesgo <b>{t.score}</b>/9
            </span>
            {pending > 0 && <span className="warn">{pending} control(es) pendiente(s)</span>}
          </div>
          <div className="ctrl-title">Controles</div>
          <ul className="controls">
            {t.controls.map((c) => (
              <li key={c.key} className={`${c.ok ? 'ok' : ''} ${c.required ? 'req' : 'opt'}`}>
                {c.setting && c.source === 'proyecto' ? (
                  <Switch on={c.ok} onChange={(v) => useStore.getState().setSecurity({ [c.setting![0]]: v })} label={c.label} />
                ) : c.auto ? (
                  <span className={`ctrl-auto ${c.ok ? 'ok' : 'no'}`} title={c.source === 'red' ? 'Según la red configurada' : 'Se detecta en el diagrama'}>
                    {c.ok ? '✓' : '✗'}
                  </span>
                ) : (
                  <input type="checkbox" checked={c.ok} onChange={(e) => setThreatControl(t.id, c.key, e.target.checked)} aria-label={c.label} />
                )}
                <div className="ctrl-text">
                  <span>
                    {c.label}
                    {!c.required && <em> · recomendado</em>}
                    {c.group && <em> · alternativa</em>}
                  </span>
                  <span className="ctrl-src">
                    {c.source === 'proyecto' && c.setting ? (
                      <>
                        Seguridad del proyecto · {SECURITY_GROUPS.find((g) => g.id === SETTING_MAP.get(c.setting![0])?.group)?.label}{' '}
                        <button className="linklike small" onClick={openSecurity}>
                          ver todo
                        </button>
                      </>
                    ) : c.source === 'red' ? (
                      <>
                        Según tu red{' '}
                        <button className="linklike small" onClick={() => (setView('c2'), useNetUi.getState().setView(true))}>
                          ⛨ ver red
                        </button>
                      </>
                    ) : c.auto ? (
                      'Detectado en el diagrama'
                    ) : (
                      'Lo marcas tú cuando esté implementado'
                    )}
                  </span>
                  {c.hint && !c.ok && <span className="ctrl-hint">{c.hint}</span>}
                  {c.fix && !c.ok && !(c.source === 'proyecto' && c.fix.security) && (
                    <button
                      className="btn small fix"
                      onClick={() => {
                        applyFix(c.fix!);
                        // Mantener la lista completa: la pieza nueva se enfoca en el lienzo pero no filtra el panel
                        useStore.getState().select([]);
                      }}
                    >
                      ⚡ {c.fix.label}
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <div className="row gap threat-actions">
            <label className="field" style={{ flex: 1 }}>
              <span className="field-label">Estado</span>
              <select value={override} onChange={(e) => setThreatState(t.id, { status: (e.target.value || undefined) as ThreatStatusOverride | undefined })}>
                <option value="">Automático ({STATUS_LABEL[t.computedStatus]})</option>
                <option value="aceptada">Riesgo aceptado</option>
                <option value="mitigada">Mitigada (otro control)</option>
                <option value="no-aplica">No aplica</option>
              </select>
            </label>
            <label className="field" style={{ flex: 1 }}>
              <span className="field-label">Responsable</span>
              <input value={t.owner ?? ''} placeholder="Equipo o persona" onChange={(e) => setThreatState(t.id, { owner: e.target.value })} />
            </label>
          </div>
          <label className="field">
            <span className="field-label">{override === 'aceptada' || override === 'no-aplica' ? 'Justificación (obligatoria para auditoría)' : 'Notas'}</span>
            <textarea rows={2} value={t.note ?? ''} placeholder={override === 'aceptada' ? '¿Por qué se acepta el riesgo? ¿Quién lo aprobó y hasta cuándo?' : 'Detalles de la mitigación, ticket, enlace…'} onChange={(e) => setThreatState(t.id, { note: e.target.value })} />
          </label>
          {(override === 'aceptada' || override === 'no-aplica') && !t.note && <div className="ctrl-hint">Documenta la justificación para que el modelo sea auditable.</div>}
          <div className="refs">
            {t.refs.map((r) => (
              <span key={r}>{r}</span>
            ))}
          </div>
          <div className="row gap">
            {t.nodeIds.length > 0 && (
              <button className="btn small" onClick={() => (setView('c2'), focus([...(t.edgeId ? [t.edgeId] : []), ...t.nodeIds]))}>
                Ver en el diagrama
              </button>
            )}
            {t.sim && (
              <button
                className="btn small sim-btn"
                onClick={() => {
                  setView('c2');
                  const sim = useSim.getState();
                  sim.setOpen(true);
                  sim.setKind(t.sim!.kind);
                  if (t.sim!.targetId) sim.patch({ targetId: t.sim!.targetId });
                }}
              >
                ▶ {t.sim.label}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function ThreatsPanel({ threats }: { threats: Threat[] }) {
  const [strideF, setStrideF] = useState<Stride[]>([]);
  const [showAll, setShowAll] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const selected = useMemo(() => nodes.filter((n) => n.selected).map((n) => n.id), [nodes]);
  const selEdges = useMemo(() => edges.filter((e) => e.selected).map((e) => e.id), [edges]);
  const meta = useStore((s) => s.meta);
  const security = useStore((s) => s.security);
  const sum = summarizeThreats(threats);
  const [scopeOff, setScopeOff] = useState(false);
  const scoped = !scopeOff && (selected.length > 0 || selEdges.length > 0);

  const list = useMemo(() => {
    return threats.filter((t) => {
      if (!showAll && !(t.status === 'abierta' || t.status === 'parcial')) return false;
      if (strideF.length && !strideF.some((k) => t.stride.includes(k))) return false;
      if (scoped && !(t.nodeIds.some((id) => selected.includes(id)) || (t.edgeId && selEdges.includes(t.edgeId)))) return false;
      return true;
    });
  }, [threats, showAll, strideF, scoped, selected, selEdges]);

  const groups = useMemo(() => {
    const g = new Map<string, Threat[]>();
    for (const t of list) {
      const k = t.kind === 'account' ? t.element : t.kind === 'flow' ? 'Flujos que cruzan límites de confianza' : t.element;
      if (!g.has(k)) g.set(k, []);
      g.get(k)!.push(t);
    }
    return [...g.entries()];
  }, [list]);

  const pct = sum.total ? Math.round((sum.handled / sum.total) * 100) : 0;
  const statusCount = (s: ThreatStatus) => threats.filter((t) => t.status === s).length;

  return (
    <div className="threats-panel">
      <div className="risk-grid">
        {RISK_ORDER.map((r) => (
          <div key={r} className={`risk-box r-${r}`}>
            <b>{r === 'Crítico' ? sum.critical : r === 'Alto' ? sum.high : r === 'Medio' ? sum.medium : sum.low}</b>
            <span>{r === 'Crítico' ? 'Críticas' : r === 'Alto' ? 'Altas' : r === 'Medio' ? 'Medias' : 'Bajas'}</span>
          </div>
        ))}
      </div>
      <div className="muted small">
        {sum.open} pendientes de {sum.total} · {statusCount('mitigada')} mitigadas · {statusCount('aceptada')} aceptadas · {statusCount('no-aplica')} no aplican
      </div>
      <div className="progress" title={`${pct}% tratado`}>
        <div className="progress-bar" style={{ width: `${pct}%`, background: '#0ca30c' }} />
      </div>
      <button className="btn small sec-open" onClick={openSecurity}>
        ⚙ Seguridad del proyecto · {SECURITY_SETTINGS.filter((x) => security[x.key]).length}/{SECURITY_SETTINGS.length} activos
      </button>
      <button
        className="btn small atk-open"
        onClick={() => {
          useStore.getState().setView('c2');
          useNetUi.getState().setView(false);
          const sim = useSim.getState();
          sim.setOpen(true);
          sim.setMode('attack');
        }}
        title="Cómo llegaría un atacante desde Internet hasta tus datos (MITRE ATT&CK)"
      >
        ☠ Ver rutas de ataque
      </button>
      <div className="stride-filter">
        {sum.byStride.map(({ k, open: o }) => (
          <button key={k} className={strideF.includes(k) ? 'on' : ''} style={strideF.includes(k) ? { background: STRIDE[k].color, borderColor: STRIDE[k].color } : undefined} onClick={() => setStrideF(strideF.includes(k) ? strideF.filter((x) => x !== k) : [...strideF, k])} title={`${STRIDE[k].es}: ${STRIDE[k].property}`}>
            <b>{k}</b>
            <span>{o}</span>
          </button>
        ))}
      </div>
      <div className="row gap" style={{ justifyContent: 'space-between' }}>
        <div className="seg light">
          <button className={!showAll ? 'on' : ''} onClick={() => setShowAll(false)}>
            Pendientes
          </button>
          <button className={showAll ? 'on' : ''} onClick={() => setShowAll(true)}>
            Todas
          </button>
        </div>
        <button className="btn small" onClick={() => download(`${slugify(meta.name)}-amenazas.csv`, threatsToCsv(threats), 'text/csv;charset=utf-8')} title="Para importar en Jira, Excel o tu herramienta de GRC">
          Exportar CSV
        </button>
      </div>
      {scoped && (
        <div className="scope-banner">
          Amenazas de la selección ·{' '}
          <button className="linkish" onClick={() => setScopeOff(true)}>
            ver todas
          </button>
        </div>
      )}
      {!scoped && scopeOff && (selected.length > 0 || selEdges.length > 0) && (
        <div className="scope-banner">
          <button className="linkish" onClick={() => setScopeOff(false)}>
            Filtrar por la selección
          </button>
        </div>
      )}
      {threats.length === 0 && <div className="muted pad">Agrega piezas al diagrama para generar el modelo de amenazas.</div>}
      {threats.length > 0 && list.length === 0 && (
        <div className="all-good">
          <div className="big">✓</div>
          <div>{showAll ? 'Nada coincide con el filtro.' : 'No hay amenazas pendientes con este filtro.'}</div>
        </div>
      )}
      {groups.map(([g, ts]) => (
        <div key={g} className="threat-group">
          <button
            className="group-head"
            onClick={() => {
              const n = new Set(collapsed);
              if (n.has(g)) n.delete(g);
              else n.add(g);
              setCollapsed(n);
            }}
          >
            <span>{collapsed.has(g) ? '▸' : '▾'}</span>
            <b>{g}</b>
            <span className="muted">{ts.length}</span>
          </button>
          {!collapsed.has(g) && ts.map((t) => <ThreatCard key={t.id} t={t} open={open === t.id} onToggle={() => setOpen(open === t.id ? null : t.id)} />)}
        </div>
      ))}
      <p className="muted small" style={{ marginTop: 8 }}>
        STRIDE por elemento: las amenazas se generan según el rol de cada pieza, su zona de confianza y las flechas que cruzan límites. Los controles con ✓/✗ se detectan en el diagrama; los demás los marcas al implementarlos.
      </p>
    </div>
  );
}
