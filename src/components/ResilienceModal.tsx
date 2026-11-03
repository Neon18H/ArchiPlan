import { useMemo } from 'react';
import { buildPlan, drOf, DR_STRATEGIES, fmtDur, type LevelTotal, type PlanCell, type ResFix } from '../resilience/model';
import type { ScenarioKind } from '../sim/scenarios';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import { Modal } from './Modals';
import { useNetUi } from './NetInspector';
import { ReplicationPanel } from './ReplicationPanel';
import { create } from 'zustand';
import { replicationLinks, suggestLinks } from '../resilience/replication';

export const useResTab = create<{ tab: 'plan' | 'replication'; setTab: (t: 'plan' | 'replication') => void }>((set) => ({ tab: 'plan', setTab: (tab) => set({ tab }) }));

export function applyResFix(fix: ResFix) {
  const st = useStore.getState();
  if (fix.nodeId && fix.props) st.updateNode(fix.nodeId, { props: fix.props });
  if (fix.dr) st.setMeta({ dr: { ...drOf(st.meta), ...fix.dr } });
  if (fix.security) st.setSecurity({ [fix.security]: true });
  st.toast('ok', `Aplicado: ${fix.label}`);
}

function runScenario(kind: ScenarioKind, onClose: () => void) {
  useStore.getState().setView('c2');
  useNetUi.getState().setView(false);
  const sim = useSim.getState();
  if (sim.mode !== 'load') sim.setMode('load');
  sim.setOpen(true);
  sim.setKind(kind);
  onClose();
}

const ICON = { ok: '✓', warn: '!', bad: '✗', na: '·' } as const;

function Cell({ c }: { c: PlanCell | null }) {
  if (!c) return <td className="res-td na">—</td>;
  return (
    <td className={`res-td ${c.status}`} title={c.text}>
      <div className="res-td-head">
        <span className={`res-ic ${c.status}`}>{ICON[c.status]}</span>
        <b>{c.status === 'na' ? '—' : Number.isFinite(c.rtoS) ? (c.rtoS > 0 ? fmtDur(c.rtoS) : 'sin corte') : 'no vuelve'}</b>
        {c.rpoS > 0 && <em>{Number.isFinite(c.rpoS) ? `pierde ${fmtDur(c.rpoS)}` : 'sin copia'}</em>}
      </div>
      {c.target && <div className="res-target">→ {c.target}</div>}
      <p>{c.text}</p>
      {c.fix && (
        <button className="btn small fix" onClick={() => applyResFix(c.fix!)}>
          ⚡ {c.fix.label}
        </button>
      )}
    </td>
  );
}

export function ResilienceModal({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const meta = useStore((s) => s.meta);
  const security = useStore((s) => s.security);
  const setMeta = useStore((s) => s.setMeta);
  const focus = useStore((s) => s.focus);
  const dr = drOf(meta);
  const plan = useMemo(() => buildPlan(nodes, edges, { dr, security }), [nodes, edges, dr, security]); // eslint-disable-line react-hooks/exhaustive-deps
  const setDr = (patch: Partial<typeof dr>) => setMeta({ dr: { ...dr, ...patch } });
  // Primero lo que falla; dentro de eso, la ruta crítica; los servicios globales al final
  const sevOf = (r: (typeof plan.rows)[number]) => Math.max(...[r.instance, r.az, r.region, r.data].map((c) => (!c ? 0 : c.status === 'bad' ? 3 : c.status === 'warn' ? 2 : c.status === 'ok' ? 1 : 0)));
  const tab = useResTab((s) => s.tab);
  const setTab = useResTab((s) => s.setTab);
  const nLinks = replicationLinks(nodes).length;
  const nSugg = suggestLinks(nodes, edges).length;
  const rows = [...plan.rows].sort((a, b) => Number(['global', 'dns'].includes(a.kind)) - Number(['global', 'dns'].includes(b.kind)) || sevOf(b) - sevOf(a) || Number(b.critical) - Number(a.critical));

  const tot = (title: string, t: LevelTotal, kind: ScenarioKind, sub: string) => {
    const rtoOk = t.rtoS <= dr.rtoMin * 60;
    const rpoOk = t.rpoS <= dr.rpoMin * 60;
    const cls = !Number.isFinite(t.rtoS) ? 'bad' : rtoOk && rpoOk ? 'ok' : 'warn';
    return (
      <div className={`res-total ${cls}`}>
        <span>{title}</span>
        <b>{Number.isFinite(t.rtoS) ? (t.rtoS > 0 ? fmtDur(t.rtoS) : 'sin corte') : 'no vuelve'}</b>
        <em>
          {t.rpoS > 0 ? (Number.isFinite(t.rpoS) ? `pierde ${fmtDur(t.rpoS)} de datos` : 'datos sin copia') : 'sin pérdida de datos'}
          {t.worst && t.rtoS > 0 ? ` · lo más lento: ${t.worst}` : ''}
        </em>
        <small>{sub}</small>
        <button className="btn small" onClick={() => runScenario(kind, onClose)}>
          ▶ Simular
        </button>
      </div>
    );
  };

  return (
    <Modal title="Resiliencia y recuperación ante desastres" onClose={onClose} wide>
      <div className="res-modal">
        <div className="tabs res-tabs" role="tablist">
          <button role="tab" aria-selected={tab === 'plan'} className={tab === 'plan' ? 'on' : ''} onClick={() => setTab('plan')}>
            Plan de failover
          </button>
          <button role="tab" aria-selected={tab === 'replication'} className={tab === 'replication' ? 'on' : ''} onClick={() => setTab('replication')}>
            Replicación y failover {nLinks ? `(${nLinks})` : ''}
            {nSugg > 0 && <span className="tb-dot" aria-label="réplicas sin configurar" />}
          </button>
        </div>
        {tab === 'replication' ? (
          <ReplicationPanel onClose={onClose} />
        ) : (
        <>
        <p className="muted small res-intro">
          A qué recurso falla cada pieza, en cuánto tiempo vuelve el servicio (RTO) y cuántos datos se pierden (RPO) ante la caída de una instancia, de una zona, de la región completa, o si los datos se dañan. Cada cifra se puede comprobar con la simulación.
        </p>

        <div className="res-dr">
          <div className="res-dr-head">
            <b>Estrategia ante la caída de la región</b>
            <label className="small">
              Región secundaria <input value={dr.secondaryRegion} onChange={(e) => setDr({ secondaryRegion: e.target.value })} aria-label="Región secundaria" />
            </label>
            <label className="small">
              RTO objetivo <input type="number" min={1} value={dr.rtoMin} onChange={(e) => setDr({ rtoMin: Math.max(1, Number(e.target.value) || 1) })} aria-label="RTO objetivo en minutos" /> min
            </label>
            <label className="small">
              RPO objetivo <input type="number" min={0} value={dr.rpoMin} onChange={(e) => setDr({ rpoMin: Math.max(0, Number(e.target.value) || 0) })} aria-label="RPO objetivo en minutos" /> min
            </label>
          </div>
          <div className="res-strategies" role="radiogroup" aria-label="Estrategia de DR">
            {DR_STRATEGIES.map((s) => (
              <button key={s.id} role="radio" aria-checked={dr.strategy === s.id} className={`res-strategy ${dr.strategy === s.id ? 'on' : ''}`} onClick={() => setDr({ strategy: s.id })}>
                <b>{s.label}</b>
                <span className="res-cost">{s.cost}</span>
                <small>
                  RTO {s.rto} · RPO {s.rpo}
                </small>
                <em>{s.help}</em>
              </button>
            ))}
          </div>
          <p className={`res-dns ${plan.dns.automatic ? 'ok' : 'warn'}`}>
            <b>DNS:</b> {plan.dns.text}
          </p>
        </div>

        <div className="res-totals">
          {tot('Falla una instancia', plan.totals.instance, 'instance-failure', 'Health checks, standby, réplicas')}
          {tot('Cae una AZ', plan.totals.az, 'az-failure', 'Reparto en AZ y Multi‑AZ')}
          {tot('Cae la región', plan.totals.region, 'region-failure', 'Estrategia de DR + DNS')}
          {tot('Datos dañados', plan.totals.data, 'data-corruption', 'Backups, PITR, versionado')}
          {tot('Ransomware', plan.totals.ransomware, 'ransomware', 'Copias fuera de la cuenta')}
        </div>

        {plan.issues.length > 0 && (
          <div className="res-issues">
            {plan.issues.slice(0, 8).map((i, k) => (
              <div key={k} className={`res-issue ${i.severity}`}>
                <button className="linklike" onClick={() => i.nodeIds.length && focus(i.nodeIds)}>
                  {i.text}
                </button>
                {i.fix && (
                  <button className="btn small fix" onClick={() => applyResFix(i.fix!)}>
                    ⚡ {i.fix.label}
                  </button>
                )}
              </div>
            ))}
            {plan.issues.length > 8 && <div className="muted small">… y {plan.issues.length - 8} más en la tabla.</div>}
          </div>
        )}

        <div className="res-table-wrap">
          <table className="res-table">
            <thead>
              <tr>
                <th>Pieza</th>
                <th>Falla una instancia / nodo</th>
                <th>Cae una AZ</th>
                <th>Cae la región</th>
                <th>Datos dañados</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.nodeId}>
                  <th scope="row">
                    <button
                      className="linklike"
                      onClick={() => {
                        focus([r.nodeId]);
                        useStore.getState().select([r.nodeId]);
                        onClose();
                      }}
                      title="Configurar su redundancia en el panel de propiedades"
                    >
                      <b>{r.label}</b>
                    </button>
                    <span className="muted small">
                      {r.service}
                      {r.critical ? ' · ruta crítica' : ''}
                    </span>
                    {r.replicaOf && <span className="repl-tag">⟲ réplica de {r.replicaOf}</span>}
                    {r.replicas && <span className="repl-tag">⟲ réplicas: {r.replicas.join(', ')}</span>}
                  </th>
                  <Cell c={r.instance} />
                  <Cell c={r.az} />
                  <Cell c={r.region} />
                  <Cell c={r.data} />
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">Tiempos típicos documentados por el proveedor; sirven para comparar diseños. Valídalos con un Game Day real (AWS Fault Injection Service / Azure Chaos Studio).</p>
        </>
        )}
      </div>
    </Modal>
  );
}
