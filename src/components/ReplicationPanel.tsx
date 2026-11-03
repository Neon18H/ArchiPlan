import { useMemo, useState } from 'react';
import { getService } from '../catalog/catalog';
import { isService } from '../lib/graph';
import { fmtDur } from '../resilience/model';
import { coverage, FAILURE_LABEL, MODE_MAP, REPLICA_MODES, replicaFamily, replicationLinks, suggestLinks, type FailureKind, type ReplicaLink, type ReplicaMode } from '../resilience/replication';
import type { ScenarioKind } from '../sim/scenarios';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import type { ServiceNode } from '../types';
import { useNetUi } from './NetInspector';
import { Num } from './ScalingInspector';

const SCENARIO_OF: Record<FailureKind, ScenarioKind> = { instance: 'instance-failure', az: 'az-failure', outage: 'node-outage', region: 'region-failure', corruption: 'data-corruption', ransomware: 'ransomware' };
const FAILURES: FailureKind[] = ['instance', 'az', 'outage', 'region', 'corruption', 'ransomware'];

export function simulateFailure(kind: FailureKind, targetId: string, onClose: () => void) {
  useStore.getState().setView('c2');
  useNetUi.getState().setView(false);
  const sim = useSim.getState();
  if (sim.mode !== 'load') sim.setMode('load');
  sim.setOpen(true);
  sim.setKind(SCENARIO_OF[kind]);
  if (['instance', 'outage', 'corruption', 'ransomware'].includes(kind)) sim.patch({ targetId });
  onClose();
}

function LinkCard({ l, onClose }: { l: ReplicaLink; onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const { updateNode, setReplica, focus } = useStore.getState();
  const label = (id: string) => (nodes.find((n) => n.id === id) as ServiceNode | undefined)?.data.label ?? id;
  const set = (props: Record<string, string | number | boolean>) => updateNode(l.replicaId, { props });
  return (
    <div className="repl-card">
      <div className="repl-head">
        <button className="linklike" onClick={() => focus([l.primaryId, l.replicaId])}>
          <b>{label(l.primaryId)}</b> <span className="repl-arrow">⟶</span> <b>{label(l.replicaId)}</b>
        </button>
        <button className="btn small" onClick={() => setReplica(l.replicaId, null)} title="Deja de tratarla como réplica (la pieza y la flecha quedan)">
          Quitar vínculo
        </button>
      </div>
      <div className="repl-modes" role="radiogroup" aria-label={`Tipo de réplica de ${label(l.replicaId)}`}>
        {REPLICA_MODES.map((m) => (
          <button key={m.id} role="radio" aria-checked={l.mode === m.id} className={l.mode === m.id ? 'on' : ''} onClick={() => set({ replicaMode: m.id, ...(m.id === 'standby' ? { failoverMode: 'auto' } : {}) })} title={m.help}>
            {m.label}
          </button>
        ))}
      </div>
      <p className="muted small repl-help">{MODE_MAP[l.mode].help}</p>
      <div className="repl-opts">
        <div className="seg-choice" role="radiogroup" aria-label="Modo de failover">
          <button role="radio" aria-checked={l.failover === 'auto'} className={l.failover === 'auto' ? 'on' : ''} onClick={() => set({ failoverMode: 'auto' })} title="Health check + promoción automática (RDS Multi‑AZ, Aurora, Route 53 ARC…)">
            Failover automático
          </button>
          <button role="radio" aria-checked={l.failover === 'manual'} className={l.failover === 'manual' ? 'on' : ''} onClick={() => set({ failoverMode: 'manual' })} title="Alguien detecta la caída y promueve la réplica con un runbook">
            Manual (runbook)
          </button>
        </div>
        {l.mode === 'delayed' && <Num label="Retraso" value={l.delayMin} min={1} max={1440} step={5} suffix="min" onChange={(v) => set({ delayMin: v })} />}
        {l.mode === 'isolated' && <Num label="Copia cada" value={l.copyEveryMin} min={5} max={1440} step={5} suffix="min" onChange={(v) => set({ copyEveryMin: v })} />}
      </div>
      <table className="repl-cov">
        <tbody>
          {FAILURES.map((f) => {
            const c = coverage(l, f);
            return (
              <tr key={f} className={c.covers ? 'ok' : 'bad'}>
                <th scope="row">{FAILURE_LABEL[f]}</th>
                <td className="repl-yes">{c.covers ? '✓ la cubre' : '✗ no la cubre'}</td>
                <td>{c.covers ? `vuelve en ${fmtDur(c.rtoS)} · ${c.rpoS > 0 ? `pierde ${fmtDur(c.rpoS)}` : 'sin pérdida'}` : ''}</td>
                <td className="repl-why">{c.why}</td>
                <td>
                  <button className="btn small" onClick={() => simulateFailure(f, l.primaryId, onClose)} title="Correr este escenario contra la primaria">
                    ▶
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ReplicationPanel({ onClose }: { onClose: () => void }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const { setReplica, createReplica } = useStore.getState();
  const links = useMemo(() => replicationLinks(nodes), [nodes]);
  const sugg = useMemo(() => suggestLinks(nodes, edges), [nodes, edges]);
  const data = nodes.filter((n): n is ServiceNode => isService(n) && !!replicaFamily(n) && !n.data.props.replicaOf);
  const [primary, setPrimary] = useState('');
  const [mode, setMode] = useState<ReplicaMode>('read');
  const [existing, setExisting] = useState('');
  const label = (id: string) => (nodes.find((n) => n.id === id) as ServiceNode | undefined)?.data.label ?? id;
  const prim = nodes.find((n) => n.id === primary) as ServiceNode | undefined;
  const sameFamily = prim ? nodes.filter((n): n is ServiceNode => isService(n) && n.id !== prim.id && replicaFamily(n) === replicaFamily(prim) && !n.data.props.replicaOf) : [];

  return (
    <div className="repl">
      <p className="muted small">
        Declara qué pieza es réplica de cuál y cómo hace failover. La simulación la usa: cuando la primaria cae, el tráfico pasa a la réplica (se ve en el lienzo) si ese tipo de réplica cubre la falla. Una réplica en vivo <b>no</b> protege de borrados ni de ransomware: copia el daño.
      </p>

      {sugg.map((g) => (
        <div key={g.replicaId + g.primaryId} className="repl-sugg">
          <span>
            <b>{label(g.replicaId)}</b> está conectada a <b>{label(g.primaryId)}</b> y es del mismo tipo. ¿Es su réplica?
          </span>
          <button className="btn small primary" onClick={() => setReplica(g.replicaId, g.primaryId, { replicaMode: 'read', failoverMode: 'manual' })}>
            Sí, {label(g.replicaId)} es réplica
          </button>
          <button className="btn small" onClick={() => setReplica(g.primaryId, g.replicaId, { replicaMode: 'read', failoverMode: 'manual' })}>
            Al revés
          </button>
        </div>
      ))}

      <div className="repl-new">
        <b>Agregar una réplica</b>
        <label className="small">
          Primaria{' '}
          <select value={primary} onChange={(e) => (setPrimary(e.target.value), setExisting(''))} aria-label="Pieza primaria">
            <option value="">Elige una pieza de datos…</option>
            {data.map((n) => (
              <option key={n.id} value={n.id}>
                {n.data.label} ({getService(n.data.serviceId).short})
              </option>
            ))}
          </select>
        </label>
        <label className="small">
          Tipo{' '}
          <select value={mode} onChange={(e) => setMode(e.target.value as ReplicaMode)} aria-label="Tipo de réplica">
            {REPLICA_MODES.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        {sameFamily.length > 0 && (
          <label className="small">
            Réplica{' '}
            <select value={existing} onChange={(e) => setExisting(e.target.value)} aria-label="Pieza réplica">
              <option value="">Crear una nueva en el diagrama</option>
              {sameFamily.map((n) => (
                <option key={n.id} value={n.id}>
                  Usar {n.data.label}
                </option>
              ))}
            </select>
          </label>
        )}
        <button
          className="btn small primary"
          disabled={!primary}
          onClick={() => {
            if (existing) setReplica(existing, primary, { replicaMode: mode, failoverMode: mode === 'standby' ? 'auto' : 'manual' });
            else createReplica(primary, mode);
            setPrimary('');
            setExisting('');
          }}
        >
          {existing ? 'Vincular' : '＋ Crear réplica'}
        </button>
      </div>

      {links.length ? links.map((l) => <LinkCard key={l.replicaId} l={l} onClose={onClose} />) : <div className="muted small pad">Todavía no hay réplicas declaradas en el diagrama.</div>}
    </div>
  );
}
