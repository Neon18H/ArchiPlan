import { memo } from 'react';
import { Handle, NodeResizer, Position, type NodeProps } from '@xyflow/react';
import { CATEGORIES, getService, ZONES } from '../catalog/catalog';
import type { ServiceNode, ZoneNode } from '../types';
import { useCanvasCtx } from './context';
import { fmtRps } from '../sim/profiles';
import type { NodeFrame } from '../sim/engine';
import { ServiceIcon } from './ServiceIcon';

const SIDES = [
  [Position.Top, 't'],
  [Position.Right, 'r'],
  [Position.Bottom, 'b'],
  [Position.Left, 'l'],
] as const;

const STATUS_LABEL: Record<NodeFrame['status'], string> = {
  ok: 'OK',
  hot: 'Alta carga',
  saturated: 'Saturado',
  degraded: 'Degradado',
  down: 'Caído',
  idle: 'Sin tráfico',
  passive: '',
};

function simExtra(f: NodeFrame): { text: string; tone?: 'good' | 'bad' } | null {
  if (f.blocked !== undefined) return { text: 'Tráfico malicioso detenido en el borde', tone: 'good' };
  if (f.healthy < f.instances) return { text: `${f.healthy}/${f.instances} instancias sanas`, tone: 'bad' };
  if (f.backlog !== undefined && f.backlog > 0.5) return { text: `Cola: ${fmtRps(f.backlog)} mensajes` };
  if (f.attack > 1 && f.status !== 'down') return { text: `${fmtRps(f.attack)} req/s maliciosos`, tone: 'bad' };
  if (f.absorbed !== undefined && f.absorbed > 1) return { text: `Caché absorbe ${fmtRps(f.absorbed)} req/s`, tone: 'good' };
  if (f.instances > 1) return { text: `${f.instances} instancias` };
  return null;
}

export const ServiceNodeView = memo(function ServiceNodeView({ id, data, selected }: NodeProps<ServiceNode>) {
  const def = getService(data.serviceId);
  const { nodeIssues, dimmed, readOnly, sim, stride } = useCanvasCtx();
  const simF = sim?.nodes[id];
  const thr = stride?.nodes.get(id);
  const issue = sim || stride ? undefined : nodeIssues.get(id);
  const color = CATEGORIES[def.category].color;
  const isActor = def.role === 'actor' || def.role === 'external';
  return (
    <div
      className={`svc ${selected ? 'is-selected' : ''} ${issue ? `has-${issue}` : ''} ${dimmed.has(id) ? 'is-dimmed' : ''} ${isActor ? 'is-actor' : ''} ${simF ? `sim-${simF.status}` : ''}`}
      style={{ ['--cat' as string]: color }}
      title={`${def.name}\n${def.description}`}
    >
      <ServiceIcon def={def} size={38} />
      <div className="svc-text">
        <div className="svc-label">{data.label}</div>
        {simF && !isActor && simF.status !== 'passive' ? (
          <>
            <div className={`svc-sim st-${simF.status}`}>
              {simF.blocked !== undefined ? `Bloqueando ${fmtRps(simF.blocked)} req/s` : simF.status === 'down' ? 'Caído' : simF.status === 'idle' ? 'Sin tráfico' : `${fmtRps(simF.offered)} req/s${Number.isFinite(simF.cap) && simF.cap > 0 ? ` · ${Math.round(Math.min(simF.util, 9.99) * 100)}%` : ''}`}
            </div>
            {(() => {
              const x = simExtra(simF);
              return x ? <div className={`svc-sim-extra ${x.tone ?? ''}`}>{x.text}</div> : null;
            })()}
          </>
        ) : (
          <>
            {data.label !== def.name && <div className="svc-kind">{def.name}</div>}
            {data.label === def.name && <div className="svc-kind">{CATEGORIES[def.category].label}</div>}
            {simF?.status === 'passive' && simF.blocked === undefined && <div className="svc-sim-extra">Fuera de la ruta del request</div>}
          </>
        )}
      </div>
      {simF && !isActor && ['saturated', 'down', 'degraded', 'hot'].includes(simF.status) && <span className={`sim-pill st-${simF.status}`}>{STATUS_LABEL[simF.status]}</span>}
      {simF && sim?.targetId === id && <span className="sim-target">Objetivo</span>}
      {thr && thr.open > 0 && (
        <span className={`thr-badge r-${thr.worst}`} title={`${thr.open} amenaza(s) pendiente(s) · máximo riesgo ${thr.worst}`}>
          ⛨ {thr.open}
        </span>
      )}
      {simF && !isActor && Number.isFinite(simF.cap) && simF.cap > 0 && simF.status !== 'passive' && simF.blocked === undefined && (
        <span className={`sim-ubar st-${simF.status}`}>
          <span style={{ width: `${Math.min(100, simF.util * 100)}%` }} />
        </span>
      )}
      {issue && <span className={`svc-badge ${issue}`}>{issue === 'error' ? '!' : issue === 'warn' ? '!' : 'i'}</span>}
      {data.notes ? <span className="svc-note" title={data.notes}>✎</span> : null}
      {!readOnly &&
        SIDES.map(([pos, key]) => <Handle key={key} id={key} type="source" position={pos} className="h" />)}
    </div>
  );
});

export const ZoneNodeView = memo(function ZoneNodeView({ id, data, selected }: NodeProps<ZoneNode>) {
  const z = ZONES[data.zoneKind];
  const { nodeIssues, dimmed, readOnly } = useCanvasCtx();
  const issue = nodeIssues.get(id);
  const extra = data.props.cidr ? String(data.props.cidr) : data.props.region ? String(data.props.region) : '';
  return (
    <div
      className={`zone zone-${data.zoneKind} ${selected ? 'is-selected' : ''} ${issue ? `has-${issue}` : ''} ${dimmed.size ? 'is-faded' : ''}`}
      style={{ ['--zc' as string]: z.color, ['--zbg' as string]: z.bg }}
    >
      {!readOnly && <NodeResizer isVisible={selected} minWidth={200} minHeight={120} color={z.color} />}
      <div className="zone-tab">
        <span className="zone-kind">{z.label}</span>
        {data.label !== z.label && <span className="zone-label">{data.label}</span>}
        {extra && <span className="zone-extra">{extra}</span>}
      </div>
    </div>
  );
});

/** Nodo de sistema usado en la vista C1 (contexto). */
export const SystemNodeView = memo(function SystemNodeView({ data }: NodeProps) {
  const d = data as { label: string; count: number; description: string };
  return (
    <div className="system-node">
      <div className="system-title">{d.label}</div>
      <div className="system-sub">Sistema de software · {d.count} componentes</div>
      {d.description && <div className="system-desc">{d.description}</div>}
      <Handle id="t" type="source" position={Position.Top} className="h" />
      <Handle id="l" type="source" position={Position.Left} className="h" />
      <Handle id="r" type="source" position={Position.Right} className="h" />
      <Handle id="b" type="source" position={Position.Bottom} className="h" />
    </div>
  );
});
