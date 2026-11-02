import { memo } from 'react';
import { Handle, NodeResizer, Position, type NodeProps } from '@xyflow/react';
import { CATEGORIES, getService, ZONES } from '../catalog/catalog';
import type { ServiceNode, ZoneNode } from '../types';
import { useCanvasCtx } from './context';
import { ServiceIcon } from './ServiceIcon';

const SIDES = [
  [Position.Top, 't'],
  [Position.Right, 'r'],
  [Position.Bottom, 'b'],
  [Position.Left, 'l'],
] as const;

export const ServiceNodeView = memo(function ServiceNodeView({ id, data, selected }: NodeProps<ServiceNode>) {
  const def = getService(data.serviceId);
  const { nodeIssues, dimmed, readOnly } = useCanvasCtx();
  const issue = nodeIssues.get(id);
  const color = CATEGORIES[def.category].color;
  const isActor = def.role === 'actor' || def.role === 'external';
  return (
    <div
      className={`svc ${selected ? 'is-selected' : ''} ${issue ? `has-${issue}` : ''} ${dimmed.has(id) ? 'is-dimmed' : ''} ${isActor ? 'is-actor' : ''}`}
      style={{ ['--cat' as string]: color }}
      title={`${def.name}\n${def.description}`}
    >
      <ServiceIcon def={def} size={38} />
      <div className="svc-text">
        <div className="svc-label">{data.label}</div>
        {data.label !== def.name && <div className="svc-kind">{def.name}</div>}
        {data.label === def.name && <div className="svc-kind">{CATEGORIES[def.category].label}</div>}
      </div>
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
