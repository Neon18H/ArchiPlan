import { memo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, Position, useInternalNode, type EdgeProps, type InternalNode } from '@xyflow/react';
import type { AppEdge, ConnData } from '../types';
import { useCanvasCtx } from './context';
import { fmtRps } from '../sim/profiles';

function center(n: InternalNode) {
  const w = n.measured.width ?? 0;
  const h = n.measured.height ?? 0;
  return { x: n.internals.positionAbsolute.x + w / 2, y: n.internals.positionAbsolute.y + h / 2, w, h };
}

/** Punto de anclaje en el borde del nodo, del lado que mira hacia el otro nodo. */
function anchor(a: ReturnType<typeof center>, b: ReturnType<typeof center>): [number, number, Position] {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  // Preferimos salidas horizontales (flujo izquierda→derecha) salvo que estén claramente apilados.
  if (Math.abs(dx) * 1.0 >= Math.abs(dy) * 0.9 || Math.abs(dx) > a.w) {
    return dx >= 0 ? [a.x + a.w / 2, a.y, Position.Right] : [a.x - a.w / 2, a.y, Position.Left];
  }
  return dy >= 0 ? [a.x, a.y + a.h / 2, Position.Bottom] : [a.x, a.y - a.h / 2, Position.Top];
}

export const FloatingEdge = memo(function FloatingEdge({ id, source, target, data, selected, markerEnd }: EdgeProps<AppEdge>) {
  const s = useInternalNode(source);
  const t = useInternalNode(target);
  const { edgeIssues, dimmed, sim } = useCanvasCtx();
  if (!s || !t) return null;
  const a = center(s);
  const b = center(t);
  const [sx, sy, sp] = anchor(a, b);
  const [tx, ty, tp] = anchor(b, a);
  const [path, lx, ly] = getSmoothStepPath({ sourceX: sx, sourceY: sy, sourcePosition: sp, targetX: tx, targetY: ty, targetPosition: tp, borderRadius: 10, offset: 18 });
  const d = (data ?? {}) as ConnData;
  const issue = sim ? undefined : edgeIssues.get(id);
  const simE = sim ? sim.edges[id] : undefined;
  // Estilos en línea (no solo CSS) para que la exportación a PNG/SVG conserve las líneas.
  const isDim = dimmed.has(source) || dimmed.has(target);
  let stroke: React.CSSProperties = {
    stroke: selected ? '#14171c' : issue === 'error' ? '#d6336c' : issue === 'warn' ? '#e0a100' : '#7a828c',
    strokeWidth: selected ? 2.4 : 1.6,
    strokeDasharray: d.async ? '6 4' : undefined,
    opacity: isDim ? 0.15 : 1,
    fill: 'none',
  };
  let simLabel: string | null = null;
  if (sim) {
    const rps = simE?.rps ?? 0;
    const attackShare = rps > 0 ? (simE?.attack ?? 0) / rps : 0;
    const w = rps > 0 ? Math.min(7, 1.6 + Math.log10(1 + rps) * 1.3) : 1.2;
    stroke = {
      stroke: rps <= 0 ? '#c3c8cf' : attackShare > 0.5 ? '#eb6834' : '#2a78d6',
      strokeWidth: w,
      strokeDasharray: rps > 0 ? '7 5' : '3 4',
      opacity: rps > 0 ? 0.9 : 0.45,
      fill: 'none',
      animation: rps > 0 && sim.playing ? `edge-flow ${Math.max(0.35, 1.6 - Math.log10(1 + rps) * 0.3)}s linear infinite` : undefined,
    };
    simLabel = rps > 0 ? `${fmtRps(rps)} req/s${attackShare > 0.05 ? ` · ${Math.round(attackShare * 100)}% ataque` : ''}` : null;
  }
  const cls = `edge ${d.async ? 'is-async' : ''} ${issue ? `has-${issue}` : ''} ${selected ? 'is-selected' : ''} ${dimmed.has(source) || dimmed.has(target) ? 'is-dimmed' : ''}`;
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} className={cls} interactionWidth={18} style={stroke} />
      {(sim ? simLabel : d.protocol) && (
        <EdgeLabelRenderer>
          <div className={`edge-label ${cls} ${sim ? 'is-sim' : ''}`} style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly}px)` }}>
            {sim ? simLabel : d.protocol}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});
