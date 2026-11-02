import { memo } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, Position, useInternalNode, type EdgeProps, type InternalNode } from '@xyflow/react';
import type { AppEdge, ConnData } from '../types';
import { useCanvasCtx } from './context';

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
  const { edgeIssues, dimmed } = useCanvasCtx();
  if (!s || !t) return null;
  const a = center(s);
  const b = center(t);
  const [sx, sy, sp] = anchor(a, b);
  const [tx, ty, tp] = anchor(b, a);
  const [path, lx, ly] = getSmoothStepPath({ sourceX: sx, sourceY: sy, sourcePosition: sp, targetX: tx, targetY: ty, targetPosition: tp, borderRadius: 10, offset: 18 });
  const d = (data ?? {}) as ConnData;
  const issue = edgeIssues.get(id);
  // Estilos en línea (no solo CSS) para que la exportación a PNG/SVG conserve las líneas.
  const isDim = dimmed.has(source) || dimmed.has(target);
  const stroke: React.CSSProperties = {
    stroke: selected ? '#14171c' : issue === 'error' ? '#d6336c' : issue === 'warn' ? '#e0a100' : '#7a828c',
    strokeWidth: selected ? 2.4 : 1.6,
    strokeDasharray: d.async ? '6 4' : undefined,
    opacity: isDim ? 0.15 : 1,
    fill: 'none',
  };
  const cls = `edge ${d.async ? 'is-async' : ''} ${issue ? `has-${issue}` : ''} ${selected ? 'is-selected' : ''} ${dimmed.has(source) || dimmed.has(target) ? 'is-dimmed' : ''}`;
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} className={cls} interactionWidth={18} style={stroke} />
      {d.protocol && (
        <EdgeLabelRenderer>
          <div className={`edge-label ${cls}`} style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly}px)` }}>
            {d.protocol}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
});
