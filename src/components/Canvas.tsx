import { useCallback, useEffect, useMemo, useRef } from 'react';
import {
  Background,
  BackgroundVariant,
  ConnectionMode,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  useReactFlow,
  type FinalConnectionState,
  type Node,
} from '@xyflow/react';
import { CATEGORIES, getService, ZONES } from '../catalog/catalog';
import { byId, isService } from '../lib/graph';
import { evaluateConnection } from '../rules/connections';
import { useStore } from '../store';
import { useSim } from '../sim/store';
import { c3Eligible } from '../c3/model';
import type { AppEdge, AppNode, ConnData, ZoneKind } from '../types';
import { FloatingEdge } from './FloatingEdge';
import { useCanvasCtx } from './context';
import { ServiceNodeView, SystemNodeView, ZoneNodeView } from './nodes';

const nodeTypes = { service: ServiceNodeView, zone: ZoneNodeView, system: SystemNodeView };
const edgeTypes = { floating: FloatingEdge };
const defaultEdgeOptions = { type: 'floating', markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: '#5b6470' } };

export const DND_MIME = 'application/x-archiplan';

/** Vista C1: actores + un único bloque "Sistema" + sistemas externos. */
function contextView(nodes: AppNode[], edges: AppEdge[], name: string, description: string): { nodes: Node[]; edges: AppEdge[] } {
  const services = nodes.filter(isService);
  const outside = services.filter((n) => ['actor', 'external'].includes(getService(n.data.serviceId).role));
  const outsideIds = new Set(outside.map((n) => n.id));
  const actors = outside.filter((n) => getService(n.data.serviceId).role === 'actor');
  const externals = outside.filter((n) => getService(n.data.serviceId).role === 'external');
  const internal = services.length - outside.length;
  const SYS_W = 340;
  const SYS_H = 170;
  const colY = (i: number, n: number) => i * 110 - ((n - 1) * 110) / 2 + SYS_H / 2 - 32;
  const out: Node[] = [
    ...actors.map((n, i) => ({ ...n, parentId: undefined, selected: false, draggable: false, position: { x: 0, y: colY(i, actors.length) } })),
    { id: '__system', type: 'system', position: { x: 340, y: 0 }, draggable: false, data: { label: name, count: internal, description }, style: { width: SYS_W, height: SYS_H } },
    ...externals.map((n, i) => ({ ...n, parentId: undefined, selected: false, draggable: false, position: { x: 340 + SYS_W + 170, y: colY(i, externals.length) } })),
  ];
  const agg = new Map<string, { s: string; t: string; protos: Set<string>; async: boolean }>();
  for (const e of edges) {
    const s = outsideIds.has(e.source) ? e.source : '__system';
    const t = outsideIds.has(e.target) ? e.target : '__system';
    if (s === t) continue;
    const k = `${s}->${t}`;
    if (!agg.has(k)) agg.set(k, { s, t, protos: new Set(), async: true });
    const a = agg.get(k)!;
    const d = (e.data ?? {}) as ConnData;
    if (d.protocol) a.protos.add(d.protocol);
    a.async = a.async && !!d.async;
  }
  const outEdges: AppEdge[] = [...agg.values()].map((a, i) => ({
    id: `c1_${i}`,
    source: a.s,
    target: a.t,
    type: 'floating',
    data: { protocol: [...a.protos].slice(0, 2).join(', ') || 'usa', async: a.async },
  }));
  return { nodes: out, edges: outEdges };
}

export function Canvas() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const view = useStore((s) => s.view);
  const meta = useStore((s) => s.meta);
  const focusRequest = useStore((s) => s.focusRequest);
  const simOpen = useSim((s) => s.open);
  const { onNodesChange, onEdgesChange, onConnect, addService, addZone, reparent, commit, setViewportCenter, toast } = useStore.getState();
  const rf = useReactFlow();
  const wrapper = useRef<HTMLDivElement>(null);

  const { attack, sim } = useCanvasCtx();
  // Failover activo en la simulación: flecha temporal hacia la réplica que atiende
  const foKeys = sim ? Object.keys(sim.edges).filter((k) => k.startsWith('fo:') && sim.edges[k].rps > 0).join(',') : '';
  const display = useMemo(() => {
    if (view === 'c1') return contextView(nodes, edges, meta.name, meta.description);
    if (foKeys) {
      const extra = foKeys.split(',').map((k) => {
        const [source, target] = k.slice(3).split('>');
        return { id: k, source, target, type: 'floating', selectable: false, deletable: false, data: { virtual: true }, markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: '#2f9e44' } };
      }) as unknown as AppEdge[];
      return { nodes: nodes as Node[], edges: [...edges, ...extra] };
    }
    if (!attack?.virtual.length) return { nodes: nodes as Node[], edges };
    // Saltos de la ruta de ataque que no son una flecha del diagrama (rol IAM, credenciales robadas)
    const extra = attack.virtual.map((v) => ({ id: v.id, source: v.source, target: v.target, type: 'floating', selectable: false, deletable: false, data: { virtual: true }, markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: '#c92a2a' } })) as unknown as AppEdge[];
    return { nodes: nodes as Node[], edges: [...edges, ...extra] };
  }, [view, nodes, edges, meta.name, meta.description, attack, foKeys]);

  useEffect(() => {
    if (!focusRequest) return;
    const id = setTimeout(() => {
      if (focusRequest.ids.length) rf.fitView({ nodes: focusRequest.ids.map((id) => ({ id })), duration: 400, padding: 0.8, maxZoom: 1.2 });
      else rf.fitView({ duration: 300, padding: 0.12 });
    }, 60);
    return () => clearTimeout(id);
  }, [focusRequest, rf]);

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      if (view !== 'c2') {
        toast('info', 'Cambia a la vista C2 (Contenedores) para editar.');
        return;
      }
      const raw = e.dataTransfer.getData(DND_MIME);
      if (!raw) return;
      const item = JSON.parse(raw) as { kind: 'service' | 'zone'; id: string };
      const p = rf.screenToFlowPosition({ x: e.clientX, y: e.clientY });
      if (item.kind === 'service') addService(item.id, { x: p.x - 86, y: p.y - 32 });
      else addZone(item.id as ZoneKind, { x: p.x - 20, y: p.y - 14 });
    },
    [rf, addService, addZone, view, toast],
  );

  const isValidConnection = useCallback((c: { source: string; target: string }) => {
    const map = byId(useStore.getState().nodes);
    const s = map.get(c.source);
    const t = map.get(c.target);
    if (!s || !t) return false;
    return evaluateConnection(s, t, map).level !== 'error';
  }, []);

  const onConnectEnd = useCallback(
    (_: MouseEvent | TouchEvent, st: FinalConnectionState) => {
      if (st.isValid || !st.fromNode || !st.toNode || st.fromNode.id === st.toNode.id) return;
      const map = byId(useStore.getState().nodes);
      const s = map.get(st.fromNode.id);
      const t = map.get(st.toNode.id);
      if (!s || !t) return;
      const v = evaluateConnection(s, t, map);
      if (v.level === 'error') toast('error', `Conexión bloqueada: ${v.msg}`);
    },
    [toast],
  );

  const readOnly = view !== 'c2';

  return (
    <div className="canvas" ref={wrapper} onDragOver={onDragOver} onDrop={onDrop}>
      <ReactFlow
        nodes={display.nodes}
        edges={display.edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        onNodesChange={readOnly ? undefined : (onNodesChange as never)}
        onEdgesChange={readOnly ? undefined : (onEdgesChange as never)}
        onConnect={onConnect}
        onConnectEnd={onConnectEnd}
        isValidConnection={isValidConnection as never}
        connectionMode={ConnectionMode.Loose}
        onNodeDragStart={() => commit()}
        onNodeDoubleClick={(_, n) => {
          if (view === 'c2' && c3Eligible(useStore.getState().nodes.find((x) => x.id === n.id))) useStore.getState().openC3(n.id);
        }}
        zoomOnDoubleClick={false}
        onNodeDragStop={(_, __, dragged) => reparent(dragged.map((n) => n.id))}
        onMoveEnd={() => {
          const el = wrapper.current;
          if (el) setViewportCenter(rf.screenToFlowPosition({ x: el.getBoundingClientRect().left + el.clientWidth / 2, y: el.getBoundingClientRect().top + el.clientHeight / 2 }));
        }}
        nodesDraggable={!readOnly}
        nodesConnectable={!readOnly}
        elementsSelectable
        deleteKeyCode={readOnly ? null : ['Delete', 'Backspace']}
        multiSelectionKeyCode={['Shift', 'Meta', 'Control']}
        snapToGrid
        snapGrid={[8, 8]}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.15}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        connectionRadius={36}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1.2} color="#cfd4da" />
        <Controls showInteractive={false} />
        {!simOpen && <MiniMap
          pannable
          zoomable
          nodeStrokeWidth={2}
          nodeColor={(n) => (n.type === 'service' ? CATEGORIES[getService((n.data as { serviceId: string }).serviceId).category].color : n.type === 'zone' ? 'transparent' : '#14171c')}
          nodeStrokeColor={(n) => (n.type === 'zone' ? ZONES[(n.data as { zoneKind: ZoneKind }).zoneKind].color : 'transparent')}
          maskColor="rgba(240,242,245,0.7)"
        />}
      </ReactFlow>
      {nodes.length === 0 && view === 'c2' && (
        <div className="empty-hint">
          <div className="empty-title">Empieza tu arquitectura</div>
          <p>Arrastra piezas desde la paleta, usa una plantilla o deja que el asistente te haga las preguntas.</p>
          <div className="empty-actions">
            <button className="btn primary" onClick={() => window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'wizard' }))}>
              Asistente guiado
            </button>
            <button className="btn" onClick={() => window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'templates' }))}>
              Ver plantillas
            </button>
          </div>
        </div>
      )}
      {view === 'c1' && <div className="view-banner">Vista de contexto (C4 · nivel 1) — solo lectura. Cambia a C2 para editar.</div>}
    </div>
  );
}
