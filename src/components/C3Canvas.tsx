import { useCallback, useEffect, useMemo } from 'react';
import { Background, BackgroundVariant, ConnectionMode, Controls, MarkerType, ReactFlow, useReactFlow, type Connection, type EdgeChange, type Node, type NodeChange } from '@xyflow/react';
import { getService } from '../catalog/catalog';
import { c3Eligible, COMPONENT_KINDS, coverage, neighbors, suggestComponents } from '../c3/model';
import { uid } from '../lib/graph';
import { useStore } from '../store';
import type { AppEdge, C3Model, ComponentKind } from '../types';
import { DND_MIME } from './Canvas';
import { FloatingEdge } from './FloatingEdge';
import { C3BoundaryView, C3ComponentView, C3ExtView } from './nodes';

const nodeTypes = { component: C3ComponentView, c3ext: C3ExtView, c3boundary: C3BoundaryView };
const edgeTypes = { floating: FloatingEdge };
const defaultEdgeOptions = { type: 'floating', markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: '#5b6470' } };
const CW = 210;
const CH = 74;
const EMPTY: C3Model = { components: [], links: [] };

export function C3Canvas() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const c3Id = useStore((s) => s.c3Id);
  const sel = useStore((s) => s.c3Selection);
  const { setC3, setC3Selection, setView, toast } = useStore.getState();
  const rf = useReactFlow();
  const node = nodes.find((n) => n.id === c3Id);
  const model = (c3Eligible(node) && node.data.c3) || EMPTY;
  const nb = useMemo(() => (c3Id ? neighbors(c3Id, nodes, edges) : []), [c3Id, nodes, edges]);
  const cov = useMemo(() => (c3Eligible(node) ? coverage(node, nodes, edges) : { missing: [], orphans: [], stale: [] }), [node, nodes, edges]);

  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.12, duration: 250 }), 60);
    return () => clearTimeout(t);
  }, [c3Id, rf, model.components.length === 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const flow = useMemo(() => {
    const comps = model.components;
    const xs = comps.map((c) => c.position.x);
    const ys = comps.map((c) => c.position.y);
    const minX = comps.length ? Math.min(...xs) : 0;
    const minY = comps.length ? Math.min(...ys) : 0;
    const maxX = comps.length ? Math.max(...xs) + CW : 760;
    const maxY = comps.length ? Math.max(...ys) + CH : 260;
    const def = c3Eligible(node) ? getService(node.data.serviceId) : null;
    const out: Node[] = [
      {
        id: '__c3b',
        type: 'c3boundary',
        position: { x: minX - 40, y: minY - 64 },
        style: { width: maxX - minX + 80, height: maxY - minY + 104 },
        draggable: false,
        selectable: false,
        zIndex: -1,
        data: { label: node?.data.label ?? '', service: def?.name ?? '', empty: comps.length === 0 },
      },
    ];
    const ins = nb.filter((x) => x.dir === 'in');
    const outs = nb.filter((x) => x.dir === 'out');
    const seen = new Set<string>();
    const col = (list: typeof nb, x: number) => {
      const uniq = list.filter((e) => !seen.has(e.node.id) && (seen.add(e.node.id), true));
      const total = uniq.length * 96;
      const startY = (minY + maxY) / 2 - total / 2;
      uniq.forEach((e, i) =>
        out.push({ id: `ext:${e.node.id}`, type: 'c3ext', position: { x, y: startY + i * 96 }, draggable: false, data: { label: e.node.data.label, serviceId: e.node.data.serviceId, dir: e.dir, missing: cov.missing.some((m) => m.node.id === e.node.id) } }),
      );
    };
    col(ins, minX - 40 - 300);
    col(outs, maxX + 40 + 90);
    for (const c of comps) out.push({ id: c.id, type: 'component', position: c.position, selected: sel.includes(c.id), data: { comp: c } });
    const ids = new Set(out.map((n) => n.id));
    const fe: AppEdge[] = model.links
      .filter((l) => ids.has(l.source) && ids.has(l.target))
      .map((l) => ({ id: l.id, source: l.source, target: l.target, type: 'floating', selected: sel.includes(l.id), data: { protocol: l.label ?? '' } }));
    return { nodes: out, edges: fe };
  }, [model, nb, node, sel, cov]);

  const save = useCallback((m: C3Model, key?: string) => c3Id && setC3(c3Id, m, key), [c3Id, setC3]);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => {
      let m = model;
      let moved = false;
      const selNow = new Set(useStore.getState().c3Selection);
      let selChanged = false;
      for (const ch of changes) {
        if (ch.type === 'position' && ch.position && !ch.id.startsWith('ext:') && ch.id !== '__c3b') {
          m = { ...m, components: m.components.map((c) => (c.id === ch.id ? { ...c, position: ch.position! } : c)) };
          moved = true;
        } else if (ch.type === 'select') {
          if (ch.selected) selNow.add(ch.id);
          else selNow.delete(ch.id);
          selChanged = true;
        } else if (ch.type === 'remove' && !ch.id.startsWith('ext:')) {
          m = { components: m.components.filter((c) => c.id !== ch.id), links: m.links.filter((l) => l.source !== ch.id && l.target !== ch.id) };
          save(m);
        }
      }
      if (moved) save(m, 'move');
      if (selChanged) setC3Selection([...selNow].filter((id) => !id.startsWith('ext:') && id !== '__c3b'));
    },
    [model, save, setC3Selection],
  );

  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => {
      const selNow = new Set(useStore.getState().c3Selection);
      let selChanged = false;
      let m = model;
      for (const ch of changes) {
        if (ch.type === 'select') {
          if (ch.selected) selNow.add(ch.id);
          else selNow.delete(ch.id);
          selChanged = true;
        } else if (ch.type === 'remove') {
          m = { ...m, links: m.links.filter((l) => l.id !== ch.id) };
          save(m);
        }
      }
      if (selChanged) setC3Selection([...selNow]);
    },
    [model, save, setC3Selection],
  );

  const onConnect = useCallback(
    (c: Connection) => {
      if (!c.source || !c.target || c.source === c.target) return;
      if (c.source.startsWith('ext:') && c.target.startsWith('ext:')) {
        toast('warn', 'Conecta las dependencias externas con algún componente interno.');
        return;
      }
      if (model.links.some((l) => l.source === c.source && l.target === c.target)) return;
      const ext = [c.source, c.target].find((x) => x.startsWith('ext:'));
      const nbx = ext ? nb.find((x) => `ext:${x.node.id}` === ext) : undefined;
      save({ ...model, links: [...model.links, { id: uid('l'), source: c.source, target: c.target, label: nbx?.protocol ?? 'usa' }] });
    },
    [model, nb, save, toast],
  );

  const addKind = useCallback(
    (kind: ComponentKind, pos?: { x: number; y: number }) => {
      const meta = COMPONENT_KINDS[kind];
      const position = pos ?? { x: (model.components.length % 4) * 250, y: Math.floor(model.components.length / 4) * 110 };
      const id = uid('c');
      save({ ...model, components: [...model.components, { id, kind, label: meta.label, tech: '', description: '', position }] });
      setC3Selection([id]);
    },
    [model, save, setC3Selection],
  );

  useEffect(() => {
    const h = (e: Event) => addKind((e as CustomEvent).detail as ComponentKind);
    window.addEventListener('archiplan:c3add', h);
    return () => window.removeEventListener('archiplan:c3add', h);
  }, [addKind]);

  if (!c3Eligible(node)) {
    return (
      <div className="canvas">
        <div className="empty-hint">
          <div className="empty-title">Elige un servicio</div>
          <p>La vista de componentes (C3) se abre con doble clic sobre una pieza de cómputo, API o flujo en C2.</p>
          <div className="empty-actions">
            <button className="btn primary" onClick={() => setView('c2')}>
              Volver a C2
            </button>
          </div>
        </div>
      </div>
    );
  }

  const generate = () => {
    if (model.components.length && !window.confirm('Se reemplazarán los componentes actuales (puedes deshacer con Ctrl+Z). ¿Continuar?')) return;
    save(suggestComponents(node, nodes, edges));
    setTimeout(() => rf.fitView({ padding: 0.12, duration: 300 }), 80);
  };

  return (
    <div
      className="canvas c3"
      onDragOver={(e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
      }}
      onDrop={(e) => {
        e.preventDefault();
        const raw = e.dataTransfer.getData(DND_MIME);
        if (!raw) return;
        const item = JSON.parse(raw) as { kind: string; id: string };
        if (item.kind !== 'component') return;
        const p = rf.screenToFlowPosition({ x: e.clientX, y: e.clientY });
        addKind(item.id as ComponentKind, { x: p.x - CW / 2, y: p.y - CH / 2 });
      }}
    >
      <ReactFlow
        nodes={flow.nodes}
        edges={flow.edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeDragStart={() => useStore.getState().commit()}
        connectionMode={ConnectionMode.Loose}
        deleteKeyCode={['Delete', 'Backspace']}
        snapToGrid
        snapGrid={[8, 8]}
        fitView
        minZoom={0.2}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        connectionRadius={36}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1.2} color="#cfd4da" />
        <Controls showInteractive={false} />
      </ReactFlow>
      <div className="c3-bar">
        <button className="btn small" onClick={() => setView('c2')}>
          ← C2
        </button>
        <div className="c3-crumb">
          <span className="muted">C3 · Componentes de</span> <b>{node.data.label}</b> <span className="muted">({getService(node.data.serviceId).name})</span>
        </div>
        {cov.missing.length > 0 && (
          <span className="c3-warn" title={cov.missing.map((m) => m.node.data.label).join(', ')}>
            {cov.missing.length} dependencia(s) de C2 sin componente
          </span>
        )}
        {cov.orphans.length > 0 && <span className="c3-warn soft">{cov.orphans.length} componente(s) sin relaciones</span>}
        <button className="btn small primary" onClick={generate}>
          {model.components.length ? 'Regenerar sugerencia' : '✨ Generar componentes sugeridos'}
        </button>
      </div>
      {model.components.length === 0 && (
        <div className="empty-hint c3-empty">
          <div className="empty-title">Componentes de {node.data.label}</div>
          <p>A los lados están las dependencias que tiene en C2. Arrastra componentes desde la paleta o genera una propuesta a partir de esas dependencias.</p>
          <div className="empty-actions">
            <button className="btn primary" onClick={generate}>
              ✨ Generar componentes sugeridos
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
