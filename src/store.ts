import { create } from 'zustand';
import { applyEdgeChanges, applyNodeChanges, type Connection, type EdgeChange, type NodeChange } from '@xyflow/react';
import { defaultProps, forCloud, getService, primaryCloud, zoneLabel, ZONE_PARENT, ZONES } from './catalog/catalog';
import { convertRegion, convertService, convertZoneLabel } from './lib/cloud';
import { absolutePosition, ancestors, byId, isService, isZone, nodeSize, placementOf, sortNodes, uid, ZONE_DEPTH } from './lib/graph';
import { buildFromSpec, NODE_H, NODE_W, type Spec } from './lib/layout';
import { evaluateConnection } from './rules/connections';
import type { AppEdge, AppNode, C3Model, Cloud, ConnData, Decision, Fix, Layer, Placement, Project, ProjectMeta, PropValue, ServiceNode, ThreatState, ZoneKind, ZoneNode } from './types';

export type ViewMode = 'c2' | 'c1' | 'c3';

interface Snapshot {
  nodes: AppNode[];
  edges: AppEdge[];
  decisions: Decision[];
  meta: ProjectMeta;
  threats: Record<string, ThreatState>;
}

export interface Toast {
  id: string;
  kind: 'error' | 'warn' | 'ok' | 'info';
  text: string;
}

interface State extends Snapshot {
  projectId: string | null;
  dirty: boolean;
  view: ViewMode;
  /** Pieza abierta en la vista de componentes (C3). */
  c3Id: string | null;
  c3Selection: string[];
  layers: Layer[];
  past: Snapshot[];
  future: Snapshot[];
  toasts: Toast[];
  focusRequest: { ids: string[]; t: number } | null;
  /** Centro del viewport (coordenadas del flujo), lo actualiza el lienzo. */
  viewportCenter: { x: number; y: number };

  onNodesChange: (changes: NodeChange<AppNode>[]) => void;
  onEdgesChange: (changes: EdgeChange<AppEdge>[]) => void;
  onConnect: (c: Connection) => void;
  commit: (coalesceKey?: string) => void;
  undo: () => void;
  redo: () => void;

  addService: (serviceId: string, pos?: { x: number; y: number }, parentOverride?: string | null) => string;
  addZone: (kind: ZoneKind, pos?: { x: number; y: number }) => string;
  reparent: (ids: string[]) => void;
  updateNode: (id: string, patch: { label?: string; notes?: string; props?: Record<string, PropValue> }) => void;
  updateEdge: (id: string, patch: Partial<ConnData>) => void;
  reverseEdge: (id: string) => void;
  deleteIds: (ids: string[]) => void;
  applyFix: (fix: Fix) => void;
  select: (ids: string[]) => void;
  focus: (ids: string[]) => void;

  setMeta: (patch: Partial<ProjectMeta>) => void;
  addDecision: (d?: Partial<Decision>) => void;
  updateDecision: (id: string, patch: Partial<Decision>) => void;
  deleteDecision: (id: string) => void;
  setThreatState: (id: string, patch: Partial<ThreatState>) => void;
  setThreatControl: (id: string, key: string, value: boolean) => void;

  loadProject: (p: Project, projectId?: string | null) => void;
  loadSpec: (spec: Spec, meta: Partial<ProjectMeta>, decisions?: Omit<Decision, 'id'>[]) => void;
  newEmpty: () => void;
  toProject: () => Project;
  setProjectId: (id: string | null) => void;
  markSaved: () => void;
  autoLayout: () => void;
  convertCloud: (to: Cloud) => void;
  cloud: () => Cloud;

  setView: (v: ViewMode) => void;
  openC3: (id: string) => void;
  setC3: (id: string, model: C3Model, coalesceKey?: string) => void;
  setC3Selection: (ids: string[]) => void;
  toggleLayer: (l: Layer) => void;
  clearLayers: () => void;
  toast: (kind: Toast['kind'], text: string) => void;
  dismissToast: (id: string) => void;
  setViewportCenter: (c: { x: number; y: number }) => void;
}

const now = () => new Date().toISOString();
export const emptyMeta = (): ProjectMeta => ({
  name: 'Arquitectura sin título',
  description: '',
  author: '',
  provider: 'aws',
  region: 'us-east-1',
  environment: 'producción',
  createdAt: now(),
  updatedAt: now(),
});

const AUTOSAVE_KEY = 'archiplan:autosave:v1';

function loadAutosave(): Partial<State> | null {
  try {
    const raw = localStorage.getItem(AUTOSAVE_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as Project & { projectId?: string | null };
    if (p.format !== 'archiplan') return null;
    return { nodes: sortNodes(p.nodes), edges: p.edges, decisions: p.decisions ?? [], threats: p.threats ?? {}, meta: { ...emptyMeta(), ...p.meta }, projectId: p.projectId ?? null };
  } catch {
    return null;
  }
}

/** Zona más profunda que contiene el punto y que puede ser padre del elemento. */
function findContainer(nodes: AppNode[], point: { x: number; y: number }, forKind: ZoneKind | 'service', excludeId?: string): ZoneNode | null {
  const map = byId(nodes);
  const isDesc = (z: AppNode) => {
    if (!excludeId) return false;
    if (z.id === excludeId) return true;
    return ancestors(z, map).some((a) => a.id === excludeId);
  };
  let best: ZoneNode | null = null;
  let bestScore = -1;
  for (const n of nodes) {
    if (!isZone(n) || isDesc(n)) continue;
    if (forKind !== 'service' && !ZONE_PARENT[forKind].includes(n.data.zoneKind)) continue;
    const p = absolutePosition(n, map);
    const { w, h } = nodeSize(n);
    if (point.x >= p.x && point.x <= p.x + w && point.y >= p.y && point.y <= p.y + h) {
      const score = ZONE_DEPTH[n.data.zoneKind] * 1e9 - w * h;
      if (score > bestScore) {
        best = n;
        bestScore = score;
      }
    }
  }
  return best;
}

/** Agranda la zona (y sus ancestros) para que quepan sus hijos. */
function growToFit(nodes: AppNode[], zoneId: string): AppNode[] {
  let out = nodes;
  let curId: string | undefined = zoneId;
  let guard = 0;
  while (curId && guard++ < 10) {
    const map = byId(out);
    const z = map.get(curId);
    if (!z || !isZone(z)) break;
    const kids = out.filter((n) => n.parentId === z.id);
    const { w, h } = nodeSize(z);
    let needW = w;
    let needH = h;
    for (const k of kids) {
      const s = nodeSize(k);
      needW = Math.max(needW, k.position.x + s.w + 24);
      needH = Math.max(needH, k.position.y + s.h + 24);
    }
    if (needW !== w || needH !== h) {
      out = out.map((n) => (n.id === z.id ? { ...n, width: needW, height: needH, style: { ...n.style, width: needW, height: needH } } : n));
    }
    curId = z.parentId;
  }
  return out;
}

/** Busca un hueco libre dentro de una zona (o en el lienzo si zoneId es null). */
function freeSpot(nodes: AppNode[], zoneId: string | null, near?: { x: number; y: number }): { x: number; y: number } {
  const map = byId(nodes);
  const siblings = nodes.filter((n) => (n.parentId ?? null) === zoneId && n.type === 'service');
  const zones = nodes.filter((n) => (n.parentId ?? null) === zoneId && n.type === 'zone');
  const occupied = [...siblings, ...zones].map((n) => ({ ...n.position, ...nodeSize(n) }));
  const collides = (x: number, y: number) => occupied.some((o) => x < o.x + o.w + 16 && x + NODE_W + 16 > o.x && y < o.y + o.h + 16 && y + NODE_H + 16 > o.y);
  if (zoneId) {
    const z = map.get(zoneId)!;
    const { w } = nodeSize(z);
    const cols = Math.max(1, Math.floor((w - 24) / (NODE_W + 30)));
    for (let row = 0; row < 40; row++) {
      for (let col = 0; col < cols; col++) {
        const x = 24 + col * (NODE_W + 30);
        const y = 40 + row * (NODE_H + 30);
        if (!collides(x, y)) return { x, y };
      }
    }
    return { x: 24, y: 40 };
  }
  const base = near ?? { x: 0, y: 0 };
  for (let r = 0; r < 30; r++) {
    for (const [dx, dy] of [[0, 0], [0, 1], [1, 0], [0, -1], [-1, 0], [1, 1], [-1, 1], [1, -1], [-1, -1]]) {
      const x = base.x + dx * r * (NODE_W + 30);
      const y = base.y + dy * r * (NODE_H + 30);
      if (!collides(x, y)) return { x, y };
    }
  }
  return base;
}

/** Elige la zona correcta para una pieza según su catálogo (para "agregar inteligente"). */
function preferredZone(nodes: AppNode[], serviceId: string): string | null {
  const def = getService(serviceId);
  const zones = nodes.filter(isZone);
  for (const pl of def.zones) {
    if (pl === 'outside') {
      if (!def.vpcBound) return null;
      continue;
    }
    if (pl === 'region') {
      const r = zones.find((z) => z.data.zoneKind === 'region');
      if (r) return r.id;
      continue;
    }
    const sub = zones.find((z) => z.data.zoneKind === (pl as Placement));
    if (sub) return sub.id;
  }
  if (def.vpcBound) {
    // No hay subnet adecuada: si existe la región, al menos dentro de ella.
    const r = zones.find((z) => z.data.zoneKind === 'region');
    return r?.id ?? null;
  }
  return null;
}

const init = loadAutosave();

export const useStore = create<State>((set, get) => ({
  nodes: init?.nodes ?? [],
  edges: init?.edges ?? [],
  decisions: init?.decisions ?? [],
  threats: init?.threats ?? {},
  meta: init?.meta ?? emptyMeta(),
  projectId: init?.projectId ?? null,
  dirty: false,
  view: 'c2',
  c3Id: null,
  c3Selection: [],
  layers: [],
  past: [],
  future: [],
  toasts: [],
  focusRequest: null,
  viewportCenter: { x: 200, y: 200 },

  commit: (() => {
    let lastKey = '';
    let lastT = 0;
    return (coalesceKey?: string) => {
      const t = Date.now();
      if (coalesceKey && coalesceKey === lastKey && t - lastT < 1200) {
        lastT = t;
        return;
      }
      lastKey = coalesceKey ?? '';
      lastT = t;
      const { nodes, edges, decisions, meta, threats, past } = get();
      set({ past: [...past.slice(-99), { nodes, edges, decisions, meta, threats }], future: [], dirty: true });
    };
  })(),
  undo: () => {
    const { past, future, nodes, edges, decisions, meta, threats } = get();
    const prev = past[past.length - 1];
    if (!prev) return;
    set({ ...prev, past: past.slice(0, -1), future: [{ nodes, edges, decisions, meta, threats }, ...future].slice(0, 100), dirty: true });
  },
  redo: () => {
    const { past, future, nodes, edges, decisions, meta, threats } = get();
    const next = future[0];
    if (!next) return;
    set({ ...next, future: future.slice(1), past: [...past, { nodes, edges, decisions, meta, threats }], dirty: true });
  },

  onNodesChange: (changes) => {
    if (get().view !== 'c2') return;
    const structural = changes.some((c) => c.type === 'remove');
    if (structural) get().commit();
    const resizeEnd = changes.some((c) => c.type === 'dimensions' && c.resizing === false);
    let nodes = applyNodeChanges(changes, get().nodes);
    if (structural) {
      // Al eliminar una zona, sus hijos pasan al padre de la zona (o al lienzo) en vez de quedar huérfanos.
      const removed = new Set(changes.filter((c) => c.type === 'remove').map((c) => (c as { id: string }).id));
      const oldMap = byId(get().nodes);
      nodes = nodes.map((n) => {
        if (n.parentId && removed.has(n.parentId)) {
          let pid: string | undefined = n.parentId;
          while (pid && removed.has(pid)) pid = oldMap.get(pid)?.parentId;
          const abs = absolutePosition(n, oldMap);
          const pAbs = pid ? absolutePosition(oldMap.get(pid)!, oldMap) : { x: 0, y: 0 };
          return { ...n, parentId: pid, position: { x: abs.x - pAbs.x, y: abs.y - pAbs.y } } as AppNode;
        }
        return n;
      });
      const ids = new Set(nodes.map((n) => n.id));
      set({ nodes: sortNodes(nodes), edges: get().edges.filter((e) => ids.has(e.source) && ids.has(e.target)), dirty: true });
      return;
    }
    const meaningful = changes.some((c) => c.type !== 'select' && c.type !== 'dimensions') || resizeEnd;
    set({ nodes, ...(meaningful ? { dirty: true } : {}) });
  },
  onEdgesChange: (changes) => {
    if (get().view !== 'c2') return;
    if (changes.some((c) => c.type === 'remove')) get().commit();
    set({ edges: applyEdgeChanges(changes, get().edges) });
  },
  onConnect: (c) => {
    const { nodes, edges } = get();
    const map = byId(nodes);
    const s = map.get(c.source);
    const t = map.get(c.target);
    if (!s || !t) return;
    const v = evaluateConnection(s, t, map);
    if (v.level === 'error') {
      get().toast('error', `Conexión bloqueada: ${v.msg}`);
      return;
    }
    if (edges.some((e) => e.source === c.source && e.target === c.target)) {
      get().toast('warn', 'Esa conexión ya existe.');
      return;
    }
    get().commit();
    const edge: AppEdge = {
      id: uid('e'),
      source: c.source,
      target: c.target,
      type: 'floating',
      data: { protocol: v.protocol, async: v.async, level: v.level === 'warn' ? 'warn' : 'ok', ruleMsg: v.msg },
    };
    set({ edges: [...edges, edge] });
    if (v.level === 'warn' && v.msg) get().toast('warn', v.msg);
  },

  addService: (serviceId, pos, parentOverride) => {
    get().commit();
    const def = getService(serviceId);
    let nodes = get().nodes;
    let parentId: string | null;
    let position: { x: number; y: number };
    if (pos) {
      const container = findContainer(nodes, { x: pos.x + NODE_W / 2, y: pos.y + NODE_H / 2 }, 'service');
      parentId = container?.id ?? null;
      const map = byId(nodes);
      const pAbs = container ? absolutePosition(container, map) : { x: 0, y: 0 };
      position = { x: pos.x - pAbs.x, y: pos.y - pAbs.y };
    } else {
      parentId = parentOverride !== undefined ? parentOverride : preferredZone(nodes, serviceId);
      const c = get().viewportCenter;
      const topLevel = nodes.filter((n) => !n.parentId);
      const near = parentId ? undefined : topLevel.length ? { x: Math.min(...topLevel.map((n) => n.position.x)) - NODE_W - 60, y: c.y } : c;
      position = freeSpot(nodes, parentId, near);
    }
    const id = uid('n');
    const sameCount = nodes.filter((n) => isService(n) && n.data.serviceId === serviceId).length;
    const node: ServiceNode = {
      id,
      type: 'service',
      position,
      ...(parentId ? { parentId } : {}),
      data: { serviceId, label: sameCount ? `${def.name} ${sameCount + 1}` : def.name, props: defaultProps(def.props) },
    };
    nodes = [...nodes.map((n) => ({ ...n, selected: false })), { ...node, selected: true }];
    if (parentId) nodes = growToFit(nodes, parentId);
    set({ nodes: sortNodes(nodes) });
    return id;
  },
  addZone: (kind, pos) => {
    get().commit();
    let nodes = get().nodes;
    const z = ZONES[kind];
    const size = { region: [900, 560], vpc: [700, 420], 'subnet-public': [230, 360], 'subnet-private': [230, 360], 'subnet-data': [230, 360], boundary: [420, 300] }[kind];
    let parentId: string | null = null;
    let position: { x: number; y: number };
    const map = byId(nodes);
    if (pos) {
      const container = findContainer(nodes, pos, kind);
      parentId = container?.id ?? null;
      const pAbs = container ? absolutePosition(container, map) : { x: 0, y: 0 };
      position = { x: pos.x - pAbs.x, y: pos.y - pAbs.y };
    } else {
      // Ubicar automáticamente dentro del padre lógico si existe
      const parentKind = ZONE_PARENT[kind].find((k) => k && nodes.some((n) => isZone(n) && n.data.zoneKind === k));
      const parent = parentKind ? nodes.find((n) => isZone(n) && n.data.zoneKind === parentKind) : undefined;
      parentId = parent?.id ?? null;
      if (parent) {
        const kids = nodes.filter((n) => n.parentId === parent.id);
        const right = kids.length ? Math.max(...kids.map((k) => k.position.x + nodeSize(k).w)) + 28 : 24;
        position = { x: right, y: 40 };
      } else {
        const all = nodes.filter((n) => !n.parentId);
        position = all.length ? { x: Math.max(...all.map((n) => n.position.x + nodeSize(n).w)) + 80, y: 0 } : { x: 300, y: 0 };
      }
    }
    const id = uid('z');
    const node: ZoneNode = {
      id,
      type: 'zone',
      position,
      ...(parentId ? { parentId } : {}),
      width: size[0],
      height: size[1],
      style: { width: size[0], height: size[1] },
      data: {
        zoneKind: kind,
        label: zoneLabel(kind, get().cloud()),
        props: Object.fromEntries(z.props.map((p) => [p.key, kind === 'region' && p.key === 'region' && get().cloud() === 'azure' ? 'eastus' : p.default])),
      },
    };
    nodes = [...nodes, node];
    if (parentId) nodes = growToFit(nodes, parentId);
    set({ nodes: sortNodes(nodes) });
    return id;
  },
  reparent: (ids) => {
    let nodes = get().nodes;
    let changed = false;
    for (const id of ids) {
      const map = byId(nodes);
      const n = map.get(id);
      if (!n) continue;
      const abs = absolutePosition(n, map);
      const { w, h } = nodeSize(n);
      const kind = isZone(n) ? n.data.zoneKind : 'service';
      const point = isZone(n) ? { x: abs.x + 8, y: abs.y + 8 } : { x: abs.x + w / 2, y: abs.y + h / 2 };
      const container = findContainer(nodes, point, kind, id);
      const newParent = container?.id;
      if ((newParent ?? undefined) === (n.parentId ?? undefined)) continue;
      const pAbs = container ? absolutePosition(container, map) : { x: 0, y: 0 };
      changed = true;
      nodes = nodes.map((x) => {
        if (x.id !== id) return x;
        const { parentId: _old, ...rest } = x;
        void _old;
        return { ...rest, ...(newParent ? { parentId: newParent } : {}), position: { x: abs.x - pAbs.x, y: abs.y - pAbs.y } } as AppNode;
      });
      if (newParent) nodes = growToFit(nodes, newParent);
    }
    if (changed) set({ nodes: sortNodes(nodes), dirty: true });
  },
  updateNode: (id, patch) => {
    get().commit(`node:${id}`);
    set({
      nodes: get().nodes.map((n) => {
        if (n.id !== id) return n;
        const data = { ...n.data, ...(patch.label !== undefined ? { label: patch.label } : {}), ...(patch.notes !== undefined ? { notes: patch.notes } : {}) };
        if (patch.props) data.props = { ...n.data.props, ...patch.props };
        return { ...n, data } as AppNode;
      }),
    });
  },
  updateEdge: (id, patch) => {
    get().commit(`edge:${id}`);
    set({ edges: get().edges.map((e) => (e.id === id ? { ...e, data: { ...(e.data as ConnData), ...patch } } : e)) });
  },
  reverseEdge: (id) => {
    get().commit();
    set({ edges: get().edges.map((e) => (e.id === id ? { ...e, source: e.target, target: e.source } : e)) });
  },
  deleteIds: (ids) => {
    const changes = ids.filter((id) => get().nodes.some((n) => n.id === id)).map((id) => ({ type: 'remove' as const, id }));
    const edgeIds = ids.filter((id) => get().edges.some((e) => e.id === id));
    if (changes.length) get().onNodesChange(changes);
    if (edgeIds.length) get().onEdgesChange(edgeIds.map((id) => ({ type: 'remove' as const, id })));
  },
  applyFix: (fix) => {
    get().commit();
    const created: string[] = [];
    const { commit } = get();
    // Evitar que cada addService cree su propio punto de undo
    set({ commit: () => {} } as Partial<State>);
    try {
      const cloud = get().cloud();
      for (const a of fix.add ?? []) {
        const id = get().addService(forCloud(a.serviceId, cloud), undefined, a.parent === undefined ? undefined : a.parent);
        if (a.label || a.props) get().updateNode(id, { label: a.label, props: a.props });
        created.push(id);
      }
    } finally {
      set({ commit } as Partial<State>);
    }
    const resolve = (ref: string) => (ref.startsWith('new:') ? created[Number(ref.slice(4))] : ref);
    let edges = get().edges;
    const map = byId(get().nodes);
    for (const c of fix.connect ?? []) {
      const s = resolve(c.source);
      const t = resolve(c.target);
      if (!s || !t || edges.some((e) => e.source === s && e.target === t)) continue;
      const v = evaluateConnection(map.get(s)!, map.get(t)!, map);
      edges = [...edges, { id: uid('e'), source: s, target: t, type: 'floating', data: { protocol: c.protocol ?? v.protocol, async: v.async, level: v.level === 'warn' ? 'warn' : 'ok' } }];
    }
    let nodes = get().nodes;
    for (const sp of fix.setProps ?? []) {
      nodes = nodes.map((n) => (n.id === sp.nodeId ? ({ ...n, data: { ...n.data, props: { ...n.data.props, ...sp.props } } } as AppNode) : n));
    }
    set({ nodes, edges, dirty: true });
    get().toast('ok', `Aplicado: ${fix.label}`);
    if (created.length) get().focus(created);
  },
  select: (ids) => {
    const s = new Set(ids);
    set({ nodes: get().nodes.map((n) => ({ ...n, selected: s.has(n.id) })), edges: get().edges.map((e) => ({ ...e, selected: s.has(e.id) })) });
  },
  focus: (ids) => {
    get().select(ids);
    set({ focusRequest: { ids, t: Date.now() } });
  },

  setMeta: (patch) => {
    get().commit('meta');
    set({ meta: { ...get().meta, ...patch } });
  },
  addDecision: (d) => {
    get().commit();
    const dec: Decision = { id: uid('adr'), title: 'Nueva decisión', status: 'propuesta', context: '', decision: '', consequences: '', ...d };
    set({ decisions: [...get().decisions, dec] });
  },
  updateDecision: (id, patch) => {
    get().commit(`adr:${id}`);
    set({ decisions: get().decisions.map((d) => (d.id === id ? { ...d, ...patch } : d)) });
  },
  deleteDecision: (id) => {
    get().commit();
    set({ decisions: get().decisions.filter((d) => d.id !== id) });
  },

  setThreatState: (id, patch) => {
    get().commit(`threat:${id}`);
    const cur = get().threats[id] ?? {};
    const next = { ...cur, ...patch };
    if (patch.status === undefined && 'status' in patch) delete next.status;
    set({ threats: { ...get().threats, [id]: next } });
  },
  setThreatControl: (id, key, value) => {
    get().commit();
    const cur = get().threats[id] ?? {};
    set({ threats: { ...get().threats, [id]: { ...cur, controls: { ...(cur.controls ?? {}), [key]: value } } } });
  },

  loadProject: (p, projectId = null) => {
    get().commit();
    set({
      nodes: sortNodes(p.nodes.map((n) => ({ ...n, selected: false }))),
      edges: p.edges.map((e) => ({ ...e, type: 'floating', selected: false })),
      decisions: p.decisions ?? [],
      threats: p.threats ?? {},
      meta: { ...emptyMeta(), ...p.meta },
      projectId,
      dirty: false,
      view: 'c2',
      c3Id: null,
      c3Selection: [],
      focusRequest: { ids: [], t: Date.now() },
    });
  },
  loadSpec: (spec, meta, decisions = []) => {
    const { nodes, edges } = buildFromSpec(spec);
    get().loadProject(
      {
        format: 'archiplan',
        version: 1,
        meta: { ...emptyMeta(), ...meta, provider: spec.cloud ?? meta.provider ?? 'aws', region: spec.region ?? (spec.cloud === 'azure' ? 'eastus' : 'us-east-1') },
        nodes,
        edges,
        decisions: decisions.map((d) => ({ ...d, id: uid('adr') })),
      },
      null,
    );
    set({ dirty: true });
  },
  newEmpty: () => {
    get().loadProject({ format: 'archiplan', version: 1, meta: emptyMeta(), nodes: [], edges: [], decisions: [], threats: {} }, null);
  },
  toProject: () => {
    const { nodes, edges, decisions, meta, threats } = get();
    return {
      format: 'archiplan',
      version: 1,
      meta: { ...meta, updatedAt: now() },
      nodes: nodes.map(({ selected: _s, dragging: _d, measured: _m, ...n }) => {
        void _s;
        void _d;
        void _m;
        return n as AppNode;
      }),
      edges: edges.map(({ selected: _s, ...e }) => {
        void _s;
        return e as AppEdge;
      }),
      decisions,
      threats,
    };
  },
  setProjectId: (id) => set({ projectId: id }),
  markSaved: () => set({ dirty: false }),

  autoLayout: () => {
    const { nodes, edges } = get();
    const map = byId(nodes);
    const zones = nodes.filter(isZone);
    const count = (k: ZoneKind) => zones.filter((z) => z.data.zoneKind === k).length;
    if (count('region') > 1 || count('vpc') > 1 || count('subnet-public') > 1 || count('subnet-private') > 1 || count('subnet-data') > 1 || count('boundary') > 0) {
      get().toast('warn', 'Auto‑organizar funciona con una sola región/VPC y una subnet de cada tipo (sin grupos libres).');
      return;
    }
    const zoneOf = (n: ServiceNode): Spec['services'][number]['zone'] => {
      const p = placementOf(n, map);
      return p === 'outside' ? 'global' : p === 'region' ? 'region' : p === 'subnet-public' ? 'public' : p === 'subnet-private' ? 'private' : 'data';
    };
    const services = nodes.filter(isService);
    const zid = (k: ZoneKind) => zones.find((z) => z.data.zoneKind === k);
    const meta = (k: ZoneKind) => {
      const z = zid(k);
      return z ? { id: z.id, label: z.data.label, props: z.data.props } : undefined;
    };
    const spec: Spec = {
      services: services.map((n) => ({ key: n.id, serviceId: n.data.serviceId, label: n.data.label, zone: zoneOf(n), props: n.data.props, notes: n.data.notes })),
      edges: [],
      zoneMeta: { region: meta('region'), vpc: meta('vpc'), public: meta('subnet-public'), private: meta('subnet-private'), data: meta('subnet-data') },
    };
    // Las claves son los ids actuales (empiezan por n_), buildFromSpec los conserva.
    const fixed = buildFromSpec(spec).nodes;
    // Zonas vacías que existían y no se usaron se conservan donde estaban
    const keptZones = zones.filter((z) => !fixed.some((f) => f.id === z.id)).map((z) => ({ ...z, parentId: undefined, position: absolutePosition(z, map) }));
    get().commit();
    set({ nodes: sortNodes([...fixed, ...keptZones] as AppNode[]), edges, focusRequest: { ids: [], t: Date.now() } });
  },

  cloud: () => primaryCloud(get().nodes, get().meta.provider ?? 'aws'),
  convertCloud: (to) => {
    const { nodes, edges, meta } = get();
    const oldMap = byId(nodes);
    const kept: string[] = [];
    let changed = 0;
    const next = nodes.map((n) => {
      if (isZone(n)) {
        const label = convertZoneLabel(n.data.zoneKind, n.data.label, to);
        const props = n.data.zoneKind === 'region' && n.data.props.region ? { ...n.data.props, region: convertRegion(String(n.data.props.region), to) } : n.data.props;
        return { ...n, data: { ...n.data, label, props } } as AppNode;
      }
      if (!isService(n)) return n;
      const c = convertService(n.data.serviceId, n.data.props, n.data.label, to);
      if (!c) {
        kept.push(n.data.label);
        return n;
      }
      if (c.serviceId !== n.data.serviceId) changed++;
      return { ...n, data: { ...n.data, serviceId: c.serviceId, label: c.label, props: c.props } } as AppNode;
    });
    const newMap = byId(next);
    const nextEdges = edges.map((e) => {
      const os = oldMap.get(e.source);
      const ot = oldMap.get(e.target);
      const ns = newMap.get(e.source);
      const nt = newMap.get(e.target);
      if (!os || !ot || !ns || !nt) return e;
      const d = (e.data ?? {}) as ConnData;
      const oldSug = evaluateConnection(os, ot, oldMap).protocol;
      if (d.protocol && d.protocol !== oldSug) return e; // protocolo personalizado: se respeta
      const v = evaluateConnection(ns, nt, newMap);
      return { ...e, data: { ...d, protocol: v.protocol, async: v.async } };
    });
    if (!changed) {
      get().toast('info', `El diagrama ya está en ${to === 'azure' ? 'Azure' : 'AWS'}.`);
      return;
    }
    get().commit();
    set({ nodes: next, edges: nextEdges, meta: { ...meta, provider: to, region: convertRegion(meta.region, to) } });
    get().toast('ok', `${changed} piezas convertidas a ${to === 'azure' ? 'Azure' : 'AWS'}.${kept.length ? ` Sin equivalente (se conservaron): ${kept.join(', ')}.` : ''}`);
  },

  setView: (v) => {
    if (v === 'c3' && !get().c3Id) {
      const sel = get().nodes.find((n) => n.selected && n.type === 'service');
      if (!sel) return;
      set({ c3Id: sel.id });
    }
    set({ view: v, c3Selection: [], focusRequest: { ids: [], t: Date.now() } });
  },
  openC3: (id) => set({ view: 'c3', c3Id: id, c3Selection: [], focusRequest: { ids: [], t: Date.now() } }),
  setC3: (id, model, coalesceKey) => {
    get().commit(coalesceKey ? `c3:${id}:${coalesceKey}` : undefined);
    set({ nodes: get().nodes.map((n) => (n.id === id && n.type === 'service' ? ({ ...n, data: { ...n.data, c3: model } } as AppNode) : n)) });
  },
  setC3Selection: (ids) => set({ c3Selection: ids }),
  toggleLayer: (l) => {
    const cur = get().layers;
    set({ layers: cur.includes(l) ? cur.filter((x) => x !== l) : [...cur, l] });
  },
  clearLayers: () => set({ layers: [] }),
  toast: (kind, text) => {
    const id = uid('t');
    set({ toasts: [...get().toasts.slice(-3), { id, kind, text }] });
    setTimeout(() => get().dismissToast(id), kind === 'error' ? 6500 : 4000);
  },
  dismissToast: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
  setViewportCenter: (c) => set({ viewportCenter: c }),
}));

// Autoguardado local (por si se cierra el navegador)
let t: ReturnType<typeof setTimeout> | undefined;
useStore.subscribe((s, prev) => {
  if (s.nodes === prev.nodes && s.edges === prev.edges && s.decisions === prev.decisions && s.meta === prev.meta && s.threats === prev.threats && s.projectId === prev.projectId) return;
  clearTimeout(t);
  t = setTimeout(() => {
    try {
      localStorage.setItem(AUTOSAVE_KEY, JSON.stringify({ ...useStore.getState().toProject(), projectId: useStore.getState().projectId }));
    } catch {
      /* cuota llena */
    }
  }, 600);
});
