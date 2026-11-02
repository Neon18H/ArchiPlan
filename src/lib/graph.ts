import type { AppEdge, AppNode, Placement, ServiceNode, ZoneKind, ZoneNode } from '../types';

export const isService = (n: AppNode | undefined): n is ServiceNode => !!n && n.type === 'service';
export const isZone = (n: AppNode | undefined): n is ZoneNode => !!n && n.type === 'zone';

export function byId(nodes: AppNode[]) {
  const m = new Map<string, AppNode>();
  for (const n of nodes) m.set(n.id, n);
  return m;
}

/** Cadena de zonas que contienen al nodo (de la más cercana a la más externa). */
export function ancestors(node: AppNode, map: Map<string, AppNode>): ZoneNode[] {
  const out: ZoneNode[] = [];
  let cur = node.parentId ? map.get(node.parentId) : undefined;
  let guard = 0;
  while (cur && guard++ < 20) {
    if (isZone(cur)) out.push(cur);
    cur = cur.parentId ? map.get(cur.parentId) : undefined;
  }
  return out;
}

export function placementOf(node: AppNode, map: Map<string, AppNode>): Placement {
  const anc = ancestors(node, map);
  const subnet = anc.find((z) => z.data.zoneKind.startsWith('subnet-'));
  if (subnet) return subnet.data.zoneKind as Placement;
  if (anc.some((z) => z.data.zoneKind === 'region' || z.data.zoneKind === 'vpc')) return 'region';
  return 'outside';
}

export function insideVpc(node: AppNode, map: Map<string, AppNode>) {
  return ancestors(node, map).some((z) => z.data.zoneKind === 'vpc');
}

/** Ordena para que los padres vayan antes que los hijos (requisito de React Flow). */
export function sortNodes(nodes: AppNode[]): AppNode[] {
  const map = byId(nodes);
  const depth = (n: AppNode) => {
    let d = 0;
    let cur = n;
    while (cur.parentId && map.get(cur.parentId) && d < 20) {
      cur = map.get(cur.parentId)!;
      d++;
    }
    return d;
  };
  return [...nodes]
    .map((n, i) => ({ n, i, d: depth(n), z: n.type === 'zone' ? 0 : 1 }))
    .sort((a, b) => a.d - b.d || a.z - b.z || a.i - b.i)
    .map((x) => x.n);
}

export function absolutePosition(node: AppNode, map: Map<string, AppNode>) {
  let x = node.position.x;
  let y = node.position.y;
  let cur = node.parentId ? map.get(node.parentId) : undefined;
  let guard = 0;
  while (cur && guard++ < 20) {
    x += cur.position.x;
    y += cur.position.y;
    cur = cur.parentId ? map.get(cur.parentId) : undefined;
  }
  return { x, y };
}

export const nodeSize = (n: AppNode) => ({
  w: (n.width ?? n.measured?.width ?? (n.style?.width as number) ?? (n.type === 'zone' ? 400 : 168)) as number,
  h: (n.height ?? n.measured?.height ?? (n.style?.height as number) ?? (n.type === 'zone' ? 260 : 64)) as number,
});

export const ZONE_DEPTH: Record<ZoneKind, number> = {
  boundary: 0,
  region: 1,
  vpc: 2,
  'subnet-public': 3,
  'subnet-private': 3,
  'subnet-data': 3,
};

export function uid(prefix = 'n') {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-3)}`;
}

export function neighbors(id: string, edges: AppEdge[]) {
  return {
    out: edges.filter((e) => e.source === id).map((e) => e.target),
    in: edges.filter((e) => e.target === id).map((e) => e.source),
  };
}
