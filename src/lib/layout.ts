import { defaultProps, getService, LAYERS, ZONES } from '../catalog/catalog';
import type { AppEdge, AppNode, Layer, PropValue, ServiceNode, ZoneKind, ZoneNode } from '../types';
import { sqlPortFor, suggestProtocol } from '../rules/connections';
import { uid } from './graph';

export type SpecZone = 'global' | 'region' | 'public' | 'private' | 'data';

export interface SpecService {
  key: string;
  serviceId: string;
  label?: string;
  zone: SpecZone;
  props?: Record<string, PropValue>;
  notes?: string;
}

export interface Spec {
  services: SpecService[];
  edges: [string, string, string?][];
  region?: string;
  zoneMeta?: Partial<Record<'region' | 'vpc' | 'public' | 'private' | 'data', { id?: string; label?: string; props?: Record<string, PropValue> }>>;
}

export const NODE_W = 172;
export const NODE_H = 64;
const GAP_X = 56;
const GAP_Y = 34;
const PAD = 24;
const HEADER = 38;

const colH = (n: number) => (n ? n * NODE_H + (n - 1) * GAP_Y : NODE_H);

/** Construye nodos y conexiones con un layout legible: Internet → Región → VPC → subnets. */
export function buildFromSpec(spec: Spec): { nodes: AppNode[]; edges: AppEdge[] } {
  const nodes: AppNode[] = [];
  const edges: AppEdge[] = [];
  const idOf = new Map<string, string>();
  const by = (z: SpecZone) => spec.services.filter((s) => s.zone === z);

  const mkService = (s: SpecService, x: number, y: number, parentId?: string): ServiceNode => {
    const def = getService(s.serviceId);
    const id = idOf.get(s.key) ?? (s.key.startsWith('n_') ? s.key : uid('n'));
    idOf.set(s.key, id);
    return {
      id,
      type: 'service',
      position: { x, y },
      ...(parentId ? { parentId } : {}),
      data: { serviceId: s.serviceId, label: s.label ?? def.name, props: { ...defaultProps(def.props), ...(s.props ?? {}) }, ...(s.notes ? { notes: s.notes } : {}) },
    };
  };
  const mkZone = (kind: ZoneKind, metaKey: keyof NonNullable<Spec['zoneMeta']>, x: number, y: number, w: number, h: number, parentId?: string): ZoneNode => {
    const meta = spec.zoneMeta?.[metaKey];
    const z = ZONES[kind];
    const props: Record<string, PropValue> = Object.fromEntries(z.props.map((p) => [p.key, p.default]));
    if (kind === 'region' && spec.region) props.region = spec.region;
    return {
      id: meta?.id ?? uid('z'),
      type: 'zone',
      position: { x, y },
      ...(parentId ? { parentId } : {}),
      style: { width: w, height: h },
      width: w,
      height: h,
      data: { zoneKind: kind, label: meta?.label ?? z.label, props: { ...props, ...(meta?.props ?? {}) } },
    };
  };
  const layerOrder = (s: SpecService) => LAYERS[getService(s.serviceId).layer].order;

  // ── Columna Internet / global
  const globals = by('global');
  const actors = globals.filter((s) => getService(s.serviceId).layer === 'actores');
  const edgeG = globals.filter((s) => getService(s.serviceId).layer !== 'actores').sort((a, b) => layerOrder(a) - layerOrder(b));
  const regionals = by('region');
  const subnets: [SpecZone, ZoneKind][] = [['public', 'subnet-public'], ['private', 'subnet-private'], ['data', 'subnet-data']];
  const usedSubnets = subnets.filter(([z]) => by(z).length > 0);
  const hasVpc = usedSubnets.length > 0;
  const hasRegion = hasVpc || regionals.length > 0;

  // Medidas de la VPC
  const subnetW = NODE_W + PAD * 2;
  const subnetH = Math.max(...usedSubnets.map(([z]) => colH(by(z).length)), NODE_H) + HEADER + PAD;
  const vpcW = hasVpc ? usedSubnets.length * subnetW + (usedSubnets.length - 1) * 28 + PAD * 2 : 0;
  const vpcH = hasVpc ? subnetH + HEADER + PAD : 0;

  // Columnas regionales por capa
  const regCols = new Map<Layer, SpecService[]>();
  for (const s of regionals.sort((a, b) => layerOrder(a) - layerOrder(b))) {
    let layer = getService(s.serviceId).layer;
    if (layer === 'observabilidad') layer = 'seguridad';
    if (!regCols.has(layer)) regCols.set(layer, []);
    regCols.get(layer)!.push(s);
  }
  // Columnas muy altas se parten en dos
  const cols: SpecService[][] = [];
  for (const list of regCols.values()) {
    for (let i = 0; i < list.length; i += 4) cols.push(list.slice(i, i + 4));
  }
  // Con VPC y varias columnas regionales, los servicios regionales van en una grilla debajo de la VPC
  // (diagrama más cuadrado y legible); sin VPC, en columnas por capa de izquierda a derecha.
  const below = hasVpc && cols.length >= 2;
  const regList = cols.flat();
  const gridCols = below ? Math.max(2, Math.floor((vpcW + GAP_X) / (NODE_W + GAP_X))) : 0;
  const gridRows = below ? Math.ceil(regList.length / gridCols) : 0;
  const gridW = below ? Math.min(gridCols, regList.length) * (NODE_W + GAP_X) - GAP_X : 0;
  const gridH = below ? colH(gridRows) : 0;
  const regContentH = below ? vpcH + GAP_Y * 1.5 + gridH : Math.max(vpcH, ...cols.map((c) => colH(c.length)), NODE_H);
  const regionW = !hasRegion
    ? 0
    : below
      ? PAD * 2 + Math.max(vpcW, gridW)
      : PAD * 2 + vpcW + (hasVpc && cols.length ? GAP_X : 0) + cols.length * (NODE_W + GAP_X) - (cols.length ? GAP_X : 0);
  const regionH = regContentH + HEADER + PAD;

  const totalH = Math.max(regionH, colH(actors.length), colH(edgeG.length));
  const centerY = (h: number) => Math.max(0, (totalH - h) / 2);

  let x = 0;
  if (actors.length) {
    let y = centerY(colH(actors.length));
    for (const s of actors) {
      nodes.push(mkService(s, x, y));
      y += NODE_H + GAP_Y;
    }
    x += NODE_W + GAP_X + 20;
  }
  if (edgeG.length) {
    // Las piezas del borde en fila de a 4
    const chunks: SpecService[][] = [];
    for (let i = 0; i < edgeG.length; i += 4) chunks.push(edgeG.slice(i, i + 4));
    for (const ch of chunks) {
      let y = centerY(colH(ch.length));
      for (const s of ch) {
        nodes.push(mkService(s, x, y));
        y += NODE_H + GAP_Y;
      }
      x += NODE_W + GAP_X;
    }
    x += 20;
  }

  if (hasRegion) {
    const region = mkZone('region', 'region', x, centerY(regionH), regionW, regionH);
    nodes.push(region);
    let rx = PAD;
    if (hasVpc) {
      const vpc = mkZone('vpc', 'vpc', rx, below ? HEADER : HEADER + (regContentH - vpcH) / 2, vpcW, vpcH, region.id);
      nodes.push(vpc);
      let sx = PAD;
      for (const [z, kind] of usedSubnets) {
        const sub = mkZone(kind, z as 'public', sx, HEADER, subnetW, subnetH, vpc.id);
        nodes.push(sub);
        let y = HEADER;
        for (const s of by(z)) {
          nodes.push(mkService(s, PAD, y, sub.id));
          y += NODE_H + GAP_Y;
        }
        sx += subnetW + 28;
      }
      rx += vpcW + GAP_X;
    }
    if (below) {
      regList.forEach((s, i) => {
        const gx = PAD + (i % gridCols) * (NODE_W + GAP_X);
        const gy = HEADER + vpcH + GAP_Y * 1.5 + Math.floor(i / gridCols) * (NODE_H + GAP_Y);
        nodes.push(mkService(s, gx, gy, region.id));
      });
    }
    for (const col of below ? [] : cols) {
      let y = HEADER + (regContentH - colH(col.length)) / 2;
      for (const s of col) {
        nodes.push(mkService(s, rx, y, region.id));
        y += NODE_H + GAP_Y;
      }
      rx += NODE_W + GAP_X;
    }
  }

  for (const [a, b, protocol] of spec.edges) {
    const sa = spec.services.find((s) => s.key === a);
    const sb = spec.services.find((s) => s.key === b);
    if (!sa || !sb) continue;
    const sug = suggestProtocol(getService(sa.serviceId), getService(sb.serviceId));
    if (sb.serviceId === 'rds' || sb.serviceId === 'aurora') sug.protocol = sqlPortFor(sb.props?.engine ?? (sb.serviceId === 'aurora' ? 'aurora-postgresql' : 'postgres'));
    edges.push({
      id: uid('e'),
      source: idOf.get(a)!,
      target: idOf.get(b)!,
      type: 'floating',
      data: { protocol: protocol ?? sug.protocol, async: sug.async },
    });
  }
  return { nodes, edges };
}
