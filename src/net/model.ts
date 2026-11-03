/**
 * Modelo de red configurable: puertos, Security Groups, listeners y target groups.
 *
 * Modo automático: si el proyecto no tiene Security Groups configurados, la red se
 * analiza con SGs derivados de las flechas (mínimo privilegio), igual que el Terraform.
 * Modo manual: el arquitecto define los SGs y sus reglas; el análisis usa exactamente eso.
 */
import { getService, lid, primaryCloud } from '../catalog/catalog';
import { ancestors, byId, isService, isZone, placementOf } from '../lib/graph';
import type { AppEdge, AppNode, Listener, NetConfig, SecurityGroup, ServiceNode, SgRule, TargetConfig } from '../types';

export const PORT_PRESETS: { label: string; protocol: SgRule['protocol']; from: number; to: number }[] = [
  { label: 'HTTPS', protocol: 'tcp', from: 443, to: 443 },
  { label: 'HTTP', protocol: 'tcp', from: 80, to: 80 },
  { label: 'App (8080)', protocol: 'tcp', from: 8080, to: 8080 },
  { label: 'PostgreSQL', protocol: 'tcp', from: 5432, to: 5432 },
  { label: 'MySQL / Aurora', protocol: 'tcp', from: 3306, to: 3306 },
  { label: 'SQL Server', protocol: 'tcp', from: 1433, to: 1433 },
  { label: 'Redis', protocol: 'tcp', from: 6379, to: 6379 },
  { label: 'Redis TLS (Azure)', protocol: 'tcp', from: 6380, to: 6380 },
  { label: 'MongoDB', protocol: 'tcp', from: 27017, to: 27017 },
  { label: 'SSH', protocol: 'tcp', from: 22, to: 22 },
  { label: 'Todo el tráfico', protocol: 'all', from: 0, to: 65535 },
];

/* ───────────────────────────── ubicación */

export const inVpc = (n: ServiceNode, map: Map<string, AppNode>) => placementOf(n, map).startsWith('subnet-');
const role = (n: ServiceNode) => getService(n.data.serviceId).role;

/** ¿La pieza lleva Security Groups? (recursos con interfaz de red en la VPC) */
export function needsSg(n: ServiceNode, map: Map<string, AppNode>): boolean {
  if (!inVpc(n, map)) return false;
  return !['netgw'].includes(role(n));
}

export function isLb(n: ServiceNode) {
  return role(n) === 'lb';
}

/** CIDR de la subnet donde está la pieza (o de la VPC). */
export function cidrOf(n: ServiceNode, map: Map<string, AppNode>): string | null {
  const anc = ancestors(n, map);
  const sub = anc.find((z) => z.data.zoneKind.startsWith('subnet-'));
  if (sub?.data.props.cidr) return String(sub.data.props.cidr);
  const vpc = anc.find((z) => z.data.zoneKind === 'vpc');
  return vpc?.data.props.cidr ? String(vpc.data.props.cidr) : null;
}

export function vpcCidr(nodes: AppNode[]): string {
  const v = nodes.find((n) => isZone(n) && n.data.zoneKind === 'vpc');
  return v && isZone(v) ? String(v.data.props.cidr ?? '10.0.0.0/16') : '10.0.0.0/16';
}

/* ───────────────────────────── puertos */

function enginePort(engine: string, fallback: number) {
  const e = engine.toLowerCase();
  if (e.includes('mysql') || e.includes('mariadb')) return 3306;
  if (e.includes('sqlserver')) return 1433;
  if (e.includes('oracle')) return 1521;
  if (e.includes('postgres')) return 5432;
  return fallback;
}

/** Puerto por defecto en el que escucha una pieza. */
export function defaultPort(n: ServiceNode): number {
  const l = lid(n);
  const p = n.data.props;
  switch (l) {
    case 'rds':
      return enginePort(String(p.engine ?? 'postgres'), 5432);
    case 'aurora':
      return enginePort(String(p.engine ?? 'aurora-postgresql'), 5432);
    case 'elasticache':
      return n.data.serviceId === 'az-redis' ? 6380 : 6379;
    case 'documentdb':
      return 27017;
    case 'redshift':
      return n.data.serviceId === 'az-synapse' ? 1433 : 5439;
    case 'msk':
      return 9098;
    case 'efs':
      return n.data.serviceId === 'az-files' ? 445 : 2049;
    case 'opensearch':
      return 443;
    case 'ec2':
    case 'ecs':
    case 'eks':
      return 8080;
    case 'alb':
    case 'nlb':
      return 443;
    default:
      return 443;
  }
}

/** Puerto en el que escucha la pieza (configurado o por defecto). */
export function listenPort(n: ServiceNode): number {
  return n.data.net?.port ?? defaultPort(n);
}

export function defaultListeners(n: ServiceNode): Listener[] {
  if (lid(n) === 'nlb') return [{ id: 'l443', port: 443, protocol: 'TCP', action: 'forward' }];
  return [
    { id: 'l443', port: 443, protocol: 'HTTPS', action: 'forward', cert: true },
    { id: 'l80', port: 80, protocol: 'HTTP', action: 'redirect-https' },
  ];
}

export function listenersOf(n: ServiceNode): Listener[] {
  return n.data.net?.listeners ?? defaultListeners(n);
}

export function targetOf(lb: ServiceNode, target: ServiceNode): TargetConfig {
  return lb.data.net?.targets?.[target.id] ?? { port: listenPort(target), protocol: lid(lb) === 'nlb' ? 'TCP' : 'HTTP', healthPath: '/health' };
}

export function originProtocol(n: ServiceNode): NetConfig['originProtocol'] {
  return n.data.net?.originProtocol ?? 'https-only';
}

/* ───────────────────────────── semántica de conexión de una flecha */

export type ConnKind =
  /** El origen abre una conexión al puerto del destino. */
  | 'connect'
  /** La pieza en la VPC sale a un servicio administrado / Internet (necesita ruta de salida). */
  | 'egress'
  /** Lo invoca la nube (eventos, triggers, plano de control): sin chequeo de red. */
  | 'managed'
  | 'none';

export interface ConnSemantics {
  kind: ConnKind;
  /** Quién inicia la conexión. */
  from: ServiceNode;
  /** A quién se conecta. */
  to: ServiceNode;
  port: number;
}

const CONTROL_SRC = ['waf', 'cert', 'devops', 'analytics'];

export function semantics(e: AppEdge, map: Map<string, AppNode>): ConnSemantics | null {
  const s = map.get(e.source);
  const t = map.get(e.target);
  if (!isService(s) || !isService(t)) return null;
  const rs = role(s);
  const rt = role(t);
  const sd = getService(s.data.serviceId);
  // DNS → X: los clientes de Internet llegan a X (el DNS solo resuelve el nombre).
  if (rs === 'dns') {
    if (['lb', 'cdn', 'api', 'compute'].includes(rt) && inVpc(t, map)) return { kind: 'connect', from: s, to: t, port: isLb(t) ? requestPort(s, t) : listenPort(t) };
    return { kind: 'none', from: s, to: t, port: 0 };
  }
  if (CONTROL_SRC.includes(rs) || rt === 'actor' || rt === 'dns' || rt === 'waf' || rt === 'cert') return { kind: 'none', from: s, to: t, port: 0 };
  if (rs === 'identity') return { kind: 'managed', from: s, to: t, port: 0 };
  // La pieza que consume "tira" de la cola / stream / registro
  if (['queue', 'stream'].includes(rs) && ['compute', 'workflow'].includes(rt)) {
    return lid(t) === 'lambda' || !inVpc(t, map) ? { kind: 'managed', from: s, to: t, port: 0 } : { kind: 'egress', from: t, to: s, port: 443 };
  }
  if (rs === 'registry') return inVpc(t, map) ? { kind: 'egress', from: t, to: s, port: 443 } : { kind: 'managed', from: s, to: t, port: 0 };
  if (['topic', 'eventbus'].includes(rs) || (sd.emitsEvents && ['datastore', 'storage'].includes(rs))) return { kind: 'managed', from: s, to: t, port: 0 };
  if (rs === 'netgw' || rt === 'netgw') return { kind: 'none', from: s, to: t, port: 0 };
  // Destino dentro de la VPC: conexión directa a su puerto
  if (inVpc(t, map)) return { kind: 'connect', from: s, to: t, port: isLb(t) ? requestPort(s, t) : isLb(s) ? targetOf(s, t).port : listenPort(t) };
  // Destino fuera de la VPC y origen dentro: salida
  if (inVpc(s, map)) return { kind: 'egress', from: s, to: t, port: 443 };
  return { kind: 'managed', from: s, to: t, port: 0 };
}

/** Puerto con el que el origen llama a un balanceador. */
export function requestPort(s: ServiceNode, lb: ServiceNode): number {
  if (role(s) === 'cdn') return originProtocol(s) === 'http-only' ? 80 : 443;
  const ls = listenersOf(lb);
  if (['actor', 'external', 'dns'].includes(role(s))) return ls.some((l) => l.port === 443) ? 443 : ls[0]?.port ?? 443;
  return ls.find((l) => l.action === 'forward')?.port ?? 443;
}

/* ───────────────────────────── generación de Security Groups (mínimo privilegio) */

const slug = (s: string) =>
  s
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40) || 'pieza';

export interface GeneratedNet {
  groups: SecurityGroup[];
  assign: Record<string, string[]>;
}

/** Un SG por pieza en la VPC con las reglas exactas que piden las flechas. */
export function generateSecurityGroups(nodes: AppNode[], edges: AppEdge[]): GeneratedNet {
  const map = byId(nodes);
  const services = nodes.filter(isService);
  const groups: SecurityGroup[] = [];
  const assign: Record<string, string[]> = {};
  const azure = primaryCloud(nodes) === 'azure';
  for (const n of services) {
    if (!needsSg(n, map)) continue;
    const id = `sg_${n.id}`;
    groups.push({
      id,
      name: `${azure ? 'nsg' : 'sg'}-${slug(n.data.label)}`,
      description: `Tráfico permitido hacia ${n.data.label}`,
      inbound: [],
      outbound: [{ id: `${id}_out`, protocol: 'all', from: 0, to: 65535, peer: { kind: 'cidr', value: '0.0.0.0/0' }, description: 'Salida (por defecto)' }],
    });
    assign[n.id] = [id];
  }
  const byNode = (id: string) => groups.find((g) => g.id === `sg_${id}`);
  const addIn = (g: SecurityGroup, port: number, peer: SgRule['peer'], description: string) => {
    if (g.inbound.some((r) => r.from <= port && r.to >= port && JSON.stringify(r.peer) === JSON.stringify(peer))) return;
    g.inbound.push({ id: `${g.id}_in${g.inbound.length + 1}`, protocol: 'tcp', from: port, to: port, peer, description });
  };
  for (const e of edges) {
    const sem = semantics(e, map);
    if (!sem || sem.kind !== 'connect') continue;
    const g = byNode(sem.to.id);
    if (!g) continue;
    const from = sem.from;
    const ports = isLb(sem.to) ? [...new Set([sem.port, ...listenersOf(sem.to).map((l) => l.port)])] : [sem.port];
    for (const port of ports) {
      if (inVpc(from, map) && byNode(from.id)) addIn(g, port, { kind: 'sg', sgId: byNode(from.id)!.id }, `Desde ${from.data.label}`);
      else if (role(from) === 'cdn') addIn(g, port, { kind: 'prefix', value: 'cdn' }, `Desde ${from.data.label}`);
      else addIn(g, port, { kind: 'cidr', value: '0.0.0.0/0' }, role(from) === 'dns' ? 'Clientes de Internet' : `Desde ${from.data.label} (Internet)`);
    }
  }
  return { groups, assign };
}

/** Configuración de red efectiva: la del proyecto (manual) o la derivada (automática). */
export interface EffectiveNet {
  mode: 'auto' | 'manual';
  groups: SecurityGroup[];
  sgIdsOf: (n: ServiceNode) => string[];
}

export function effectiveNet(nodes: AppNode[], edges: AppEdge[], groups: SecurityGroup[] | undefined): EffectiveNet {
  if (groups && groups.length) {
    return { mode: 'manual', groups, sgIdsOf: (n) => n.data.net?.sgIds ?? [] };
  }
  const gen = generateSecurityGroups(nodes, edges);
  return { mode: 'auto', groups: gen.groups, sgIdsOf: (n) => gen.assign[n.id] ?? [] };
}

/* ───────────────────────────── IPs y CIDR */

function ipToInt(ip: string): number | null {
  const m = ip.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((x) => x > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function parseCidr(c: string): { base: number; bits: number } | null {
  const [ip, b] = c.trim().split('/');
  const base = ipToInt(ip);
  const bits = b === undefined ? 32 : Number(b);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return { base, bits };
}

/** ¿El bloque `outer` contiene completamente al bloque `inner`? */
export function cidrContains(outer: string, inner: string): boolean {
  const o = parseCidr(outer);
  const i = parseCidr(inner);
  if (!o || !i || i.bits < o.bits) return false;
  const mask = o.bits === 0 ? 0 : (~0 << (32 - o.bits)) >>> 0;
  return ((o.base & mask) >>> 0) === ((i.base & mask) >>> 0);
}

export const isAnyCidr = (c: string) => c.trim() === '0.0.0.0/0' || c.trim() === '::/0';

export function ruleText(r: SgRule, groups: SecurityGroup[], cdnName = 'CloudFront'): string {
  const ports = r.protocol === 'all' ? 'todo el tráfico' : r.from === r.to ? `${r.protocol.toUpperCase()} ${r.from}` : `${r.protocol.toUpperCase()} ${r.from}-${r.to}`;
  const peer = r.peer.kind === 'cidr' ? r.peer.value : r.peer.kind === 'prefix' ? `prefijos de ${cdnName}` : groups.find((g) => g.id === (r.peer as { sgId: string }).sgId)?.name ?? 'SG eliminado';
  return `${ports} · ${peer}`;
}

/* ───────────────────────────── lenguaje claro para reglas y accesos */

export const PORT_NAME: Record<number, string> = {
  22: 'SSH',
  80: 'HTTP',
  443: 'HTTPS',
  445: 'SMB',
  1433: 'SQL Server',
  1521: 'Oracle',
  2049: 'NFS',
  3000: 'App',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5439: 'Redshift',
  6379: 'Redis',
  6380: 'Redis TLS',
  8080: 'App',
  8443: 'HTTPS alt.',
  9098: 'Kafka',
  27017: 'MongoDB',
};

export const portLabel = (p: number) => (PORT_NAME[p] ? `${PORT_NAME[p]} ${p}` : `puerto ${p}`);

/** ¿La regla cubre este puerto TCP? */
export const ruleCovers = (r: SgRule, port: number) => r.protocol === 'all' || (r.protocol === 'tcp' && r.from <= port && r.to >= port);

/** ¿El origen/destino de la regla corresponde a esta pieza? */
export function peerIs(peer: SgRule['peer'], other: ServiceNode, map: Map<string, AppNode>, sgIdsOf: (n: ServiceNode) => string[]): boolean {
  if (peer.kind === 'cidr') {
    if (isAnyCidr(peer.value)) return true;
    const c = inVpc(other, map) ? cidrOf(other, map) : null;
    return !!c && cidrContains(peer.value, c);
  }
  if (peer.kind === 'prefix') return role(other) === 'cdn';
  return inVpc(other, map) && sgIdsOf(other).includes(peer.sgId);
}

/** Quién es el origen de una regla, en palabras (nombres de piezas en lugar de ids de SG). */
export function peerText(peer: SgRule['peer'], nodes: AppNode[], groups: SecurityGroup[], sgIdsOf: (n: ServiceNode) => string[], cdnName = 'CloudFront'): string {
  if (peer.kind === 'prefix') return cdnName;
  if (peer.kind === 'cidr') return isAnyCidr(peer.value) ? 'cualquier IP de Internet' : `el rango ${peer.value}`;
  const g = groups.find((x) => x.id === peer.sgId);
  if (!g) return 'un grupo eliminado';
  const users = nodes.filter(isService).filter((n) => sgIdsOf(n).includes(g.id));
  return users.length ? users.map((n) => n.data.label).join(', ') : `el grupo ${g.name} (sin piezas)`;
}

export function ruleSentence(r: SgRule, dir: 'inbound' | 'outbound', nodes: AppNode[], groups: SecurityGroup[], sgIdsOf: (n: ServiceNode) => string[], cdnName = 'CloudFront'): string {
  const what = r.protocol === 'all' ? 'todo el tráfico' : r.from === r.to ? portLabel(r.from) : `${r.protocol.toUpperCase()} ${r.from}–${r.to}`;
  return `${what} ${dir === 'inbound' ? 'desde' : 'hacia'} ${peerText(r.peer, nodes, groups, sgIdsOf, cdnName)}`;
}

/** Origen de un acceso, elegido por el arquitecto en palabras. */
export type AccessSource = { kind: 'node'; id: string } | { kind: 'internet' } | { kind: 'cdn' } | { kind: 'cidr'; value: string };

const SG_COLORS = ['#2a78d6', '#e8590c', '#2f9e44', '#ae3ec9', '#d6336c', '#0c8599', '#e0a100', '#5c7cfa', '#868e96'];
export const sgColor = (groups: SecurityGroup[], id: string) => SG_COLORS[Math.max(0, groups.findIndex((g) => g.id === id)) % SG_COLORS.length];
