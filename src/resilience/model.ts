/**
 * Resiliencia: redundancia, failover y recuperación ante desastres.
 *
 * Para cada pieza resuelve, a partir de sus propiedades y de la estrategia de DR del proyecto:
 *  - qué pasa si falla una instancia o nodo (a qué recurso falla y en cuánto tiempo),
 *  - qué pasa si cae una zona de disponibilidad,
 *  - qué pasa si cae la región completa (región secundaria, réplica entre regiones, DNS),
 *  - con qué se recuperan los datos si se corrompen o los cifra un ransomware (backups, PITR).
 *
 * Los tiempos son valores típicos documentados por AWS/Azure; sirven para comparar diseños,
 * no son un SLA.
 */
import { cloudText, getService, lid, primaryCloud } from '../catalog/catalog';
import { ancestors, byId, isService } from '../lib/graph';
import type { AppEdge, AppNode, Cloud, PropValue, ServiceNode } from '../types';

/* ───────────────────────── estrategia de DR del proyecto */

export type DrStrategy = 'none' | 'backup' | 'pilot' | 'warm' | 'active';

export interface DrConfig {
  strategy: DrStrategy;
  /** Región secundaria (texto libre: us-west-2, eastus2…). */
  secondaryRegion: string;
  /** Objetivos del negocio, en minutos. */
  rtoMin: number;
  rpoMin: number;
}

export const DEFAULT_DR: DrConfig = { strategy: 'none', secondaryRegion: 'us-west-2', rtoMin: 60, rpoMin: 15 };

export const DR_STRATEGIES: { id: DrStrategy; label: string; rto: string; rpo: string; cost: string; help: string }[] = [
  { id: 'none', label: 'Sin DR', rto: '∞ (hasta que vuelva la región)', rpo: '—', cost: '$', help: 'Todo vive en una región. Si la región cae, el servicio cae con ella.' },
  { id: 'backup', label: 'Backup y restauración', rto: 'horas', rpo: '24 h (copia diaria)', cost: '$', help: 'Copias de los backups en otra región. Ante un desastre se despliega todo con IaC y se restauran los datos.' },
  { id: 'pilot', label: 'Pilot light', rto: '10‑30 min', rpo: 'segundos‑minutos', cost: '$$', help: 'Los datos se replican en vivo a la región secundaria; el cómputo está apagado (ASG en 0) y se enciende al fallar.' },
  { id: 'warm', label: 'Warm standby', rto: 'minutos', rpo: 'segundos', cost: '$$$', help: 'Una copia reducida de todo corre en la región secundaria y escala a tamaño completo al fallar.' },
  { id: 'active', label: 'Activo‑activo (multi‑sitio)', rto: '≈ detección DNS', rpo: '≈ 0', cost: '$$$$', help: 'Ambas regiones atienden tráfico. Si una cae, Route 53 manda todo a la otra.' },
];
export const DR_MAP = Object.fromEntries(DR_STRATEGIES.map((s) => [s.id, s])) as Record<DrStrategy, (typeof DR_STRATEGIES)[number]>;

export function drOf(meta: { dr?: Partial<DrConfig> } | undefined): DrConfig {
  return { ...DEFAULT_DR, ...(meta?.dr ?? {}) };
}

/* ───────────────────────── tipos de pieza */

export type ResKind = 'fleet' | 'single-vm' | 'serverless' | 'relational' | 'nosql' | 'cache' | 'object' | 'files' | 'search' | 'broker' | 'lb' | 'nat' | 'dns' | 'global' | 'managed' | 'identity' | 'actor';

const GLOBAL = new Set(['cloudfront', 'route53', 'waf', 'shield', 'iam', 'globalaccelerator', 'organizations']);
const FLEET = new Set(['ec2', 'ecs', 'eks', 'beanstalk', 'batch', 'apprunner']);
const RELATIONAL = new Set(['rds', 'aurora', 'documentdb', 'neptune', 'redshift']);

export function resKind(n: ServiceNode): ResKind {
  const id = lid(n);
  const role = getService(n.data.serviceId).role;
  if (role === 'actor' || role === 'external') return 'actor';
  if (GLOBAL.has(id)) return id === 'route53' ? 'dns' : 'global';
  if (id === 'lightsail' || id === 'onprem') return 'single-vm';
  if (FLEET.has(id)) return 'fleet';
  if (id === 'lambda') return 'serverless';
  if (RELATIONAL.has(id)) return 'relational';
  if (id === 'dynamodb') return 'nosql';
  if (id === 'elasticache' || id === 'memorydb') return 'cache';
  if (id === 's3') return 'object';
  if (id === 'efs' || id === 'fsx') return 'files';
  if (id === 'opensearch') return 'search';
  if (id === 'msk' || id === 'mq') return 'broker';
  if (id === 'alb' || id === 'nlb') return 'lb';
  if (id === 'natgw') return 'nat';
  if (id === 'cognito') return 'identity';
  return 'managed';
}

/** ¿Tiene datos que se pierden o hay que recuperar? */
export const holdsData = (k: ResKind) => ['relational', 'nosql', 'object', 'files', 'search', 'broker'].includes(k);

/* ───────────────────────── configuración por pieza */

export interface CallerConfig {
  timeoutMs: number;
  retries: number;
  breaker: boolean;
}

export interface NodeRes {
  kind: ResKind;
  /** AZ en las que corre (instancias repartidas o réplica en otra AZ). */
  azs: number;
  /** Segundos hasta que el health check saca una instancia caída. */
  detectS: number;
  /** Failover cuando cae el primario / una instancia (s; Infinity = no hay). */
  failoverS: number;
  /** Despliegue de RDS. */
  deployment?: 'single' | 'multi-az' | 'multi-az-cluster';
  readReplicas: number;
  /** Replicación a otra región (Global Database, Global Tables, réplica cross‑region, CRR…). */
  crossRegion: boolean;
  /** Días de retención de backups automáticos (0 = sin backups). */
  backupDays: number;
  pitr: boolean;
  versioning: boolean;
  rdsProxy: boolean;
  /** NAT Gateway: uno por AZ. */
  perAz: boolean;
  /** Route 53 */
  routing?: 'simple' | 'failover' | 'latency' | 'weighted';
  healthChecks?: boolean;
  ttl?: number;
  caller: CallerConfig;
}

const num = (p: Record<string, PropValue>, k: string, d: number) => (p[k] !== undefined && p[k] !== '' && Number.isFinite(Number(p[k])) ? Number(p[k]) : d);
const bool = (p: Record<string, PropValue>, k: string, d: boolean) => (p[k] === undefined ? d : !!p[k]);

/** Instancias deseadas de una flota (mismas claves que el escalado). */
function desiredOf(n: ServiceNode): number {
  const p = n.data.props;
  const id = lid(n);
  if (id === 'ec2') return Math.max(1, num(p, 'count', 2));
  if (id === 'ecs') return Math.max(0, num(p, 'desired', 2));
  if (id === 'eks') return Math.max(1, num(p, 'nodes', 3));
  if (id === 'apprunner' || id === 'beanstalk') return Math.max(1, num(p, 'instances', 1));
  return Math.max(1, num(p, 'instances', 1));
}

export function vpcAzs(n: AppNode, map: Map<string, AppNode>): number {
  const vpc = ancestors(n, map).find((z) => z.data.zoneKind === 'vpc');
  return vpc ? Math.max(1, Number(vpc.data.props.azs ?? 2)) : 3;
}

export function nodeRes(n: ServiceNode, map: Map<string, AppNode>, security: Record<string, boolean> = {}): NodeRes {
  const p = n.data.props;
  const kind = resKind(n);
  const id = lid(n);
  const vAzs = vpcAzs(n, map);
  const resilientCalls = !!security.resilience;
  const caller: CallerConfig = {
    timeoutMs: num(p, 'timeoutMs', resilientCalls ? 2000 : 30000),
    retries: Math.max(0, num(p, 'retries', resilientCalls ? 2 : 3)),
    breaker: bool(p, 'circuitBreaker', resilientCalls),
  };
  const r: NodeRes = {
    kind,
    azs: 3,
    detectS: 30,
    failoverS: 0,
    readReplicas: 0,
    crossRegion: !!p.crossRegion,
    backupDays: 0,
    pitr: false,
    versioning: false,
    rdsProxy: !!p.rdsProxy,
    perAz: !!p.perAz,
    caller,
  };
  switch (kind) {
    case 'fleet': {
      const desired = desiredOf(n);
      const spread = num(p, 'azSpread', desired >= 2 ? vAzs : 1);
      r.azs = Math.max(1, Math.min(spread, vAzs, Math.max(1, desired)));
      r.detectS = Math.max(5, num(p, 'hcInterval', 10) * Math.max(1, num(p, 'hcThreshold', 3)));
      r.failoverS = r.detectS;
      break;
    }
    case 'single-vm':
      r.azs = 1;
      r.failoverS = Infinity;
      break;
    case 'relational': {
      const isRds = id === 'rds';
      if (isRds) {
        // «Multi‑AZ» de las propiedades decide si hay standby; «deployment» elige el tipo
        const dep = (p.multiAZ === false ? 'single' : p.deployment === 'multi-az-cluster' ? 'multi-az-cluster' : 'multi-az') as NodeRes['deployment'];
        r.deployment = dep;
        r.azs = dep === 'single' ? 1 : dep === 'multi-az-cluster' ? 3 : 2;
        r.failoverS = dep === 'single' ? Infinity : dep === 'multi-az-cluster' ? 35 : 90;
        r.readReplicas = Math.max(0, num(p, 'readReplicas', 0));
        r.backupDays = Math.max(0, num(p, 'backupDays', 7));
        r.pitr = r.backupDays > 0;
      } else {
        // Aurora, DocumentDB, Neptune: almacenamiento en 3 AZ; las réplicas son el failover
        const replicas = id === 'aurora' ? Math.max(0, num(p, 'replicas', 1)) : Math.max(0, num(p, 'instances', 2) - 1);
        r.readReplicas = replicas;
        r.azs = replicas >= 1 ? Math.min(3, replicas + 1) : 1;
        r.failoverS = replicas >= 1 ? 30 : 600;
        r.backupDays = Math.max(1, num(p, 'backupDays', 7));
        r.pitr = true;
        if (id === 'redshift') {
          r.failoverS = 900;
          r.azs = 1;
        }
      }
      if (r.rdsProxy && Number.isFinite(r.failoverS)) r.failoverS = Math.round(r.failoverS * 0.35);
      break;
    }
    case 'nosql':
      r.pitr = bool(p, 'pitr', true);
      r.backupDays = r.pitr ? 35 : 0;
      break;
    case 'cache': {
      const replicas = Math.max(0, num(p, 'replicas', id === 'memorydb' ? 1 : 1));
      const auto = bool(p, 'autoFailover', true);
      r.readReplicas = replicas;
      r.azs = replicas >= 1 && auto ? 2 : 1;
      r.failoverS = replicas >= 1 && auto ? 30 : 300;
      r.backupDays = id === 'memorydb' ? 7 : 0;
      break;
    }
    case 'object':
      r.versioning = bool(p, 'versioning', true);
      break;
    case 'files':
      r.backupDays = num(p, 'backupDays', 0);
      break;
    case 'search': {
      const n2 = Math.max(1, num(p, 'instances', 2));
      r.azs = n2 >= 2 ? 2 : 1;
      r.failoverS = n2 >= 2 ? 60 : 900;
      r.backupDays = 14; // snapshots automáticos
      break;
    }
    case 'broker': {
      const multi = id === 'mq' ? !!p.multiAz || p.deployment === 'ACTIVE_STANDBY_MULTI_AZ' : num(p, 'brokers', 3) >= 2;
      r.azs = multi ? 2 : 1;
      r.failoverS = multi ? 60 : Infinity;
      break;
    }
    case 'lb':
      r.azs = vAzs;
      break;
    case 'nat':
      r.azs = r.perAz ? vAzs : 1;
      break;
    case 'dns':
      r.routing = (['simple', 'failover', 'latency', 'weighted'].includes(String(p.routing)) ? String(p.routing) : 'simple') as NodeRes['routing'];
      r.healthChecks = !!p.healthChecks;
      r.ttl = num(p, 'ttl', 60);
      break;
    default:
      break;
  }
  return r;
}

/* ───────────────────────── región: DNS y recuperación por pieza */

export interface DnsCutover {
  /** Segundos desde la caída hasta que el DNS manda el tráfico a la región secundaria. */
  seconds: number;
  automatic: boolean;
  text: string;
  dnsId: string | null;
}

export function dnsCutover(nodes: AppNode[], security: Record<string, boolean> = {}): DnsCutover {
  const map = byId(nodes);
  const dns = nodes.filter(isService).find((n) => resKind(n) === 'dns');
  if (!dns) return { seconds: 3600, automatic: false, dnsId: null, text: 'No hay DNS administrado en el diagrama: el cambio se hace a mano en el registrador (~1 h con propagación).' };
  const r = nodeRes(dns, map, security);
  const ttl = r.ttl ?? 60;
  if (r.routing !== 'simple' && r.healthChecks) {
    const s = 90 + ttl;
    return { seconds: s, automatic: true, dnsId: dns.id, text: `Route 53 con política «${r.routing}» y health checks: detecta la caída en ~90 s (3 chequeos de 30 s) y deja de responder con la región caída; los clientes cambian al vencer el TTL (${ttl} s). Total ≈ ${fmtDur(s)}.` };
  }
  const why = r.routing === 'simple' ? 'enrutamiento simple' : 'sin health checks';
  const s = 900 + ttl;
  return { seconds: s, automatic: false, dnsId: dns.id, text: `Route 53 con ${why}: alguien tiene que notar la caída y cambiar el registro a mano (~15 min) y esperar el TTL (${ttl} s). Total ≈ ${fmtDur(s)}.` };
}

export interface RegionRecovery {
  /** Segundos desde la caída hasta que la pieza vuelve a servir en la región secundaria (Infinity = no vuelve). */
  rtoS: number;
  /** Datos que se pierden (s). 0 = nada; Infinity = no hay copia. */
  rpoS: number;
  /** Capacidad al volver (fracción del tamaño normal) y segundos hasta llegar al 100 %. */
  capacity0: number;
  rampS: number;
  text: string;
  status: 'ok' | 'warn' | 'bad' | 'na';
  fix?: ResFix;
}

export interface ResFix {
  label: string;
  nodeId?: string;
  props?: Record<string, PropValue>;
  dr?: Partial<DrConfig>;
  security?: string;
}

const RESTORE_S: Partial<Record<ResKind, number>> = { relational: 2700, nosql: 1800, object: 7200, files: 3600, search: 3600, broker: 1800 };

export function regionRecovery(n: ServiceNode, r: NodeRes, dr: DrConfig, security: Record<string, boolean> = {}): RegionRecovery {
  const k = r.kind;
  const region = dr.secondaryRegion || 'la región secundaria';
  const id = lid(n);
  if (k === 'actor') return { rtoS: 0, rpoS: 0, capacity0: 1, rampS: 0, text: 'Fuera de la nube.', status: 'na' };
  if (k === 'global' || k === 'dns') return { rtoS: 0, rpoS: 0, capacity0: 1, rampS: 0, text: 'Servicio global: no depende de una región.', status: 'ok' };
  if (dr.strategy === 'none')
    return { rtoS: Infinity, rpoS: holdsData(k) ? Infinity : 0, capacity0: 0, rampS: 0, status: 'bad', text: 'Solo existe en la región principal: queda caída hasta que el proveedor recupere la región.' };

  // Piezas con datos: necesitan una copia en la otra región
  if (holdsData(k) || id === 'memorydb') {
    if (r.crossRegion) {
      const how: Record<string, [number, number, string]> = {
        aurora: [60, 1, `Aurora Global Database: la región ${region} se promueve en ~1 min (failover administrado); retraso de replicación < 1 s.`],
        rds: [600, 60, `Réplica de lectura en ${region}: se promueve a primaria en ~5‑10 min; la replicación es asíncrona (segundos a minutos de retraso).`],
        documentdb: [60, 1, `DocumentDB Global Cluster: el clúster de ${region} se promueve en ~1 min.`],
        neptune: [60, 1, `Neptune Global Database: promoción en ~1 min.`],
        dynamodb: [0, 1, `Global Tables: la tabla ya está activa en ${region} (activo‑activo); replicación ~1 s.`],
        s3: [0, 900, `Replicación entre regiones (CRR) a un bucket en ${region}: los objetos están allí; con RTC el 99,99 % llega en 15 min.`],
        efs: [300, 900, `EFS Replication a ${region}: se usa la réplica (RPO ~15 min).`],
        opensearch: [600, 60, `Replicación entre clústeres hacia ${region}.`],
        memorydb: [60, 1, `MemoryDB Multi‑Region: la réplica de ${region} toma el control.`],
        msk: [300, 60, `MSK Replicator hacia ${region}.`],
        mq: [300, 60, `Amazon MQ con réplica entre regiones.`],
        redshift: [1800, 3600, `Snapshots entre regiones: se restaura el clúster en ${region}.`],
      };
      const [rto, rpo, text] = how[id] ?? [600, 60, `Réplica en ${region}.`];
      return { rtoS: rto, rpoS: rpo, capacity0: 1, rampS: 0, text, status: rto <= dr.rtoMin * 60 && rpo <= dr.rpoMin * 60 ? 'ok' : 'warn' };
    }
    if (security.offsiteBackup || dr.strategy === 'backup') {
      const restore = (RESTORE_S[k] ?? 3600) + (id === 'rds' ? Math.min(7200, Number(n.data.props.storage ?? 50) * 6) : 0);
      const tested = !!security.restoreTests;
      const rto = Math.round(restore * (tested ? 1 : 1.5));
      const fix: ResFix = { label: replicaLabel(id), nodeId: n.id, props: { crossRegion: true } };
      if (!security.offsiteBackup)
        return { rtoS: Infinity, rpoS: Infinity, capacity0: 0, rampS: 0, status: 'bad', text: `La estrategia es «backup y restauración», pero los backups no se copian a otra región: no hay de dónde restaurar en ${region}.`, fix: { label: 'Copiar los backups a otra región (AWS Backup)', security: 'offsiteBackup' } };
      return {
        rtoS: rto,
        rpoS: 86400,
        capacity0: 1,
        rampS: 0,
        status: dr.strategy === 'backup' ? 'warn' : 'bad',
        text: `Se restaura desde la copia de backup en ${region} (~${fmtDur(rto)}${tested ? '' : ', +50 % porque nunca se probó la restauración'}). Se pierde lo escrito desde la última copia (hasta 24 h).`,
        fix: dr.strategy === 'backup' ? undefined : fix,
      };
    }
    return {
      rtoS: Infinity,
      rpoS: Infinity,
      capacity0: 0,
      rampS: 0,
      status: 'bad',
      text: `Los datos solo están en la región principal: con «${DR_MAP[dr.strategy].label}» la región ${region} no tiene de dónde leerlos.`,
      fix: { label: replicaLabel(id), nodeId: n.id, props: { crossRegion: true } },
    };
  }

  // Cachés: se recrean vacías en la otra región
  if (k === 'cache') {
    const base = computeRecovery(dr, true);
    return { ...base, text: `${base.text} La caché arranca vacía (más carga sobre la BD al inicio).`, status: base.status };
  }
  if (k === 'identity') {
    const base = computeRecovery(dr, true);
    return { ...base, status: 'warn', text: `${base.text} Ojo: los grupos de usuarios de Cognito no se replican entre regiones; hay que exportar y migrar usuarios (o pedir restablecer contraseñas).` };
  }
  return computeRecovery(dr, k === 'serverless' || k === 'managed' || k === 'lb' || k === 'nat');
}

function computeRecovery(dr: DrConfig, managed: boolean): RegionRecovery {
  const region = dr.secondaryRegion || 'la región secundaria';
  switch (dr.strategy) {
    case 'backup':
      return { rtoS: managed ? 3600 : 7200, rpoS: 0, capacity0: 1, rampS: 0, status: 'warn', text: `Se despliega desde cero con IaC en ${region} (~${managed ? '1 h' : '2 h'}).` };
    case 'pilot':
      return { rtoS: managed ? 300 : 1200, rpoS: 0, capacity0: 1, rampS: 0, status: 'warn', text: managed ? `Configuración desplegada en ${region}; se activa en ~5 min.` : `En ${region} el ASG está en 0: se enciende y las instancias quedan listas en ~20 min.` };
    case 'warm':
      return managed
        ? { rtoS: 0, rpoS: 0, capacity0: 1, rampS: 0, status: 'ok', text: `Ya desplegado en ${region}.` }
        : { rtoS: 0, rpoS: 0, capacity0: 0.25, rampS: 300, status: 'ok', text: `Copia reducida (~25 %) corriendo en ${region}; escala a tamaño completo en ~5 min.` };
    case 'active':
      return { rtoS: 0, rpoS: 0, capacity0: 1, rampS: 0, status: 'ok', text: `Atiende tráfico en ${region} todo el tiempo.` };
    default:
      return { rtoS: Infinity, rpoS: 0, capacity0: 0, rampS: 0, status: 'bad', text: 'Sin región secundaria.' };
  }
}

const replicaLabel = (id: string) =>
  ({ aurora: 'Activar Aurora Global Database', rds: 'Crear réplica en otra región', dynamodb: 'Activar Global Tables', s3: 'Activar replicación entre regiones (CRR)', documentdb: 'Activar Global Cluster', efs: 'Activar EFS Replication', memorydb: 'Activar Multi‑Region' })[id] ?? 'Replicar a otra región';

/* ───────────────────────── corrupción y ransomware */

export interface DataRecovery {
  rtoS: number;
  rpoS: number;
  text: string;
  status: 'ok' | 'warn' | 'bad' | 'na';
  fix?: ResFix;
}

export function dataRecovery(n: ServiceNode, r: NodeRes, opts: { ransomware: boolean; security: Record<string, boolean> }): DataRecovery {
  const k = r.kind;
  const id = lid(n);
  const tested = !!opts.security.restoreTests;
  const slow = (s: number) => Math.round(s * (tested ? 1 : 1.5));
  const untested = tested ? '' : ' (+50 %: la restauración nunca se ha probado)';
  if (k === 'cache' && id !== 'memorydb') return { rtoS: 0, rpoS: 0, status: 'ok', text: 'Es una caché: se vacía y se vuelve a llenar desde la base de datos.' };
  if (!holdsData(k) && id !== 'memorydb') return { rtoS: 0, rpoS: 0, status: 'na', text: '—' };
  if (opts.ransomware) {
    if (!opts.security.offsiteBackup)
      return {
        rtoS: Infinity,
        rpoS: Infinity,
        status: 'bad',
        text: 'El atacante, con permisos en la cuenta, borra también los backups, snapshots y versiones. No hay copia fuera de su alcance.',
        fix: { label: 'Copias en otra cuenta con vault lock', security: 'offsiteBackup' },
      };
    const rto = slow((RESTORE_S[k] ?? 3600) + 1800);
    return { rtoS: rto, rpoS: 86400, status: 'warn', text: `Se restaura desde la bóveda inmutable (AWS Backup vault lock, otra cuenta): ~${fmtDur(rto)}${untested}. Se pierde lo escrito desde la última copia (hasta 24 h).` };
  }
  // Error humano / bug: las réplicas (Multi‑AZ, Global) copian el daño; solo sirven los backups
  if (k === 'relational' || id === 'memorydb') {
    if (r.backupDays <= 0)
      return { rtoS: Infinity, rpoS: Infinity, status: 'bad', text: 'Sin backups automáticos: los datos dañados no se pueden recuperar. Multi‑AZ y las réplicas copian el daño al instante.', fix: { label: 'Activar backups (7 días)', nodeId: n.id, props: { backupDays: 7 } } };
    const restore = slow(id === 'aurora' ? 900 : 1200 + Math.min(5400, Number(n.data.props.storage ?? 50) * 6));
    return { rtoS: restore, rpoS: id === 'rds' ? 300 : 5, status: 'ok', text: `Restauración a un punto en el tiempo (PITR, ${r.backupDays} días de retención) a una instancia nueva: ~${fmtDur(restore)}${untested}; se pierde lo de los últimos ${id === 'rds' ? '5 min' : 'segundos'}.` };
  }
  if (k === 'nosql') {
    if (!r.pitr) return { rtoS: Infinity, rpoS: Infinity, status: 'bad', text: 'Sin point‑in‑time recovery: no hay a qué volver.', fix: { label: 'Activar PITR', nodeId: n.id, props: { pitr: true } } };
    const restore = slow(1800);
    return { rtoS: restore, rpoS: 5, status: 'ok', text: `PITR: se restaura a una tabla nueva al segundo previo al daño (~${fmtDur(restore)}${untested}).` };
  }
  if (k === 'object') {
    if (!r.versioning) return { rtoS: Infinity, rpoS: Infinity, status: 'bad', text: 'Sin versionado: un objeto sobrescrito o borrado se pierde.', fix: { label: 'Activar versionado', nodeId: n.id, props: { versioning: true } } };
    const restore = slow(1800);
    return { rtoS: restore, rpoS: 0, status: 'ok', text: `Versionado: se restauran las versiones previas (~${fmtDur(restore)}${untested}).` };
  }
  if (r.backupDays > 0 || opts.security.offsiteBackup) {
    const restore = slow(RESTORE_S[k] ?? 3600);
    return { rtoS: restore, rpoS: 86400, status: 'warn', text: `Se restaura desde el último backup (~${fmtDur(restore)}${untested}); se pierde hasta 24 h.` };
  }
  return { rtoS: Infinity, rpoS: Infinity, status: 'bad', text: 'Sin backups configurados.', fix: { label: 'Activar backups', nodeId: n.id, props: { backupDays: 7 } } };
}

/* ───────────────────────── plan de failover */

export interface PlanCell {
  status: 'ok' | 'warn' | 'bad' | 'na';
  text: string;
  /** Recurso al que se pasa el tráfico. */
  target?: string;
  rtoS: number;
  rpoS: number;
  fix?: ResFix;
}

export interface PlanRow {
  nodeId: string;
  label: string;
  service: string;
  kind: ResKind;
  critical: boolean;
  instance: PlanCell;
  az: PlanCell;
  region: PlanCell;
  data: PlanCell | null;
}

export interface LevelTotal {
  rtoS: number;
  rpoS: number;
  worst: string | null;
}

export interface ResiliencePlan {
  dr: DrConfig;
  dns: DnsCutover;
  rows: PlanRow[];
  totals: { instance: LevelTotal; az: LevelTotal; region: LevelTotal; data: LevelTotal; ransomware: LevelTotal };
  issues: { severity: 'error' | 'warn'; text: string; nodeIds: string[]; fix?: ResFix }[];
}

/** Piezas por las que pasan las peticiones de los usuarios (las que importan para el RTO). */
export function criticalPath(nodes: AppNode[], edges: AppEdge[]): Set<string> {
  const map = byId(nodes);
  const skip = new Set(['observability', 'devops', 'registry', 'analytics', 'cert', 'kms', 'waf']);
  const out = new Map<string, string[]>();
  for (const e of edges) {
    if (!out.has(e.source)) out.set(e.source, []);
    out.get(e.source)!.push(e.target);
  }
  const start = nodes.filter(isService).filter((n) => ['user', 'admin'].includes(lid(n)) || getService(n.data.serviceId).role === 'actor');
  const seen = new Set<string>();
  const stack = start.map((n) => n.id);
  while (stack.length) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    for (const t of out.get(id) ?? []) {
      const tn = map.get(t);
      if (!isService(tn) || skip.has(getService(tn.data.serviceId).role)) continue;
      stack.push(t);
    }
  }
  for (const s of start) seen.delete(s.id);
  return seen;
}

const levelTotal = (rows: PlanRow[], key: 'instance' | 'az' | 'region' | 'data', only?: Set<string>): LevelTotal => {
  let rto = 0;
  let rpo = 0;
  let worst: string | null = null;
  for (const r of rows) {
    const c = r[key];
    if (!c || c.status === 'na') continue;
    if (only && !only.has(r.nodeId) && key !== 'data') continue;
    if (c.rtoS > rto) {
      rto = c.rtoS;
      worst = r.label;
    }
    rpo = Math.max(rpo, c.rpoS);
  }
  return { rtoS: rto, rpoS: rpo, worst };
};

export function buildPlan(nodes: AppNode[], edges: AppEdge[], opts: { dr: DrConfig; security: Record<string, boolean> }): ResiliencePlan {
  const map = byId(nodes);
  const { dr, security } = opts;
  const cloud: Cloud = primaryCloud(nodes);
  const T = (s: string) => (cloud === 'azure' ? cloudText(s, cloud) : s);
  const crit = criticalPath(nodes, edges);
  const dns = dnsCutover(nodes, security);
  const behindLb = (n: ServiceNode) => edges.some((e) => e.target === n.id && isService(map.get(e.source)) && resKind(map.get(e.source) as ServiceNode) === 'lb');
  const rows: PlanRow[] = [];
  const issues: ResiliencePlan['issues'] = [];

  for (const n of nodes.filter(isService)) {
    const r = nodeRes(n, map, security);
    if (r.kind === 'actor') continue;
    const def = getService(n.data.serviceId);
    if (['observability', 'devops', 'registry', 'cert', 'kms'].includes(def.role) && r.kind !== 'global') continue;
    const id = lid(n);
    const lb = behindLb(n);
    const inst: PlanCell = { status: 'ok', text: '', rtoS: 0, rpoS: 0 };
    const az: PlanCell = { status: 'ok', text: '', rtoS: 0, rpoS: 0 };
    const vAzs = vpcAzs(n, map);

    switch (r.kind) {
      case 'fleet': {
        const desired = desiredOf(n);
        const p = n.data.props;
        const asg = id === 'ec2' ? p.autoscaling !== false && p.scalePolicy !== 'manual' : true;
        inst.target = desired >= 2 ? 'las demás instancias' : undefined;
        if (desired >= 2) {
          inst.text = `${lb ? 'El balanceador' : 'El servicio'} deja de enviarle tráfico en ~${r.detectS} s (health check cada ${num(p, 'hcInterval', 10)} s × ${num(p, 'hcThreshold', 3)} fallos) y lo reparte entre las otras ${desired - 1}. ${asg ? 'Auto Scaling la reemplaza (~4 min).' : 'Nadie la reemplaza: queda con menos capacidad.'}`;
          inst.rtoS = r.detectS;
          inst.status = asg ? 'ok' : 'warn';
          if (!lb && id !== 'ecs') inst.status = 'warn';
        } else {
          inst.text = asg ? `Es la única: el servicio cae hasta que Auto Scaling cree otra (~4 min).` : 'Es la única y no hay Auto Scaling: queda caída hasta que alguien la reemplace.';
          inst.rtoS = asg ? 240 : Infinity;
          inst.status = 'bad';
          inst.fix = { label: 'Correr 2 instancias en 2 AZ', nodeId: n.id, props: { [id === 'ec2' ? 'count' : id === 'ecs' ? 'desired' : id === 'eks' ? 'nodes' : 'instances']: 2, azSpread: 2 } };
        }
        if (r.azs >= 2) {
          const lose = Math.ceil(desired / r.azs);
          az.text = `Repartidas en ${r.azs} AZ: se pierden ~${lose} de ${desired}; ${lb ? 'el balanceador' : 'el servicio'} sigue con las de las otras AZ y Auto Scaling repone la capacidad en las AZ sanas.`;
          az.target = `instancias en las otras ${r.azs - 1} AZ`;
          az.rtoS = r.detectS;
          az.status = desired - lose >= 1 ? 'ok' : 'warn';
        } else {
          az.text = vAzs < 2 ? 'La VPC usa una sola AZ: si esa AZ cae, no hay a dónde ir.' : 'Todas las instancias están en una sola AZ: si cae, se pierde todo hasta que Auto Scaling cree instancias en otra AZ (~4 min).';
          az.rtoS = vAzs < 2 ? Infinity : 240;
          az.status = 'bad';
          az.fix = vAzs < 2 ? undefined : { label: 'Repartir en 2 AZ', nodeId: n.id, props: { azSpread: 2, ...(desired < 2 ? { [id === 'ec2' ? 'count' : id === 'ecs' ? 'desired' : id === 'eks' ? 'nodes' : 'instances']: 2 } : {}) } };
        }
        break;
      }
      case 'single-vm':
        inst.text = 'Una sola máquina sin reemplazo automático.';
        inst.rtoS = Infinity;
        inst.status = 'bad';
        az.text = 'Vive en una AZ: si cae, cae el servicio.';
        az.rtoS = Infinity;
        az.status = 'bad';
        break;
      case 'serverless':
        inst.text = 'Lambda reintenta en otro entorno de ejecución; no hay instancias que administrar.';
        az.text = 'Corre en varias AZ de forma automática.';
        break;
      case 'relational': {
        const replicaNote = r.readReplicas > 0 && id === 'rds' ? ` Las ${r.readReplicas} réplica(s) de lectura no hacen failover automático en RDS.` : '';
        if (id === 'rds') {
          if (r.deployment === 'single') {
            inst.text = `Single‑AZ: si falla la instancia, RDS la recupera en el mismo lugar (~10‑30 min); si se pierde el volumen, hay que restaurar desde backup.${replicaNote}`;
            inst.rtoS = 1200;
            inst.status = 'bad';
            inst.fix = { label: 'Pasar a Multi‑AZ', nodeId: n.id, props: { deployment: 'multi-az', multiAZ: true } };
            az.text = 'Single‑AZ: si cae su AZ, la base de datos cae hasta que vuelva la AZ o se restaure en otra.';
            az.rtoS = Infinity;
            az.status = 'bad';
            az.fix = inst.fix;
          } else {
            const cluster = r.deployment === 'multi-az-cluster';
            inst.target = cluster ? 'uno de los 2 standbys legibles' : 'el standby síncrono en otra AZ';
            inst.text = `${cluster ? 'Multi‑AZ cluster: uno de los 2 standbys (que también sirven lecturas)' : 'Multi‑AZ: el standby síncrono'} se promueve y el endpoint DNS apunta a él en ~${r.failoverS} s, sin pérdida de datos.${r.rdsProxy ? ' RDS Proxy mantiene las conexiones de la app durante el cambio.' : ' La app debe reconectar (sin RDS Proxy ve errores mientras tanto).'}${replicaNote}`;
            inst.rtoS = r.failoverS;
            az.text = inst.text;
            az.target = inst.target;
            az.rtoS = r.failoverS;
            if (!r.rdsProxy) inst.fix = az.fix = { label: 'Agregar RDS Proxy', nodeId: n.id, props: { rdsProxy: true } };
          }
        } else {
          const name = id === 'aurora' ? 'Aurora' : def.short;
          if (r.readReplicas >= 1) {
            inst.target = `una réplica de ${name} en otra AZ`;
            inst.text = `${name} promueve una réplica a escritora en ~${r.failoverS} s; el almacenamiento ya está en 3 AZ, sin pérdida de datos.`;
            inst.rtoS = r.failoverS;
            az.text = inst.text;
            az.target = inst.target;
            az.rtoS = r.failoverS;
          } else {
            inst.text = `Sin réplicas: ${name} recrea la instancia escritora (~10 min). Los datos están a salvo (almacenamiento en 3 AZ).`;
            inst.rtoS = r.failoverS;
            inst.status = 'warn';
            inst.fix = { label: 'Agregar 1 réplica', nodeId: n.id, props: id === 'aurora' ? { replicas: 1 } : { instances: 2 } };
            az.text = inst.text;
            az.rtoS = r.failoverS;
            az.status = 'warn';
            az.fix = inst.fix;
          }
        }
        break;
      }
      case 'nosql':
        inst.text = 'Servicio administrado: replica cada escritura en 3 AZ. No hay nada que hacer.';
        az.text = 'Sigue funcionando con las otras AZ.';
        break;
      case 'cache':
        if (r.readReplicas >= 1 && r.azs >= 2) {
          inst.target = 'la réplica en otra AZ';
          inst.text = `La réplica se promueve a primaria en ~${r.failoverS} s; la caché conserva los datos.`;
          inst.rtoS = r.failoverS;
          az.text = inst.text;
          az.target = inst.target;
          az.rtoS = r.failoverS;
        } else {
          inst.text = r.readReplicas >= 1 ? 'Tiene réplica pero sin failover automático: queda caída hasta promoverla a mano.' : 'Sin réplica: el nodo se reemplaza (~5 min) y la caché queda vacía; toda la carga cae sobre la base de datos.';
          inst.rtoS = 300;
          inst.status = 'warn';
          inst.fix = { label: r.readReplicas >= 1 ? 'Activar failover automático' : 'Agregar 1 réplica con failover', nodeId: n.id, props: { replicas: Math.max(1, r.readReplicas), autoFailover: true } };
          az.text = inst.text;
          az.rtoS = 300;
          az.status = 'warn';
          az.fix = inst.fix;
        }
        break;
      case 'object':
        inst.text = 'S3 guarda cada objeto en 3 AZ (11 nueves de durabilidad).';
        az.text = 'Sin impacto.';
        break;
      case 'files':
        inst.text = 'Sistema de archivos regional en varias AZ.';
        az.text = 'Los puntos de montaje de las otras AZ siguen funcionando.';
        break;
      case 'search':
        inst.text = r.azs >= 2 ? `Los shards réplica toman el control (~${r.failoverS} s).` : 'Un solo nodo: queda caído hasta reemplazarlo.';
        inst.rtoS = r.failoverS;
        inst.status = r.azs >= 2 ? 'ok' : 'bad';
        az.text = r.azs >= 2 ? 'Con zone awareness sigue en la otra AZ.' : 'Un solo nodo en una AZ.';
        az.rtoS = r.failoverS;
        az.status = inst.status;
        break;
      case 'broker':
        inst.text = r.azs >= 2 ? `El broker en standby toma el control (~${r.failoverS} s).` : 'Un solo broker: si cae, se detiene la mensajería.';
        inst.rtoS = r.failoverS;
        inst.status = r.azs >= 2 ? 'ok' : 'bad';
        az.text = inst.text;
        az.rtoS = r.failoverS;
        az.status = inst.status;
        break;
      case 'lb':
        inst.text = 'Administrado: AWS reemplaza los nodos del balanceador.';
        az.text = vAzs >= 2 ? `Tiene nodos en ${vAzs} AZ: el DNS del balanceador deja de anunciar la AZ caída.` : 'La VPC tiene una sola AZ: el balanceador necesita al menos 2 subnets en AZ distintas.';
        az.status = vAzs >= 2 ? 'ok' : 'bad';
        az.rtoS = vAzs >= 2 ? 60 : Infinity;
        break;
      case 'nat':
        inst.text = 'Administrado y redundante dentro de su AZ.';
        if (r.perAz) az.text = `Un NAT Gateway por AZ: cada subnet privada sale por el de su propia AZ.`;
        else {
          az.text = 'Es zonal: si cae su AZ, las subnets privadas de las otras AZ que salen por él pierden Internet (llamadas a APIs externas, parches).';
          az.status = 'warn';
          az.rtoS = 0; // las peticiones de los usuarios siguen; se pierde la salida a Internet de una parte
          az.fix = { label: 'Un NAT Gateway por AZ', nodeId: n.id, props: { perAz: true } };
        }
        break;
      case 'dns':
        inst.text = 'Route 53 tiene SLA de 100 %.';
        az.text = 'Global: sin impacto.';
        break;
      case 'global':
        inst.text = 'Servicio global en el borde.';
        az.text = 'Sin impacto.';
        break;
      case 'identity':
      case 'managed':
        inst.text = 'Servicio regional administrado, redundante en varias AZ.';
        az.text = 'Sin impacto.';
        break;
    }
    const reg = regionRecovery(n, r, dr, security);
    const dataRec = holdsData(r.kind) || id === 'memorydb' ? dataRecovery(n, r, { ransomware: false, security }) : null;
    rows.push({
      nodeId: n.id,
      label: n.data.label,
      service: def.short,
      kind: r.kind,
      critical: crit.has(n.id),
      instance: { ...inst, text: T(inst.text) },
      az: { ...az, text: T(az.text) },
      region: { status: reg.status, text: T(reg.text), rtoS: reg.rtoS, rpoS: reg.rpoS, fix: reg.fix },
      data: dataRec ? { status: dataRec.status, text: T(dataRec.text), rtoS: dataRec.rtoS, rpoS: dataRec.rpoS, fix: dataRec.fix } : null,
    });
  }

  // Totales: el servicio vuelve cuando vuelve la pieza crítica más lenta
  const totals = {
    instance: levelTotal(rows, 'instance', crit),
    az: levelTotal(rows, 'az', crit),
    region: levelTotal(rows, 'region', crit),
    data: levelTotal(rows, 'data'),
    ransomware: { rtoS: 0, rpoS: 0, worst: null as string | null },
  };
  // El DNS se suma a la región (salvo sin DR, que ya es infinito)
  const regionalEntry = rows.some((r) => r.critical && !['global', 'dns'].includes(r.kind));
  if (dr.strategy !== 'none' && regionalEntry && totals.region.rtoS < Infinity && dns.seconds > totals.region.rtoS) {
    totals.region = { ...totals.region, rtoS: dns.seconds, worst: 'cambio de DNS' };
  }
  for (const n of nodes.filter(isService)) {
    const r = nodeRes(n, map, security);
    if (!holdsData(r.kind) && lid(n) !== 'memorydb') continue;
    const d = dataRecovery(n, r, { ransomware: true, security });
    if (d.rtoS > totals.ransomware.rtoS) totals.ransomware = { rtoS: d.rtoS, rpoS: Math.max(totals.ransomware.rpoS, d.rpoS), worst: n.data.label };
    else totals.ransomware.rpoS = Math.max(totals.ransomware.rpoS, d.rpoS);
  }

  // Problemas que ve el arquitecto
  for (const r of rows) {
    for (const [lvl, cell] of [['instancia', r.instance], ['AZ', r.az]] as const) {
      if (cell.status === 'bad' && r.critical) issues.push({ severity: 'error', text: `${r.label}: punto único de falla ante la caída de una ${lvl}.`, nodeIds: [r.nodeId], fix: cell.fix });
    }
  }
  if (dr.strategy === 'active' && !dns.automatic) issues.push({ severity: 'error', text: 'Activo‑activo necesita Route 53 con política de latencia, ponderada o failover y health checks: hoy el cambio de región es manual.', nodeIds: dns.dnsId ? [dns.dnsId] : [], fix: dns.dnsId ? { label: 'Route 53 con failover y health checks', nodeId: dns.dnsId, props: { routing: dr.strategy === 'active' ? 'latency' : 'failover', healthChecks: true } } : undefined });
  else if (dr.strategy !== 'none' && dr.strategy !== 'backup' && !dns.automatic) issues.push({ severity: 'warn', text: `El cambio a ${dr.secondaryRegion} depende de un cambio manual de DNS (~${fmtDur(dns.seconds)}).`, nodeIds: dns.dnsId ? [dns.dnsId] : [], fix: dns.dnsId ? { label: 'Route 53 con failover y health checks', nodeId: dns.dnsId, props: { routing: 'failover', healthChecks: true } } : undefined });
  for (const r of rows) if (r.region.status === 'bad' && r.critical && dr.strategy !== 'none' && holdsData(r.kind)) issues.push({ severity: 'error', text: `${r.label}: ${r.region.text}`, nodeIds: [r.nodeId], fix: r.region.fix });
  for (const r of rows) if (r.data?.status === 'bad') issues.push({ severity: 'error', text: `${r.label}: ${r.data.text}`, nodeIds: [r.nodeId], fix: r.data.fix });
  if (totals.region.rtoS > dr.rtoMin * 60 && dr.strategy !== 'none') issues.push({ severity: 'warn', text: `El RTO estimado ante la caída de la región (${fmtDur(totals.region.rtoS)}) supera el objetivo (${dr.rtoMin} min).`, nodeIds: [] });
  if (totals.region.rpoS > dr.rpoMin * 60 && dr.strategy !== 'none' && Number.isFinite(totals.region.rpoS)) issues.push({ severity: 'warn', text: `El RPO estimado ante la caída de la región (${fmtDur(totals.region.rpoS)}) supera el objetivo (${dr.rpoMin} min).`, nodeIds: [] });

  return { dr, dns, rows, totals, issues };
}

/* ───────────────────────── formato */

export function fmtDur(s: number): string {
  if (!Number.isFinite(s)) return '∞';
  if (s <= 0) return '0 s';
  if (s < 90) return `${Math.round(s)} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(s < 36000 ? 1 : 0).replace('.0', '')} h`;
  return `${Math.round(s / 86400)} días`;
}

/** Resumen corto de la redundancia de una pieza (para badges y para el asistente IA). */
export function resBadge(n: ServiceNode, map: Map<string, AppNode>, security: Record<string, boolean> = {}): string | null {
  const r = nodeRes(n, map, security);
  const parts: string[] = [];
  if (r.kind === 'fleet') parts.push(`${r.azs} AZ`);
  if (r.kind === 'relational') parts.push(lid(n) === 'rds' ? (r.deployment === 'single' ? 'Single‑AZ' : r.deployment === 'multi-az-cluster' ? 'Multi‑AZ cluster' : 'Multi‑AZ') : `${r.readReplicas} réplica(s)`);
  if (r.kind === 'cache') parts.push(r.readReplicas >= 1 ? `${r.readReplicas} réplica(s)` : 'sin réplica');
  if (r.crossRegion) parts.push('🌐 otra región');
  if (r.kind === 'dns' && r.routing !== 'simple') parts.push(`${r.routing}${r.healthChecks ? ' + HC' : ''}`);
  return parts.length ? parts.join(' · ') : null;
}

