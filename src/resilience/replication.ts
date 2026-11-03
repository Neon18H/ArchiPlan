/**
 * Réplicas dibujadas como piezas del diagrama y su failover.
 *
 * Una pieza puede declararse réplica de otra (props `replicaOf`, `replicaMode`, `failoverMode`…).
 * Cada tipo de réplica protege contra unas fallas y no contra otras:
 *  - una réplica en vivo (standby, lectura, otra región) copia al instante un borrado o un
 *    cifrado: sirve contra caídas de hardware, de AZ o de región, no contra corrupción ni ransomware;
 *  - una réplica con retraso sirve contra la corrupción si se detecta antes de que se aplique;
 *  - una copia aislada en otra cuenta es lo único que sobrevive a un ransomware.
 */
import { getService, lid } from '../catalog/catalog';
import { byId, isService } from '../lib/graph';
import type { AppEdge, AppNode, PropValue, ServiceNode } from '../types';

export type ReplicaMode = 'standby' | 'read' | 'cross-region' | 'delayed' | 'isolated';
export type FailoverMode = 'auto' | 'manual';
export type FailureKind = 'instance' | 'az' | 'outage' | 'region' | 'corruption' | 'ransomware';

export const REPLICA_MODES: { id: ReplicaMode; label: string; short: string; help: string }[] = [
  { id: 'standby', label: 'Standby síncrono (otra AZ)', short: 'standby', help: 'Copia síncrona en otra zona de disponibilidad. No se pierde nada al fallar.' },
  { id: 'read', label: 'Réplica de lectura (misma región)', short: 'lectura', help: 'Copia asíncrona que además atiende lecturas. Se promueve si cae la primaria.' },
  { id: 'cross-region', label: 'Réplica en otra región', short: 'otra región', help: 'Copia asíncrona en la región secundaria. Sobrevive a la caída de la región.' },
  { id: 'delayed', label: 'Réplica con retraso', short: 'con retraso', help: 'Aplica los cambios con un retraso fijo (p. ej. 1 h): si se detecta un borrado antes, se detiene y se usa la copia sana.' },
  { id: 'isolated', label: 'Copia aislada en otra cuenta', short: 'aislada', help: 'Copia periódica e inmutable en una cuenta de recuperación (vault lock / air‑gapped). Sobrevive a un ransomware.' },
];
export const MODE_MAP = Object.fromEntries(REPLICA_MODES.map((m) => [m.id, m])) as Record<ReplicaMode, (typeof REPLICA_MODES)[number]>;

export const FAILURE_LABEL: Record<FailureKind, string> = {
  instance: 'Falla de la instancia',
  az: 'Caída de la AZ',
  outage: 'La pieza deja de responder',
  region: 'Caída de la región',
  corruption: 'Corrupción / borrado',
  ransomware: 'Ransomware',
};

export interface ReplicaLink {
  primaryId: string;
  replicaId: string;
  mode: ReplicaMode;
  failover: FailoverMode;
  /** Réplica con retraso: minutos. */
  delayMin: number;
  /** Copia aislada: cada cuántos minutos se copia. */
  copyEveryMin: number;
}

export interface Coverage {
  covers: boolean;
  /** Segundos desde la falla hasta que la réplica atiende. */
  rtoS: number;
  /** Datos que se pierden (s de escrituras). */
  rpoS: number;
  why: string;
}

const num = (p: Record<string, PropValue>, k: string, d: number) => (Number.isFinite(Number(p[k])) && p[k] !== undefined && p[k] !== '' ? Number(p[k]) : d);

/** Piezas que pueden ser réplica de otra (mismo tipo de datos). */
export function replicaFamily(n: ServiceNode): string | null {
  const id = lid(n);
  if (['rds', 'aurora'].includes(id)) return 'sql';
  if (['documentdb'].includes(id)) return 'doc';
  if (['dynamodb'].includes(id)) return 'kv';
  if (['elasticache', 'memorydb'].includes(id)) return 'cache';
  if (['s3'].includes(id)) return 'object';
  if (['efs', 'fsx'].includes(id)) return 'files';
  if (['opensearch'].includes(id)) return 'search';
  if (['neptune'].includes(id)) return 'graph';
  if (['redshift'].includes(id)) return 'dw';
  if (['msk', 'mq'].includes(id)) return 'broker';
  return null;
}

export function linkOf(n: ServiceNode): ReplicaLink | null {
  const p = n.data.props;
  if (!p.replicaOf) return null;
  const mode = (REPLICA_MODES.some((m) => m.id === p.replicaMode) ? p.replicaMode : 'read') as ReplicaMode;
  return {
    primaryId: String(p.replicaOf),
    replicaId: n.id,
    mode,
    failover: (p.failoverMode === 'manual' || p.failoverMode === 'auto' ? p.failoverMode : mode === 'standby' ? 'auto' : 'manual') as FailoverMode,
    delayMin: Math.max(1, num(p, 'delayMin', 60)),
    copyEveryMin: Math.max(5, num(p, 'copyEveryMin', 60)),
  };
}

export function replicationLinks(nodes: AppNode[]): ReplicaLink[] {
  const ids = new Set(nodes.map((n) => n.id));
  return nodes
    .filter(isService)
    .map(linkOf)
    .filter((l): l is ReplicaLink => !!l && ids.has(l.primaryId) && l.primaryId !== l.replicaId);
}

/** ¿Cubre la réplica esta falla de la primaria? (detección + promoción, pérdida de datos y por qué). */
export function coverage(l: ReplicaLink, failure: FailureKind, opts: { detectS?: number } = {}): Coverage {
  const auto = l.failover === 'auto';
  // Detección y promoción: automático = health check + promoción; manual = alguien lo nota y promueve
  const promote = { standby: 60, read: 300, 'cross-region': 300, delayed: 300, isolated: 1800 }[l.mode];
  const detect = auto ? 30 : 600;
  const rto = detect + (auto ? Math.min(promote, l.mode === 'standby' ? 60 : 90) : promote);
  const rpo = { standby: 0, read: 5, 'cross-region': 60, delayed: l.delayMin * 60, isolated: l.copyEveryMin * 60 }[l.mode];
  const live = l.mode === 'standby' || l.mode === 'read' || l.mode === 'cross-region';
  switch (failure) {
    case 'instance':
    case 'az':
    case 'outage':
      if (l.mode === 'delayed') return { covers: true, rtoS: 600 + 300, rpoS: rpo, why: `Se promueve aplicando antes el retraso pendiente; si no se puede, se pierden los últimos ${l.delayMin} min.` };
      return { covers: true, rtoS: rto, rpoS: rpo, why: auto ? 'Failover automático: health check + promoción.' : 'Failover manual: alguien detecta la caída y promueve la réplica.' };
    case 'region':
      if (l.mode === 'cross-region' || l.mode === 'isolated') return { covers: true, rtoS: rto, rpoS: rpo, why: l.mode === 'isolated' ? 'La copia está en otra cuenta y región: se restaura allí.' : 'Está en la región secundaria: se promueve allí.' };
      return { covers: false, rtoS: Infinity, rpoS: Infinity, why: 'Está en la misma región: cae junto con la primaria.' };
    case 'corruption': {
      if (live) return { covers: false, rtoS: Infinity, rpoS: Infinity, why: 'Es una réplica en vivo: el borrado o el UPDATE dañino se replica en segundos. Multi‑AZ y las réplicas no protegen de esto.' };
      const det = opts.detectS ?? 600;
      if (l.mode === 'delayed') {
        if (det >= l.delayMin * 60) return { covers: false, rtoS: Infinity, rpoS: Infinity, why: `El daño se detectó a los ${Math.round(det / 60)} min y la réplica va ${l.delayMin} min atrás: ya lo aplicó.` };
        return { covers: true, rtoS: det + 300, rpoS: det, why: `Se detiene la replicación antes de que llegue el daño (va ${l.delayMin} min atrás) y se promueve la copia sana.` };
      }
      return { covers: true, rtoS: det + 1800, rpoS: rpo, why: `Se restaura la última copia aislada (cada ${l.copyEveryMin} min).` };
    }
    case 'ransomware':
      if (l.mode === 'isolated') return { covers: true, rtoS: 1800, rpoS: rpo, why: 'La copia está en otra cuenta con bloqueo inmutable: el atacante no la alcanza.' };
      return { covers: false, rtoS: Infinity, rpoS: Infinity, why: 'Está en la misma cuenta: con las mismas credenciales el atacante también la cifra o la borra.' };
  }
}

/** Pares de piezas del mismo tipo unidos por una flecha y sin vínculo declarado: probablemente una réplica. */
export function suggestLinks(nodes: AppNode[], edges: AppEdge[]): { primaryId: string; replicaId: string }[] {
  const map = byId(nodes);
  const declared = new Set(replicationLinks(nodes).flatMap((l) => [l.primaryId, l.replicaId]));
  const out: { primaryId: string; replicaId: string }[] = [];
  const seen = new Set<string>();
  for (const e of edges) {
    const a = map.get(e.source);
    const b = map.get(e.target);
    if (!isService(a) || !isService(b)) continue;
    const fa = replicaFamily(a);
    if (!fa || fa !== replicaFamily(b)) continue;
    if (declared.has(a.id) || declared.has(b.id)) continue;
    const key = [a.id, b.id].sort().join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    // La primaria es la que recibe más flechas de la aplicación; si empatan, la que se creó primero
    const inA = edges.filter((x) => x.target === a.id && getService((map.get(x.source) as ServiceNode)?.data.serviceId ?? '').role === 'compute').length;
    const inB = edges.filter((x) => x.target === b.id && getService((map.get(x.source) as ServiceNode)?.data.serviceId ?? '').role === 'compute').length;
    const first = nodes.findIndex((n) => n.id === a.id) <= nodes.findIndex((n) => n.id === b.id) ? a : b;
    const primary = inA === inB ? first : inA > inB ? a : b;
    out.push({ primaryId: primary.id, replicaId: primary === a ? b.id : a.id });
  }
  return out;
}

export function linkSummary(l: ReplicaLink): string {
  const m = MODE_MAP[l.mode];
  return `${m.short}${l.mode === 'delayed' ? ` ${l.delayMin} min` : l.mode === 'isolated' ? ` cada ${l.copyEveryMin} min` : ''} · failover ${l.failover === 'auto' ? 'automático' : 'manual'}`;
}
