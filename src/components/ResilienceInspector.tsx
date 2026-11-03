import { getService, lid } from '../catalog/catalog';
import { byId } from '../lib/graph';
import { buildPlan, drOf, fmtDur, nodeRes, vpcAzs, type PlanCell } from '../resilience/model';
import { useStore } from '../store';
import type { PropValue, ServiceNode } from '../types';
import { Switch } from './NetInspector';
import { Num } from './ScalingInspector';
import { applyResFix } from './ResilienceModal';

export const openResilience = () => window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'resilience' }));

function Row({ label, help, on, onChange }: { label: string; help?: string; on: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="res-row">
      <div>
        <b>{label}</b>
        {help && <span>{help}</span>}
      </div>
      <Switch on={on} onChange={onChange} label={label} />
    </div>
  );
}

const ICON = { ok: '✓', warn: '!', bad: '✗', na: '·' } as const;

export function PlanCellView({ title, cell }: { title: string; cell: PlanCell }) {
  return (
    <div className={`res-cell ${cell.status}`}>
      <div className="res-cell-head">
        <span className={`res-ic ${cell.status}`}>{ICON[cell.status]}</span>
        <b>{title}</b>
        {cell.status !== 'na' && <em>{Number.isFinite(cell.rtoS) ? (cell.rtoS > 0 ? `vuelve en ${fmtDur(cell.rtoS)}` : 'sin corte') : 'no vuelve'}</em>}
      </div>
      {cell.target && (
        <div className="res-target">
          → falla hacia <b>{cell.target}</b>
        </div>
      )}
      <p>{cell.text}</p>
      {cell.fix && (
        <button className="btn small fix" onClick={() => applyResFix(cell.fix!)}>
          ⚡ {cell.fix.label}
        </button>
      )}
    </div>
  );
}

/** Sección «Resiliencia» del inspector: redundancia, failover y backups de la pieza. */
export function ResilienceSection({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const security = useStore((s) => s.security);
  const meta = useStore((s) => s.meta);
  const { updateNode } = useStore.getState();
  const map = byId(nodes);
  const r = nodeRes(node, map, security);
  if (r.kind === 'actor') return null;
  const set = (props: Record<string, PropValue>) => updateNode(node.id, { props });
  const id = lid(node);
  const def = getService(node.data.serviceId);
  const p = node.data.props;
  const row = buildPlan(nodes, edges, { dr: drOf(meta), security }).rows.find((x) => x.nodeId === node.id);
  const isCaller = ['fleet', 'serverless', 'single-vm'].includes(r.kind);
  const vAzs = vpcAzs(node, map);
  const replicaName: Record<string, string> = { aurora: 'Aurora Global Database', rds: 'Réplica en otra región', dynamodb: 'Global Tables', s3: 'Replicación entre regiones (CRR)', documentdb: 'Global Cluster', elasticache: 'Global Datastore', memorydb: 'Multi‑Region', efs: 'EFS Replication', neptune: 'Global Database' };

  return (
    <div className="insp-section res-section">
      <div className="row between">
        <div className="insp-section-title">Resiliencia y failover</div>
        <button className="linkish small" onClick={openResilience}>
          Plan completo
        </button>
      </div>

      {r.kind === 'fleet' && (
        <>
          <div className="res-label">Zonas de disponibilidad</div>
          <div className="seg-choice" role="radiogroup" aria-label="Repartir en zonas de disponibilidad">
            {[1, 2, 3].map((n) => (
              <button key={n} role="radio" aria-checked={r.azs === n} className={r.azs === n ? 'on' : ''} disabled={n > vAzs} title={n > vAzs ? `La VPC solo tiene ${vAzs} AZ` : undefined} onClick={() => set({ azSpread: n })}>
                {n} AZ
              </button>
            ))}
          </div>
          <div className="scale-grid">
            <Num label="Health check cada" value={Number(p.hcInterval ?? 10)} min={5} max={300} step={5} suffix="s" onChange={(v) => set({ hcInterval: v })} />
            <Num label="Fallos para sacarla" value={Number(p.hcThreshold ?? 3)} min={2} max={10} onChange={(v) => set({ hcThreshold: v })} />
          </div>
          <div className="scale-note">Una instancia caída deja de recibir tráfico a los ~{r.detectS} s.</div>
        </>
      )}

      {r.kind === 'relational' && id === 'rds' && (
        <>
          <div className="res-label">Despliegue</div>
          <div className="seg-choice wrap" role="radiogroup" aria-label="Despliegue de RDS">
            {([['single', 'Single‑AZ'], ['multi-az', 'Multi‑AZ'], ['multi-az-cluster', 'Multi‑AZ cluster']] as const).map(([k, l]) => (
              <button key={k} role="radio" aria-checked={r.deployment === k} className={r.deployment === k ? 'on' : ''} onClick={() => set({ deployment: k, multiAZ: k !== 'single' })} title={k === 'single' ? 'Una instancia en una AZ' : k === 'multi-az' ? 'Standby síncrono en otra AZ; failover 60‑120 s' : '2 standbys legibles en 3 AZ; failover ~35 s'}>
                {l}
              </button>
            ))}
          </div>
          <div className="scale-grid">
            <Num label="Réplicas de lectura" value={r.readReplicas} min={0} max={15} onChange={(v) => set({ readReplicas: v })} />
            <Num label="Backups" value={r.backupDays} min={0} max={35} suffix="días" onChange={(v) => set({ backupDays: v })} />
          </div>
          <Row label="RDS Proxy" help="Mantiene las conexiones durante el failover (hasta 66 % más rápido)" on={r.rdsProxy} onChange={(v) => set({ rdsProxy: v })} />
        </>
      )}
      {r.kind === 'relational' && id !== 'rds' && (
        <>
          <div className="scale-grid">
            <Num label={id === 'aurora' ? 'Réplicas (failover)' : 'Instancias'} value={id === 'aurora' ? r.readReplicas : r.readReplicas + 1} min={id === 'aurora' ? 0 : 1} max={15} onChange={(v) => set(id === 'aurora' ? { replicas: v } : { instances: v })} />
            <Num label="Backups" value={r.backupDays} min={1} max={35} suffix="días" onChange={(v) => set({ backupDays: v })} />
          </div>
          {id === 'aurora' && <Row label="RDS Proxy" help="Conexiones estables durante el failover" on={r.rdsProxy} onChange={(v) => set({ rdsProxy: v })} />}
        </>
      )}
      {r.kind === 'nosql' && <Row label="Point‑in‑time recovery" help="Restaurar la tabla a cualquier segundo de los últimos 35 días" on={r.pitr} onChange={(v) => set({ pitr: v })} />}
      {r.kind === 'cache' && (
        <>
          <div className="scale-grid">
            <Num label="Réplicas" value={r.readReplicas} min={0} max={5} onChange={(v) => set({ replicas: v })} />
          </div>
          <Row label="Failover automático (Multi‑AZ)" help="La réplica se promueve sola si cae la primaria" on={p.autoFailover !== false} onChange={(v) => set({ autoFailover: v })} />
        </>
      )}
      {r.kind === 'object' && <Row label="Versionado" help="Recupera objetos sobrescritos o borrados" on={r.versioning} onChange={(v) => set({ versioning: v })} />}
      {r.kind === 'files' && (
        <div className="scale-grid">
          <Num label="Backups (AWS Backup)" value={r.backupDays} min={0} max={35} suffix="días" onChange={(v) => set({ backupDays: v })} />
        </div>
      )}
      {r.kind === 'nat' && <Row label="Un NAT Gateway por AZ" help="Si cae una AZ, las otras siguen saliendo a Internet" on={r.perAz} onChange={(v) => set({ perAz: v })} />}
      {r.kind === 'dns' && (
        <>
          <div className="res-label">Política de enrutamiento</div>
          <div className="seg-choice wrap" role="radiogroup" aria-label="Política de enrutamiento de Route 53">
            {([['simple', 'Simple'], ['failover', 'Failover'], ['latency', 'Latencia'], ['weighted', 'Ponderada']] as const).map(([k, l]) => (
              <button key={k} role="radio" aria-checked={r.routing === k} className={r.routing === k ? 'on' : ''} onClick={() => set({ routing: k })}>
                {l}
              </button>
            ))}
          </div>
          <Row label="Health checks" help="Route 53 deja de responder con la región caída" on={!!r.healthChecks} onChange={(v) => set({ healthChecks: v })} />
          <div className="scale-grid">
            <Num label="TTL" value={r.ttl ?? 60} min={5} max={86400} step={5} suffix="s" onChange={(v) => set({ ttl: v })} />
          </div>
        </>
      )}

      {(replicaName[id] && (holds(r.kind) || id === 'elasticache' || id === 'memorydb')) && (
        <Row label={replicaName[id]} help={`Copia en ${drOf(meta).secondaryRegion} para sobrevivir a la caída de la región`} on={r.crossRegion} onChange={(v) => set({ crossRegion: v })} />
      )}

      {isCaller && (
        <>
          <div className="res-label">Llamadas a dependencias</div>
          <div className="scale-grid">
            <Num label="Timeout" value={r.caller.timeoutMs} min={100} max={120000} step={100} suffix="ms" onChange={(v) => set({ timeoutMs: v })} />
            <Num label="Reintentos" value={r.caller.retries} min={0} max={10} onChange={(v) => set({ retries: v })} />
          </div>
          <Row label="Circuit breaker" help="Deja de llamar a una dependencia lenta o caída y falla rápido" on={r.caller.breaker} onChange={(v) => set({ circuitBreaker: v })} />
          {p.timeoutMs === undefined && <div className="scale-note">{security.resilience ? 'Valores tomados de «Seguridad del proyecto → Timeouts, reintentos y circuit breaker».' : 'Valores típicos por defecto de un SDK (30 s y 3 reintentos). Pruébalos con la simulación «Lentitud».'}</div>}
        </>
      )}

      {row && (
        <div className="res-cells">
          <PlanCellView title={r.kind === 'fleet' ? 'Si falla una instancia' : def.role === 'datastore' || r.kind === 'cache' ? 'Si falla el primario' : 'Si falla un nodo'} cell={row.instance} />
          <PlanCellView title="Si cae una AZ" cell={row.az} />
          <PlanCellView title="Si cae la región" cell={row.region} />
          {row.data && <PlanCellView title="Si se dañan los datos" cell={row.data} />}
        </div>
      )}
    </div>
  );
}

const holds = (k: string) => ['relational', 'nosql', 'object', 'files', 'search', 'broker'].includes(k);
