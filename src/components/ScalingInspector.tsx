import { getService } from '../catalog/catalog';
import { byId, isService } from '../lib/graph';
import { isLb } from '../net/model';
import { describeScaling, policiesFor, scalingOf, type ScalePolicy } from '../scaling/model';
import { fmtRps, profileFor } from '../sim/profiles';
import { useStore } from '../store';
import type { PropValue, ServiceNode } from '../types';

function Num({ label, value, onChange, min = 0, max = 100000, step = 1, suffix, disabled }: { label: string; value: number; onChange: (v: number) => void; min?: number; max?: number; step?: number; suffix?: string; disabled?: boolean }) {
  return (
    <label className={`scale-num ${disabled ? 'disabled' : ''}`}>
      <span>{label}</span>
      <span className="scale-num-in">
        <button type="button" disabled={disabled || value - step < min} onClick={() => onChange(Math.max(min, +(value - step).toFixed(2)))} aria-label={`Menos ${label}`}>
          −
        </button>
        <input type="number" min={min} max={max} step={step} value={value} disabled={disabled} onChange={(e) => Number.isFinite(Number(e.target.value)) && onChange(Math.max(min, Math.min(max, Number(e.target.value))))} aria-label={label} />
        <button type="button" disabled={disabled || value + step > max} onClick={() => onChange(Math.min(max, +(value + step).toFixed(2)))} aria-label={`Más ${label}`}>
          +
        </button>
      </span>
      {suffix && <em>{suffix}</em>}
    </label>
  );
}

/** Dibujito de la capacidad: instancias iniciales (llenas) y hasta dónde puede crecer (contorno). */
function Fleet({ desired, max, grows }: { desired: number; max: number; grows: boolean }) {
  const cap = 24;
  const total = grows ? max : desired;
  const shown = Math.min(cap, total);
  return (
    <div className="fleet" aria-hidden>
      {Array.from({ length: shown }, (_, i) => (
        <span key={i} className={i < desired ? 'on' : 'can'} />
      ))}
      {total > cap && <em>+{total - cap}</em>}
    </div>
  );
}

export function ScalingSection({ node }: { node: ServiceNode }) {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const { updateNode } = useStore.getState();
  const s = scalingOf(node);
  if (!s) return null;
  const map = byId(nodes);
  const set = (props: Record<string, PropValue>) => updateNode(node.id, { props });
  const prof = profileFor(node);
  const behindLb = edges.some((e) => e.target === node.id && isService(map.get(e.source)) && isLb(map.get(e.source) as ServiceNode));
  const azure = node.data.serviceId.startsWith('az-');
  const per = prof.perInstance;
  const fleetKinds = ['instances', 'tasks', 'nodes', 'app'] as const;
  const desiredKey = s.kind === 'instances' ? 'count' : s.kind === 'tasks' ? 'desired' : s.kind === 'nodes' ? 'nodes' : 'instances';
  const unit = s.kind === 'tasks' ? (azure ? 'réplicas' : 'tareas') : s.kind === 'nodes' ? 'nodos' : 'instancias';
  const grows = ['cpu', 'requests', 'step'].includes(s.policy);
  const setPolicy = (p: ScalePolicy) => set({ scalePolicy: p, ...(s.kind === 'instances' ? { autoscaling: p !== 'manual' } : {}), ...(s.kind === 'tasks' ? { 'sim.autoscaling': p !== 'fixed' } : {}), ...(p !== 'manual' && p !== 'fixed' && s.max <= s.desired ? { maxSize: Math.max(s.desired * 3, s.desired + 2) } : {}) });

  return (
    <div className="insp-section scale-section">
      <div className="insp-section-title">Escalado</div>
      <div className="scale-summary">{describeScaling(node, per)}</div>

      {(fleetKinds as readonly string[]).includes(s.kind) && (
        <>
          <div className="seg-choice wrap" role="radiogroup" aria-label="Política de escalado">
            {policiesFor(s.kind, behindLb).map((p) => {
              const off = p.id === 'requests' && !behindLb && s.kind !== 'app' && !azure;
              return (
                <button key={p.id} role="radio" aria-checked={s.policy === p.id} className={s.policy === p.id ? 'on' : ''} title={p.help} disabled={off} onClick={() => setPolicy(p.id)}>
                  {p.label}
                </button>
              );
            })}
          </div>
          <Fleet desired={s.desired} max={s.max} grows={grows} />
          <div className="scale-grid">
            {grows && <Num label="Mínimo" value={s.min} min={s.kind === 'tasks' ? 0 : 1} max={s.desired} onChange={(v) => set({ minSize: v })} />}
            <Num label={grows ? 'Al iniciar' : `${unit[0].toUpperCase()}${unit.slice(1)}`} value={s.desired} min={s.kind === 'tasks' ? 0 : 1} max={1000} onChange={(v) => set({ [desiredKey]: v, ...(grows && v > s.max ? { maxSize: v } : {}), ...(v < s.min ? { minSize: v } : {}) })} />
            {grows && <Num label="Máximo" value={s.max} min={Math.max(1, s.desired)} max={1000} onChange={(v) => set({ maxSize: v })} />}
          </div>
          {s.policy === 'cpu' && s.kind !== 'nodes' && (
            <label className="scale-slider">
              <span>
                CPU objetivo <b>{s.targetCpu} %</b>
              </span>
              <input type="range" min={20} max={90} step={5} value={s.targetCpu} onChange={(e) => set({ targetCpu: Number(e.target.value) })} />
              <em>Más bajo = reacciona antes, pero más instancias ociosas.</em>
            </label>
          )}
          {s.policy === 'requests' && (
            <div className="scale-grid">
              <Num label="Peticiones/s por instancia" value={s.targetRequests} min={1} max={100000} step={10} onChange={(v) => set({ targetRequests: v })} />
              {Number.isFinite(per) && <div className={`scale-note ${s.targetRequests > per ? 'bad' : ''}`}>Cada {unit.slice(0, -1)} aguanta ~{fmtRps(per)} req/s{s.targetRequests > per ? ': el objetivo es mayor, escalaría tarde.' : '.'}</div>}
            </div>
          )}
          {s.policy === 'step' && (
            <div className="scale-grid">
              <Num label="Umbral de CPU" value={s.stepThreshold} min={20} max={95} step={5} suffix="%" onChange={(v) => set({ stepThreshold: v })} />
              <Num label="Agregar de golpe" value={s.stepAdd} min={1} max={50} onChange={(v) => set({ stepAdd: v })} />
            </div>
          )}
          {grows && (
            <div className="scale-grid">
              <Num label="Calentamiento" value={s.warmup} min={0} max={1800} step={10} suffix="s" onChange={(v) => set({ warmup: v })} />
              <div className="scale-note">Arranque + health checks. Con la detección (~{s.detection} s), cada {unit.slice(0, -1)} nueva tarda ~{s.detection + s.warmup} s en recibir tráfico.</div>
            </div>
          )}
          {Number.isFinite(per) && (
            <div className="scale-cap">
              Capacidad: <b>{fmtRps(per * Math.max(1, s.desired))} req/s</b> al iniciar{grows ? <> → <b>{fmtRps(per * s.max)} req/s</b> al máximo</> : null}
            </div>
          )}
        </>
      )}

      {s.kind === 'functions' && (
        <div className="scale-grid">
          <Num label="Concurrencia reservada" value={s.reserved ?? 0} min={0} max={10000} step={10} onChange={(v) => set({ reservedConcurrency: v })} />
          <Num label="Concurrencia aprovisionada" value={s.provisioned ?? 0} min={0} max={10000} step={1} onChange={(v) => set({ provisionedConcurrency: v })} />
          <div className="scale-note">Reservada = tope (0 = comparte la cuota de la cuenta). Aprovisionada = ejecuciones siempre calientes, sin arranque en frío (tiene costo fijo).</div>
        </div>
      )}

      {s.kind === 'aurora' && (
        <>
          <div className="seg-choice">
            <button className={s.serverless ? 'on' : ''} onClick={() => set({ serverless: true })}>
              Serverless v2
            </button>
            <button className={!s.serverless ? 'on' : ''} onClick={() => set({ serverless: false })}>
              Instancias fijas
            </button>
          </div>
          <div className="scale-grid">
            <Num label="Réplicas de lectura" value={s.replicas ?? 1} min={0} max={15} onChange={(v) => set({ replicas: v })} />
            {s.serverless && (
              <>
                <Num label="ACU mínimas" value={s.minAcu ?? 2} min={0.5} max={256} step={0.5} onChange={(v) => set({ minAcu: v })} />
                <Num label="ACU máximas" value={s.maxAcu ?? 16} min={s.minAcu ?? 0.5} max={256} step={1} onChange={(v) => set({ maxAcu: v })} />
              </>
            )}
          </div>
        </>
      )}

      {s.kind === 'nosql' && node.data.serviceId !== 'az-cosmos' && (
        <>
          <div className="seg-choice">
            <button className={s.billing !== 'PROVISIONED' ? 'on' : ''} onClick={() => set({ billing: 'PAY_PER_REQUEST' })}>
              On‑demand
            </button>
            <button className={s.billing === 'PROVISIONED' ? 'on' : ''} onClick={() => set({ billing: 'PROVISIONED' })}>
              Provisionada
            </button>
          </div>
          {s.billing === 'PROVISIONED' && (
            <>
              <label className="toggle">
                <input type="checkbox" checked={s.policy === 'cpu'} onChange={(e) => set({ autoscaling: e.target.checked })} />
                <span>Auto scaling de capacidad</span>
              </label>
              <div className="scale-grid">
                <Num label="Lecturas/s (RCU)" value={s.rcu ?? 1000} min={1} max={400000} step={100} onChange={(v) => set({ rcu: v })} />
                {s.policy === 'cpu' && <Num label="Máximo RCU" value={s.maxRcu ?? 4000} min={s.rcu ?? 1} max={400000} step={100} onChange={(v) => set({ maxRcu: v })} />}
              </div>
            </>
          )}
        </>
      )}
      {s.kind === 'nosql' && node.data.serviceId === 'az-cosmos' && (
        <>
          <div className="seg-choice">
            {['Serverless', 'Autoscale', 'Provisioned'].map((b) => (
              <button key={b} className={s.billing === b ? 'on' : ''} onClick={() => set({ billing: b })}>
                {b === 'Provisioned' ? 'Fija' : b}
              </button>
            ))}
          </div>
          {s.billing !== 'Serverless' && <Num label={s.billing === 'Autoscale' ? 'RU/s máximas' : 'RU/s'} value={s.ru ?? 4000} min={400} max={1000000} step={100} onChange={(v) => set({ ru: v })} />}
        </>
      )}

      {s.kind === 'throttle' && (
        <div className="scale-grid">
          <Num label={node.data.serviceId === 'apigw' ? 'Límite (req/s)' : 'Rate limit por política (req/s)'} value={s.rateLimit ?? 10000} min={1} max={100000} step={100} onChange={(v) => set({ rateLimit: v })} />
          {node.data.serviceId === 'apigw' && <Num label="Ráfaga" value={s.burstLimit ?? 5000} min={1} max={100000} step={100} onChange={(v) => set({ burstLimit: v })} />}
          <div className="scale-note">Protege el backend: lo que pasa del límite recibe 429 en el borde en lugar de saturar la aplicación.</div>
        </div>
      )}
      {getService(node.data.serviceId).role === 'compute' && <div className="scale-foot">La simulación usa exactamente esta configuración.</div>}
    </div>
  );
}
