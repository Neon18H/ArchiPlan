import { useEffect, useState } from 'react';
import { DT, targetCandidates, pickDefaultTarget } from '../sim/engine';
import { fmtRps } from '../sim/profiles';
import { FIELD_LABEL, SCENARIO_MAP, SCENARIOS, type Scenario } from '../sim/scenarios';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import { SimChart } from './SimChart';

const SEV_LABEL = { error: 'Crítico', warn: 'Aviso', info: 'Nota', ok: 'Bien' } as const;

function fmtTime(t: number) {
  const m = Math.floor(t / 60);
  const s = t % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function SimPanel() {
  const { scenario, result, idx, playing, speed, setKind, patch, setIdx, setPlaying, setSpeed, setOpen } = useSim();
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const focus = useStore((s) => s.focus);
  const [tab, setTab] = useState<'findings' | 'events'>('findings');
  const meta = SCENARIO_MAP[scenario.kind];

  // Reproducción
  useEffect(() => {
    if (!playing || !result) return;
    const id = setInterval(() => {
      const st = useSim.getState();
      if (st.idx >= result.frames.length - 1) {
        st.setPlaying(false);
        return;
      }
      st.setIdx(st.idx + 1);
    }, 1000 / speed);
    return () => clearInterval(id);
  }, [playing, speed, result]);

  const candidates = meta.target ? targetCandidates(nodes, scenario.kind) : [];
  const autoTarget = meta.target ? pickDefaultTarget(nodes, edges, scenario.kind) : null;
  const frame = result?.frames[idx];
  const s = result?.summary;
  const pct = (v: number) => `${(v * 100).toFixed(v >= 0.9995 ? 1 : 2)}%`;

  const field = (k: keyof Scenario) => {
    const f = FIELD_LABEL[k];
    if (k === 'targetId') {
      return (
        <label key={k} className="sim-field wide">
          <span>{f.label}</span>
          <select value={scenario.targetId} onChange={(e) => patch({ targetId: e.target.value })}>
            <option value="">Automático{autoTarget ? ` (${(nodes.find((n) => n.id === autoTarget)?.data as { label: string })?.label})` : ''}</option>
            {candidates.map((n) => (
              <option key={n.id} value={n.id}>
                {n.data.label}
              </option>
            ))}
          </select>
        </label>
      );
    }
    return (
      <label key={k} className="sim-field">
        <span>
          {f.label}
          {f.unit && <em> ({f.unit})</em>}
        </span>
        <input
          type="number"
          min={f.min}
          max={f.max}
          step={f.step}
          value={Number(scenario[k])}
          onChange={(e) => {
            let v = Number(e.target.value);
            if (!Number.isFinite(v)) return;
            if (f.min !== undefined) v = Math.max(f.min, v);
            if (f.max !== undefined) v = Math.min(f.max, v);
            patch({ [k]: v } as Partial<Scenario>);
          }}
        />
      </label>
    );
  };

  return (
    <section className="simpanel" aria-label="Simulación">
      <div className="sim-config">
        <div className="sim-head">
          <b>Simulación</b>
          <button className="x" onClick={() => setOpen(false)} aria-label="Cerrar simulación">
            ×
          </button>
        </div>
        <div className="sim-kinds">
          {SCENARIOS.map((m) => (
            <button key={m.kind} className={`sim-kind ${m.kind === scenario.kind ? 'on' : ''}`} onClick={() => setKind(m.kind)} title={m.description}>
              {m.short}
            </button>
          ))}
        </div>
        <p className="sim-desc">{meta.description}</p>
        <div className="sim-fields">{meta.fields.map(field)}</div>
        <p className="sim-disclaimer">Estimaciones con cuotas por defecto de AWS y cargas típicas. Ajusta la capacidad de cada pieza en su panel de propiedades.</p>
      </div>

      <div className="sim-main">
        {result && frame ? (
          <>
            <div className="sim-transport">
              <button className="btn small" onClick={() => setIdx(0)} title="Al inicio">
                ⏮
              </button>
              <button
                className="btn small primary"
                onClick={() => {
                  if (!playing && idx >= result.frames.length - 1) setIdx(0);
                  setPlaying(!playing);
                }}
              >
                {playing ? '❚❚ Pausa' : '▶ Reproducir'}
              </button>
              <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="Velocidad">
                {[2, 4, 8, 16].map((v) => (
                  <option key={v} value={v}>
                    {v * DT}× velocidad
                  </option>
                ))}
              </select>
              <span className="sim-time">
                {fmtTime(frame.t)} / {fmtTime(result.frames[result.frames.length - 1].t)}
              </span>
              <span className="sim-now">
                <b>{fmtRps(frame.legitOffered)}</b> req/s · éxito <b className={frame.success < 0.99 ? 'bad' : 'good'}>{(frame.success * 100).toFixed(1)}%</b> · <b>{Math.round(frame.latency)}</b> ms
                {frame.attackSent > 0 && (
                  <>
                    {' '}
                    · ataque <b>{fmtRps(frame.attackSent)}</b> req/s
                  </>
                )}
              </span>
            </div>
            <SimChart result={result} idx={idx} onScrub={(i) => (setPlaying(false), setIdx(i))} />
          </>
        ) : (
          <div className="muted pad">Agrega piezas al diagrama para simular.</div>
        )}
      </div>

      <div className="sim-results">
        {s && (
          <div className="kpis">
            <div className={`kpi ${s.availability >= 0.999 ? 'good' : s.availability >= 0.99 ? 'warn' : 'bad'}`}>
              <span>Disponibilidad</span>
              <b>{pct(s.availability)}</b>
            </div>
            <div className="kpi">
              <span>Recuperación</span>
              <b>{s.minSuccess >= 0.99 ? '—' : s.recoverySeconds !== null ? `${s.recoverySeconds} s` : 'no'}</b>
            </div>
            <div className="kpi">
              <span>Latencia p95</span>
              <b>{s.p95Latency >= 1000 ? `${(s.p95Latency / 1000).toFixed(1)} s` : `${Math.round(s.p95Latency)} ms`}</b>
            </div>
            <div className="kpi" title={s.bottleneck ? `${s.bottleneck.label}: ${Math.round(s.bottleneck.peakUtil * 100)}% de su capacidad en el pico` : ''}>
              <span>Más exigido</span>
              <b className="ellipsis">{s.bottleneck ? `${s.bottleneck.label}` : '—'}</b>
            </div>
          </div>
        )}
        <div className="sim-tabs">
          <button className={tab === 'findings' ? 'on' : ''} onClick={() => setTab('findings')}>
            Hallazgos {result ? `(${result.findings.length})` : ''}
          </button>
          <button className={tab === 'events' ? 'on' : ''} onClick={() => setTab('events')}>
            Línea de eventos {result ? `(${result.events.length})` : ''}
          </button>
        </div>
        <div className="sim-list">
          {tab === 'findings' &&
            result?.findings.map((f, k) => (
              <button key={k} className={`sim-finding ${f.severity}`} onClick={() => f.nodeIds.length && focus(f.nodeIds)}>
                <span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span>
                <b>{f.title}</b>
                <span>{f.detail}</span>
              </button>
            ))}
          {tab === 'events' &&
            result?.events.map((e, k) => (
              <button
                key={k}
                className={`sim-event ${e.kind}`}
                onClick={() => {
                  setPlaying(false);
                  setIdx(Math.round(e.t / DT));
                  if (e.nodeId) focus([e.nodeId]);
                }}
              >
                <span className="ev-t">{fmtTime(e.t)}</span>
                <span>{e.label}</span>
              </button>
            ))}
          {tab === 'events' && result && !result.events.length && <div className="muted small pad">Sin eventos.</div>}
        </div>
      </div>
    </section>
  );
}
