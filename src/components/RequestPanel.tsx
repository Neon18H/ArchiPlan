import { useEffect, useMemo } from 'react';
import { getService } from '../catalog/catalog';
import { isService } from '../lib/graph';
import { REQUESTS, type HopStatus, type TraceResult } from '../net/trace';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import type { ServiceNode } from '../types';

const HOP_ICON: Record<HopStatus, string> = { ok: '✓', fail: '✗', blocked: '⛔', warn: '!', info: '→' };

export function ModeSwitch() {
  const mode = useSim((s) => s.mode);
  const setMode = useSim((s) => s.setMode);
  return (
    <div className="seg light sim-mode" role="tablist" aria-label="Tipo de simulación">
      <button role="tab" aria-selected={mode === 'load'} className={mode === 'load' ? 'on' : ''} onClick={() => setMode('load')} title="Carga, fallas y ataques en el tiempo">
        Escenarios
      </button>
      <button role="tab" aria-selected={mode === 'request'} className={mode === 'request' ? 'on' : ''} onClick={() => setMode('request')} title="Sigue una petición de usuario salto a salto">
        Petición de usuario
      </button>
    </div>
  );
}

function statusClass(r: TraceResult) {
  if (r.outcome === 'na') return 'na';
  if (r.asExpected) return 'good';
  return r.outcome === 'insecure' || r.outcome === 'partial' ? 'warn' : 'bad';
}

function codeOf(r: TraceResult) {
  if (r.outcome === 'na') return 'N/A';
  return r.status ? String(r.status) : r.statusText.replace(/^ERR_/, '').replace(/_/g, ' ').toLowerCase();
}

export function RequestPanel() {
  const { req, trace, battery, step, setReq, runTrace, setStep, setOpen } = useSim();
  const nodes = useStore((s) => s.nodes);
  const { focus, applyNetFix } = useStore.getState();

  const actors = useMemo(() => nodes.filter((n): n is ServiceNode => isService(n) && ['actor', 'external'].includes(getService(n.data.serviceId).role)), [nodes]);
  const targets = useMemo(() => nodes.filter((n): n is ServiceNode => isService(n) && ['compute', 'datastore', 'cache', 'storage', 'search', 'workflow', 'external', 'ai'].includes(getService(n.data.serviceId).role)), [nodes]);

  // Animación salto a salto
  useEffect(() => {
    if (!trace || step >= trace.hops.length) return;
    const id = setTimeout(() => setStep(step + 1), step === 0 ? 0 : 380);
    return () => clearTimeout(id);
  }, [trace, step, setStep]);

  const done = !!trace && step >= trace.hops.length;
  const def = REQUESTS.find((r) => r.id === req.kind)!;

  return (
    <section className="simpanel req-panel" aria-label="Petición de usuario">
      <div className="sim-config">
        <div className="sim-head">
          <ModeSwitch />
          <button className="x" onClick={() => setOpen(false)} aria-label="Cerrar simulación">
            ×
          </button>
        </div>
        <div className="req-kinds">
          {REQUESTS.map((r) => (
            <button key={r.id} className={`req-kind ${r.id === req.kind ? 'on' : ''} ${r.expect === 'blocked' ? 'attack' : ''}`} onClick={() => setReq({ kind: r.id })} title={r.desc}>
              <span className="req-method">{r.method}</span> {r.label}
            </button>
          ))}
        </div>
        <label className="sim-field wide">
          <span>Quién hace la petición</span>
          <select value={req.entryId} onChange={(e) => setReq({ entryId: e.target.value })}>
            <option value="">Automático{actors[0] ? ` (${actors[0].data.label})` : ''}</option>
            {actors.map((n) => (
              <option key={n.id} value={n.id}>
                {n.data.label}
              </option>
            ))}
          </select>
        </label>
        <label className="sim-field wide">
          <span>Destino (opcional)</span>
          <select value={req.targetId} onChange={(e) => setReq({ targetId: e.target.value })}>
            <option value="">Camino principal</option>
            {targets.map((n) => (
              <option key={n.id} value={n.id}>
                {n.data.label}
              </option>
            ))}
          </select>
        </label>
        <button className="btn primary req-send" onClick={() => runTrace(true)}>
          ▶ Enviar petición
        </button>
        <p className="sim-disclaimer">Revisa en cada salto los Security Groups, listeners, puertos, rutas de salida, WAF y autenticación que configuraste.</p>
      </div>

      <div className="sim-main req-main">
        {trace ? (
          <>
            <div className="req-line">
              <code>
                {def.method} {def.path}
              </code>
              {done ? (
                <span className={`req-status ${statusClass(trace)}`}>
                  {trace.outcome === 'na' ? 'No aplica' : trace.status ? `${trace.status} ${trace.statusText}` : trace.statusText}
                </span>
              ) : (
                <span className="req-status pending">en camino…</span>
              )}
              {done && trace.outcome !== 'na' && <span className="muted small">{trace.totalMs >= 1000 ? `${(trace.totalMs / 1000).toFixed(1)} s` : `${trace.totalMs} ms`}</span>}
            </div>
            <ol className="req-hops">
              {trace.hops.slice(0, step).map((h) => (
                <li key={h.id} className={`hop st-${h.status} ${h.async ? 'async' : ''}`} style={{ marginLeft: h.depth * 16 }}>
                  <button onClick={() => focus([h.nodeId, ...(h.edgeId ? [h.edgeId] : [])])}>
                    <span className="hop-ico">{HOP_ICON[h.status]}</span>
                    <span className="hop-body">
                      <b>
                        {h.async && <em className="hop-async">asíncrono</em>}
                        {h.title}
                      </b>
                      <span>{h.detail}</span>
                    </span>
                    <span className="hop-t">{h.at >= 1000 ? `${(h.at / 1000).toFixed(1)} s` : `${h.at} ms`}</span>
                  </button>
                </li>
              ))}
            </ol>
            {!trace.hops.length && <div className="muted pad">{trace.headline}</div>}
          </>
        ) : (
          <div className="muted pad">Elige una petición y envíala.</div>
        )}
      </div>

      <div className="sim-results req-results">
        {trace && done && (
          <div className={`req-verdict ${statusClass(trace)}`}>
            <b>{trace.asExpected ? (trace.outcome === 'na' ? 'No aplica' : 'La arquitectura responde bien') : trace.outcome === 'insecure' ? 'Funciona, pero es inseguro' : trace.outcome === 'partial' ? 'Responde, pero algo falla detrás' : 'Algo está mal configurado'}</b>
            <span>{trace.headline}</span>
          </div>
        )}
        {trace && done && trace.problems.length > 0 && (
          <div className="req-problems">
            <div className="req-sub">Dónde está el error</div>
            {trace.problems.map((p, k) => (
              <div key={k} className="req-problem">
                <button className="linklike" onClick={() => focus([p.nodeId, ...(p.edgeId ? [p.edgeId] : [])])}>
                  <b>{p.title}</b>
                </button>
                <span>{p.detail}</span>
                {p.fix && (
                  <button
                    className="btn small fix"
                    onClick={() => {
                      applyNetFix(p.fix!);
                      setTimeout(() => useSim.getState().runTrace(true), 50);
                    }}
                  >
                    ⚡ {p.fix.label}
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        {trace && done && trace.notes.map((n, k) => <p key={k} className="muted small req-note">{n}</p>)}
        {battery && (
          <div className="req-battery">
            <div className="req-sub">Batería de pruebas</div>
            {battery.map((r) => (
              <button key={r.request.id} className={`bat ${statusClass(r)} ${r.request.id === req.kind ? 'on' : ''}`} onClick={() => setReq({ kind: r.request.id })} title={r.headline}>
                <span className="bat-code">{codeOf(r)}</span>
                <span className="bat-label">{r.request.label}</span>
                <span className="bat-ok">{r.outcome === 'na' ? '—' : r.asExpected ? '✓' : '✗'}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
