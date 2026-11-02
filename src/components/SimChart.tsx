import { useEffect, useMemo, useRef, useState } from 'react';
import type { SimResult } from '../sim/engine';
import { fmtRps } from '../sim/profiles';

/** Paleta (validada con el validador de dataviz, modo claro). */
const C = {
  served: '#2a78d6', // slot 1
  toApp: '#eb6834', // slot 2
  blocked: '#1baf7a', // slot 3
  demand: '#8a8f98', // referencia (muted)
  errors: '#d03b3b', // status crítico
  good: '#0ca30c',
  grid: '#eceef1',
  axis: '#69727d',
  ink: '#14171c',
};

interface Series {
  key: string;
  label: string;
  color: string;
  values: number[];
  dashed?: boolean;
  fmt: (v: number) => string;
}
interface Panel {
  id: string;
  title: string;
  height: number;
  series: Series[];
  yMax?: number;
  yMin?: number;
  refLine?: { y: number; label: string };
  errorBand?: [string, string];
  yFmt: (v: number) => string;
}

const M = { l: 46, r: 92, t: 18, b: 4 };
const AXIS_H = 18;
const GAP = 6;

function niceMax(v: number) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

export function SimChart({ result, idx, onScrub }: { result: SimResult; idx: number; onScrub: (i: number) => void }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);
  const [hoverEvent, setHoverEvent] = useState<number | null>(null);
  const dragging = useRef(false);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  const fr = result.frames;
  const isAttack = result.scenario.kind === 'ddos-l7' || result.scenario.kind === 'web-attacks';
  const panels: Panel[] = useMemo(() => {
    const p: Panel[] = [
      {
        id: 'traffic',
        title: 'Tráfico legítimo (req/s)',
        height: 82,
        errorBand: ['demand', 'served'],
        yFmt: fmtRps,
        series: [
          { key: 'demand', label: 'Demanda', color: C.demand, dashed: true, values: fr.map((f) => f.legitOffered), fmt: (v) => `${fmtRps(v)} req/s` },
          { key: 'served', label: 'Atendidos', color: C.served, values: fr.map((f) => f.legitOk), fmt: (v) => `${fmtRps(v)} req/s` },
        ],
      },
      {
        id: 'success',
        title: 'Éxito (%)',
        height: 62,
        yMin: Math.min(90, Math.floor(Math.min(...fr.map((f) => f.success * 100)) / 10) * 10),
        yMax: 100,
        refLine: { y: 99, label: '99%' },
        yFmt: (v) => `${Math.round(v)}%`,
        series: [{ key: 'success', label: 'Éxito', color: C.served, values: fr.map((f) => f.success * 100), fmt: (v) => `${v.toFixed(v >= 99.95 ? 0 : 1)}%` }],
      },
      {
        id: 'latency',
        title: 'Latencia media (ms)',
        height: 62,
        yFmt: (v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${Math.round(v)}`),
        series: [{ key: 'latency', label: 'Latencia', color: C.served, values: fr.map((f) => f.latency), fmt: (v) => `${Math.round(v)} ms` }],
      },
    ];
    if (isAttack)
      p.push({
        id: 'attack',
        title: 'Tráfico malicioso (req/s)',
        height: 78,
        yFmt: fmtRps,
        series: [
          { key: 'sent', label: 'Enviado', color: C.demand, dashed: true, values: fr.map((f) => f.attackSent), fmt: (v) => `${fmtRps(v)} req/s` },
          { key: 'blocked', label: 'Bloqueado en el borde', color: C.blocked, values: fr.map((f) => f.attackBlocked + f.attackAbsorbed), fmt: (v) => `${fmtRps(v)} req/s` },
          { key: 'toApp', label: 'Llega a la app', color: C.toApp, values: fr.map((f) => f.attackToApp), fmt: (v) => `${fmtRps(v)} req/s` },
        ],
      });
    return p;
  }, [fr, isAttack]);

  const plotW = Math.max(100, width - M.l - M.r);
  const tMax = fr[fr.length - 1]?.t ?? 1;
  const x = (t: number) => M.l + (t / tMax) * plotW;
  const totalH = panels.reduce((a, p) => a + p.height + GAP, 0) + AXIS_H;
  const offsets: number[] = [];
  panels.reduce((acc, p) => (offsets.push(acc), acc + p.height + GAP), 0);

  const idxAt = (clientX: number) => {
    const r = wrap.current!.getBoundingClientRect();
    const t = ((clientX - r.left - M.l) / plotW) * tMax;
    return Math.max(0, Math.min(fr.length - 1, Math.round((t / tMax) * (fr.length - 1))));
  };

  const hi = hover ?? null;
  const tooltipLeft = hi !== null ? Math.min(width - 210, Math.max(0, x(fr[hi].t) + 10)) : 0;

  return (
    <div className="simchart" ref={wrap}>
      <div className="simchart-legend">
        <span>
          <i className="lk" style={{ borderColor: C.demand, borderStyle: 'dashed' }} />
          Demanda / enviado
        </span>
        <span>
          <i className="lk" style={{ borderColor: C.served }} />
          Atendidos
        </span>
        <span>
          <i className="lk-rect" style={{ background: C.errors, opacity: 0.25 }} />
          Errores
        </span>
        {isAttack && (
          <>
            <span>
              <i className="lk" style={{ borderColor: C.blocked }} />
              Bloqueado en el borde
            </span>
            <span>
              <i className="lk" style={{ borderColor: C.toApp }} />
              Llega a la app
            </span>
          </>
        )}
        <span className="muted">· Haz clic o arrastra para mover el tiempo</span>
      </div>
      <svg
        width={width}
        height={totalH}
        role="img"
        aria-label="Línea de tiempo de la simulación"
        onPointerMove={(e) => {
          const i = idxAt(e.clientX);
          setHover(i);
          if (dragging.current) onScrub(i);
        }}
        onPointerLeave={() => {
          setHover(null);
          dragging.current = false;
        }}
        onPointerDown={(e) => {
          dragging.current = true;
          (e.target as Element).setPointerCapture?.(e.pointerId);
          onScrub(idxAt(e.clientX));
        }}
        onPointerUp={() => (dragging.current = false)}
        style={{ cursor: 'crosshair', touchAction: 'none' }}
      >
        {panels.map((p, pi) => {
          const top = offsets[pi];
          const vals = p.series.flatMap((s) => s.values);
          const yMax = p.yMax ?? niceMax(Math.max(...vals, 1) * 1.05);
          const yMin = p.yMin ?? 0;
          const y = (v: number) => top + M.t + (1 - (Math.min(Math.max(v, yMin), yMax) - yMin) / (yMax - yMin || 1)) * (p.height - M.t - M.b);
          const path = (vs: number[]) => vs.map((v, i) => `${i ? 'L' : 'M'}${x(fr[i].t).toFixed(1)},${y(v).toFixed(1)}`).join('');
          const ticks = [yMin, (yMin + yMax) / 2, yMax];
          let band = '';
          if (p.errorBand) {
            const a = p.series.find((s) => s.key === p.errorBand![0])!.values;
            const b = p.series.find((s) => s.key === p.errorBand![1])!.values;
            band = path(a) + b.map((_, k) => b.length - 1 - k).map((i) => `L${x(fr[i].t).toFixed(1)},${y(b[i]).toFixed(1)}`).join('') + 'Z';
          }
          // Etiquetas directas al final, separadas para que no choquen
          const ends = p.series.map((s) => ({ s, yy: y(s.values[s.values.length - 1]) })).sort((a, b) => a.yy - b.yy);
          for (let k = 1; k < ends.length; k++) if (ends[k].yy - ends[k - 1].yy < 11) ends[k].yy = ends[k - 1].yy + 11;
          return (
            <g key={p.id}>
              <text x={M.l} y={top + 10} className="sc-title">
                {p.title}
              </text>
              {ticks.map((tv, k) => (
                <g key={k}>
                  <line x1={M.l} x2={M.l + plotW} y1={y(tv)} y2={y(tv)} stroke={C.grid} strokeWidth={1} />
                  <text x={M.l - 6} y={y(tv) + 3} className="sc-tick" textAnchor="end">
                    {p.yFmt(tv)}
                  </text>
                </g>
              ))}
              {p.refLine && (
                <g>
                  <line x1={M.l} x2={M.l + plotW} y1={y(p.refLine.y)} y2={y(p.refLine.y)} stroke={C.axis} strokeDasharray="3 3" strokeWidth={1} />
                  <text x={M.l + plotW + 4} y={y(p.refLine.y) + 3} className="sc-tick">
                    meta {p.refLine.label}
                  </text>
                </g>
              )}
              {band && <path d={band} fill={C.errors} opacity={0.22} />}
              {p.series.map((s) => (
                <path key={s.key} d={path(s.values)} fill="none" stroke={s.color} strokeWidth={2} strokeDasharray={s.dashed ? '4 3' : undefined} strokeLinejoin="round" />
              ))}
              {p.series.length > 1 &&
                ends.map(({ s, yy }) => (
                  <text key={s.key} x={M.l + plotW + 6} y={yy + 3} className="sc-direct">
                    {s.label}
                  </text>
                ))}
            </g>
          );
        })}

        {/* Eje de tiempo */}
        {(() => {
          const yAxis = totalH - AXIS_H + 4;
          const step = tMax <= 300 ? 60 : tMax <= 900 ? 120 : 300;
          const ticks: number[] = [];
          for (let t = 0; t <= tMax; t += step) ticks.push(t);
          return ticks.map((t) => (
            <text key={t} x={x(t)} y={yAxis + 10} className="sc-tick" textAnchor="middle">
              {t >= 60 ? `${Math.floor(t / 60)}m${t % 60 ? `${t % 60}s` : ''}` : `${t}s`}
            </text>
          ));
        })()}

        {/* Eventos */}
        {result.events.map((ev, k) => {
          const col = ev.kind === 'bad' ? C.errors : ev.kind === 'good' ? C.good : C.axis;
          const ex = x(Math.min(ev.t, tMax));
          return (
            <g key={k} onPointerEnter={() => setHoverEvent(k)} onPointerLeave={() => setHoverEvent(null)}>
              <line x1={ex} x2={ex} y1={2} y2={totalH - AXIS_H} stroke={col} strokeWidth={1} strokeDasharray="2 3" opacity={0.55} />
              <rect x={ex - 6} y={totalH - AXIS_H - 2} width={12} height={12} fill="transparent" />
              <path d={`M${ex - 4},${totalH - AXIS_H + 4} L${ex + 4},${totalH - AXIS_H + 4} L${ex},${totalH - AXIS_H - 2} Z`} fill={col} />
            </g>
          );
        })}

        {/* Instante actual */}
        <line x1={x(fr[idx]?.t ?? 0)} x2={x(fr[idx]?.t ?? 0)} y1={0} y2={totalH - AXIS_H} stroke={C.ink} strokeWidth={2} />
        {hi !== null && hi !== idx && <line x1={x(fr[hi].t)} x2={x(fr[hi].t)} y1={0} y2={totalH - AXIS_H} stroke={C.axis} strokeWidth={1} />}
      </svg>

      {hi !== null && hoverEvent === null && (
        <div className="sc-tip" style={{ left: tooltipLeft }}>
          <div className="sc-tip-t">t = {fr[hi].t}s</div>
          {panels.flatMap((p) =>
            p.series.map((s) => (
              <div key={p.id + s.key} className="sc-tip-row">
                <i className="lk" style={{ borderColor: s.color, borderStyle: s.dashed ? 'dashed' : 'solid' }} />
                <b>{s.fmt(s.values[hi])}</b>
                <span>{p.series.length > 1 ? s.label : p.title.replace(/ \(.+\)$/, '')}</span>
              </div>
            )),
          )}
        </div>
      )}
      {hoverEvent !== null && (
        <div className="sc-tip" style={{ left: Math.min(width - 260, Math.max(0, x(result.events[hoverEvent].t) - 120)), bottom: AXIS_H + 6, top: 'auto', width: 250 }}>
          <div className="sc-tip-t">t = {result.events[hoverEvent].t}s</div>
          <div>{result.events[hoverEvent].label}</div>
        </div>
      )}
    </div>
  );
}
