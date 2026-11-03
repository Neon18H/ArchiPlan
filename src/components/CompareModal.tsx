import { useEffect, useMemo, useRef, useState } from 'react';
import { aiApi, useAi } from '../ai/store';
import { useStore } from '../store';
import { buildAdr, compareVariants, diffVariants, PILLARS, rescore, WEIGHT_PRESETS, type Comparison, type Pillar, type VariantMetrics, type Weights } from '../variants/compare';
import type { Variant } from '../types';
import { Modal } from './Modals';

const money = (n: number) => `US$${Math.round(n).toLocaleString('es-CO')}`;
const pct = (n: number) => `${(n * 100).toFixed(2)} %`;

type Better = 'high' | 'low';
/** Clase de cada celda: mejor (verde) y peor (rojo) de la fila, si hay diferencia. */
function marks(values: number[], better: Better, tol = 1e-9): string[] {
  if (values.length < 2) return values.map(() => '');
  const best = better === 'high' ? Math.max(...values) : Math.min(...values);
  const worst = better === 'high' ? Math.min(...values) : Math.max(...values);
  if (Math.abs(best - worst) <= tol) return values.map(() => '');
  return values.map((v) => (Math.abs(v - best) <= tol ? 'best' : Math.abs(v - worst) <= tol ? 'worst' : ''));
}

interface Row {
  label: string;
  help?: string;
  cells: (m: VariantMetrics) => React.ReactNode;
  value?: (m: VariantMetrics) => number;
  better?: Better;
  tol?: number;
}

function Section({ title, rows, metrics }: { title: string; rows: Row[]; metrics: VariantMetrics[] }) {
  return (
    <>
      <tr className="cmp-sec">
        <th colSpan={metrics.length + 1}>{title}</th>
      </tr>
      {rows.map((r) => {
        const cls = r.value && r.better ? marks(metrics.map(r.value), r.better, r.tol) : metrics.map(() => '');
        return (
          <tr key={r.label}>
            <th scope="row" title={r.help}>
              {r.label}
            </th>
            {metrics.map((m, i) => (
              <td key={m.id} className={cls[i]}>
                {r.cells(m)}
              </td>
            ))}
          </tr>
        );
      })}
    </>
  );
}

const AI_PROMPT = `Eres un arquitecto de soluciones senior. Con los resultados de la comparación de variantes que te paso, redacta un ADR breve en español, solo con la decisión y su justificación, sin inventar datos que no estén en los resultados.
Responde exactamente con tres secciones Markdown:
## Contexto
(2-4 frases: qué se comparó y con qué prioridades)
## Decisión
(qué variante se elige y por qué, con las cifras que lo justifican)
## Consecuencias
(lo que se acepta a cambio y los pendientes concretos de la variante elegida)`;

function parseAdr(text: string) {
  const sec = (name: string) => {
    const m = text.match(new RegExp(`##\\s*${name}[^\\n]*\\n([\\s\\S]*?)(?=\\n##\\s|$)`, 'i'));
    return m ? m[1].trim() : '';
  };
  return { context: sec('Contexto'), decision: sec('Decisi[oó]n'), consequences: sec('Consecuencias') };
}

export function CompareModal({ onClose }: { onClose: () => void }) {
  const security = useStore((s) => s.security);
  const activeVariant = useStore((s) => s.activeVariant);
  const storeAi = useAi((s) => s.config?.configured);
  const [fetchedAi, setFetchedAi] = useState<boolean | undefined>(undefined);
  const aiConfigured = !!(storeAi ?? fetchedAi);
  const [preset, setPreset] = useState('equilibrado');
  const [weights, setWeights] = useState<Weights>(WEIGHT_PRESETS[0].weights);
  const [avgRps, setAvgRps] = useState(50);
  const [variants, setVariants] = useState<Variant[]>(() => useStore.getState().syncedVariants());
  const [result, setResult] = useState<Comparison | null>(null);
  const [running, setRunning] = useState(true);
  const [error, setError] = useState('');
  const [openCost, setOpenCost] = useState(false);
  const [ai, setAi] = useState<{ text: string; busy: boolean; error?: string } | null>(null);
  const ctl = useRef<AbortController | null>(null);

  useEffect(() => {
    if (useAi.getState().config === null)
      aiApi
        .config()
        .then((c) => setFetchedAi(c.configured))
        .catch(() => setFetchedAi(false));
    return () => ctl.current?.abort();
  }, []);

  // Las simulaciones tardan unos cientos de ms: se corren fuera del render y se vuelven a correr al cambiar el tráfico.
  useEffect(() => {
    setRunning(true);
    const vs = useStore.getState().syncedVariants();
    setVariants(vs);
    const t = setTimeout(() => {
      try {
        setResult(compareVariants(vs, { security, avgRps, weights }));
        setError('');
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
      setRunning(false);
    }, 30);
    return () => clearTimeout(t);
    // los pesos se recalculan aparte (no hace falta volver a simular)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [security, avgRps]);

  // Cambiar los pesos solo recalcula el puntaje
  const comparison = useMemo(() => (result ? rescore(result, weights) : null), [result, weights]);
  const metrics = comparison?.metrics ?? [];
  const winner = metrics.find((m) => m.id === comparison?.winnerId);
  const sumW = PILLARS.reduce((a, p) => a + weights[p.id], 0);

  const setW = (p: Pillar, v: number) => {
    setPreset('');
    setWeights({ ...weights, [p]: v });
  };

  const adr = comparison ? buildAdr(comparison, variants) : null;
  const saveAdr = (d: { title: string; context: string; decision: string; consequences: string }) => {
    // Primero se abre la pestaña ADR para que la nueva decisión aparezca desplegada
    window.dispatchEvent(new CustomEvent('archiplan:tab', { detail: 'adr' }));
    onClose();
    setTimeout(() => {
      const st = useStore.getState();
      st.addDecision({ title: d.title, status: 'propuesta', context: d.context, decision: d.decision, consequences: d.consequences });
      st.toast('ok', 'ADR creado como «propuesta» en la pestaña ADR.');
    }, 30);
  };

  const draftWithAi = async () => {
    if (!adr || !comparison) return;
    ctl.current?.abort();
    const c = new AbortController();
    ctl.current = c;
    setAi({ text: '', busy: true });
    const data = `Título propuesto: ${adr.title}\n\n### Resultados\n${adr.context}\n\n### Borrador automático de la decisión\n${adr.decision}\n\n### Borrador de consecuencias\n${adr.consequences}`;
    try {
      const text = await aiApi.stream(AI_PROMPT, [{ role: 'user', content: data }], (t) => setAi({ text: t, busy: true }), c.signal);
      setAi({ text, busy: false });
    } catch (e) {
      if (c.signal.aborted) return;
      setAi({ text: '', busy: false, error: e instanceof Error ? e.message : String(e) });
    }
  };

  const rows = {
    total: [
      {
        label: 'Puntaje',
        help: 'Promedio ponderado de los pilares con las prioridades de arriba.',
        value: (m: VariantMetrics) => m.total,
        better: 'high' as Better,
        cells: (m: VariantMetrics) => (
          <span className="cmp-total">
            {m.id === winner?.id && <span aria-label="Ganadora">👑 </span>}
            <b>{m.total}</b>/100
          </span>
        ),
      },
      ...PILLARS.map<Row>((p) => ({
        label: p.label,
        help: p.help,
        value: (m) => m.scores[p.id],
        better: 'high',
        cells: (m) => (
          <span className="cmp-bar" title={`${m.scores[p.id]}/100`}>
            <i style={{ width: `${m.scores[p.id]}%` }} />
            <em>{m.scores[p.id]}</em>
          </span>
        ),
      })),
    ] as Row[],
    avail: [
      ...(metrics[0]?.availability ?? []).map<Row>((a, i) => ({
        label: a.label,
        value: (m) => m.availability[i].value,
        better: 'high',
        tol: 0.00005,
        cells: (m) => pct(m.availability[i].value),
      })),
      { label: 'Ponderada (40/40/20)', value: (m) => m.availFailures, better: 'high', tol: 0.00005, cells: (m) => <b>{pct(m.availFailures)}</b> },
      { label: 'Bajo DDoS', value: (m) => m.attack.ddosAvail, better: 'high', tol: 0.00005, cells: (m) => pct(m.attack.ddosAvail) },
    ] as Row[],
    perf: [
      { label: 'p95 con carga normal', value: (m) => m.p95Load, better: 'low', tol: 5, cells: (m) => `${Math.round(m.p95Load)} ms` },
      { label: 'p95 en el pico', value: (m) => m.p95Spike, better: 'low', tol: 5, cells: (m) => `${Math.round(m.p95Spike)} ms` },
      { label: 'Éxito en el pico', value: (m) => m.successSpike, better: 'high', tol: 0.0005, cells: (m) => pct(m.successSpike) },
    ] as Row[],
    sec: [
      {
        label: 'Amenazas abiertas',
        help: 'Críticas / altas / medias / bajas que siguen abiertas o parciales.',
        value: (m) => m.threats.critical * 100 + m.threats.high * 10 + m.threats.medium,
        better: 'low',
        cells: (m) => (
          <span className="cmp-threats">
            <span className="t-c" title="Críticas">{m.threats.critical}</span>
            <span className="t-h" title="Altas">{m.threats.high}</span>
            <span className="t-m" title="Medias">{m.threats.medium}</span>
            <span className="t-l" title="Bajas">{m.threats.low}</span>
          </span>
        ),
      },
      {
        label: 'Ataques web bloqueados',
        value: (m) => m.attack.webBlockedPct ?? 0,
        better: 'high',
        tol: 0.005,
        cells: (m) => (m.attack.webBlockedPct === null ? <span className="muted">sin entrada web</span> : `${Math.round(m.attack.webBlockedPct * 100)} %`),
      },
      {
        label: 'Peticiones de usuario',
        help: 'Navegar, API, login, API sin token (debe rechazarse) e inyección SQL (debe bloquearse).',
        value: (m) => m.battery.filter((b) => b.ok).length,
        better: 'high',
        cells: (m) => (
          <span title={m.battery.map((b) => `${b.ok ? '✓' : '✗'} ${b.label}: ${b.status}`).join('\n')}>
            {m.battery.filter((b) => b.ok).length}/{m.battery.length}
            {m.battery.some((b) => !b.ok) && <span className="muted small"> · falla {m.battery.filter((b) => !b.ok).map((b) => b.label).join(', ')}</span>}
          </span>
        ),
      },
    ] as Row[],
    cost: [
      { label: 'Costo mensual', value: (m) => m.cost.total, better: 'low', tol: 1, cells: (m) => <b>{money(m.cost.total)}</b> },
      { label: 'Por millón de peticiones', value: (m) => m.cost.perMillion, better: 'low', tol: 0.01, cells: (m) => `US$${m.cost.perMillion.toFixed(2)}` },
    ] as Row[],
    ops: [
      {
        label: 'Complejidad',
        value: (m) => m.complexity.points,
        better: 'low',
        tol: 0.5,
        cells: (m) => (
          <span>
            <b>{m.complexity.label}</b> <span className="muted small">({m.complexity.points} pts)</span>
          </span>
        ),
      },
      { label: 'Piezas / tipos', value: (m) => m.pieces, better: 'low', cells: (m) => `${m.pieces} / ${m.serviceTypes}` },
      { label: 'Conexiones', value: (m) => m.connections, better: 'low', cells: (m) => m.connections },
      { label: 'Errores / avisos', value: (m) => m.validation.errors * 10 + m.validation.warns, better: 'low', cells: (m) => `${m.validation.errors} / ${m.validation.warns}` },
      { label: 'Conexiones bloqueadas por red', value: (m) => m.blocked, better: 'low', cells: (m) => m.blocked },
    ] as Row[],
  };

  const winnerVariant = variants.find((v) => v.id === winner?.id);

  return (
    <Modal title="Comparar variantes" onClose={onClose} wide>
      <div className="cmp">
        <p className="muted small cmp-intro">
          Se corren <b>las mismas pruebas</b> a cada variante: caída de instancia, de zona y de la dependencia principal, carga y pico, ataques web y DDoS, las peticiones de usuario, STRIDE, la red y un costo mensual estimado. Ajusta las prioridades para tu equipo.
        </p>
        <div className="cmp-controls">
          <label className="small">
            Prioridades{' '}
            <select
              value={preset}
              onChange={(e) => {
                const p = WEIGHT_PRESETS.find((x) => x.id === e.target.value);
                setPreset(e.target.value);
                if (p) setWeights(p.weights);
              }}
            >
              {!preset && <option value="">Personalizado</option>}
              {WEIGHT_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <label className="small">
            Tráfico promedio{' '}
            <input type="number" min={1} max={100000} value={avgRps} onChange={(e) => setAvgRps(Math.max(1, Math.min(100000, Number(e.target.value) || 1)))} aria-label="Tráfico promedio en peticiones por segundo" /> req/s
          </label>
          <div className="cmp-weights">
            {PILLARS.map((p) => (
              <label key={p.id} title={p.help}>
                <span>{p.label}</span>
                <input type="range" min={0} max={50} step={5} value={weights[p.id]} onChange={(e) => setW(p.id, Number(e.target.value))} aria-label={`Peso de ${p.label}`} />
                <em>{sumW ? Math.round((weights[p.id] / sumW) * 100) : 0} %</em>
              </label>
            ))}
          </div>
        </div>

        {error && <p className="cmp-error">No se pudo comparar: {error}</p>}
        {running && !comparison && <p className="cmp-running">⏳ Corriendo las simulaciones en {variants.length} variantes…</p>}

        {comparison && (
          <div className={`cmp-table-wrap ${running ? 'stale' : ''}`}>
            <table className="cmp-table">
              <thead>
                <tr>
                  <th />
                  {metrics.map((m) => (
                    <th key={m.id} className={m.id === winner?.id ? 'winner' : ''}>
                      <div className="cmp-head">
                        <span>{m.name}</span>
                        {m.id === activeVariant && <span className="cmp-tag">en edición</span>}
                        {m.id === winner?.id && <span className="cmp-tag win">recomendada</span>}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <Section title="Resultado" rows={rows.total} metrics={metrics} />
                <Section title="Disponibilidad" rows={rows.avail} metrics={metrics} />
                <Section title="Latencia" rows={rows.perf} metrics={metrics} />
                <Section title="Amenazas y ataques" rows={rows.sec} metrics={metrics} />
                <Section title="Costo estimado" rows={rows.cost} metrics={metrics} />
                <tr>
                  <th scope="row">
                    <button className="linkish small" onClick={() => setOpenCost(!openCost)} aria-expanded={openCost}>
                      {openCost ? '▾' : '▸'} Detalle del costo
                    </button>
                  </th>
                  {metrics.map((m) => (
                    <td key={m.id} className="cmp-costitems">
                      {openCost ? (
                        <ul>
                          {[...m.cost.items]
                            .sort((a, b) => b.monthly - a.monthly)
                            .filter((x) => x.monthly >= 0.5)
                            .map((x, i) => (
                              <li key={i} title={x.basis}>
                                <span>{x.label}</span> <b>{money(x.monthly)}</b>
                              </li>
                            ))}
                        </ul>
                      ) : (
                        <span className="muted small">{[...m.cost.items].sort((a, b) => b.monthly - a.monthly)[0]?.label ?? '—'} es lo más caro</span>
                      )}
                    </td>
                  ))}
                </tr>
                <Section title="Complejidad y salud" rows={rows.ops} metrics={metrics} />
                {winnerVariant && (
                  <>
                    <tr className="cmp-sec">
                      <th colSpan={metrics.length + 1}>Qué cambia respecto a la recomendada</th>
                    </tr>
                    <tr>
                      <th scope="row">Diferencias</th>
                      {metrics.map((m) => {
                        if (m.id === winnerVariant.id) return <td key={m.id} className="muted small">— referencia —</td>;
                        const v = variants.find((x) => x.id === m.id);
                        const d = v ? diffVariants(winnerVariant, v) : null;
                        return (
                          <td key={m.id} className="cmp-diff">
                            {!d ? null : d.distinct ? (
                              <span className="small">Diseño distinto ({m.pieces} piezas)</span>
                            ) : !d.added.length && !d.removed.length && !d.changed.length ? (
                              <span className="muted small">Idéntica</span>
                            ) : (
                              <ul>
                                {d.added.slice(0, 6).map((x) => (
                                  <li key={`a${x}`} className="add">＋ {x}</li>
                                ))}
                                {d.removed.slice(0, 6).map((x) => (
                                  <li key={`r${x}`} className="rem">− {x}</li>
                                ))}
                                {d.changed.slice(0, 6).map((x) => (
                                  <li key={`c${x}`} className="chg">~ {x}</li>
                                ))}
                                {d.added.length + d.removed.length + d.changed.length > 18 && <li className="muted">…</li>}
                              </ul>
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  </>
                )}
                <tr className="cmp-actions">
                  <th />
                  {metrics.map((m) => (
                    <td key={m.id}>
                      {m.id !== activeVariant ? (
                        <button
                          className="btn small"
                          onClick={() => {
                            useStore.getState().switchVariant(m.id);
                            onClose();
                          }}
                        >
                          Editar esta variante
                        </button>
                      ) : (
                        <span className="muted small">Es la que estás editando</span>
                      )}
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {comparison && adr && winner && (
          <div className="cmp-adr">
            <div className="row between">
              <div>
                <b>Decisión: «{winner.name}»</b>
                <p className="muted small">El ADR solo lleva la decisión y su justificación con las cifras de esta comparación. Queda como «propuesta» para que el equipo lo apruebe.</p>
              </div>
              <div className="row gap">
                {aiConfigured && (
                  <button className="btn" onClick={draftWithAi} disabled={ai?.busy} title="Pedirle al asistente de IA que redacte el ADR con estos resultados">
                    {ai?.busy ? 'Redactando…' : '✨ Redactar con IA'}
                  </button>
                )}
                <button className="btn primary" onClick={() => saveAdr(adr)}>
                  Generar ADR
                </button>
              </div>
            </div>
            <details className="cmp-adr-preview">
              <summary className="small">Vista previa del ADR automático</summary>
              <pre>
                {`# ${adr.title}\n\n## Contexto\n${adr.context}\n\n## Decisión\n${adr.decision}\n\n## Consecuencias\n${adr.consequences}`}
              </pre>
            </details>
            {ai && (
              <div className="cmp-ai">
                {ai.error ? (
                  <p className="cmp-error">El asistente no respondió: {ai.error}</p>
                ) : (
                  <>
                    <pre>{ai.text || '…'}</pre>
                    {!ai.busy && ai.text && (
                      <div className="row gap">
                        <button
                          className="btn primary"
                          onClick={() => {
                            const p = parseAdr(ai.text);
                            saveAdr({ title: adr.title, context: p.context || adr.context, decision: p.decision || adr.decision, consequences: p.consequences || adr.consequences });
                          }}
                        >
                          Guardar ADR redactado por IA
                        </button>
                        <button className="btn" onClick={() => setAi(null)}>Descartar</button>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
