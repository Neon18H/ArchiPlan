import { useEffect, useState } from 'react';
import { mitigationUrl, PROFILES, TACTIC_ID, techUrl, type AttackControl, type AttackFix, type AttackProfile } from '../attack/paths';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import type { ServiceNode } from '../types';
import { ModeSwitch } from './RequestPanel';

export function applyAttackFix(fix: AttackFix) {
  const st = useStore.getState();
  if (fix.security) st.setSecurity({ [fix.security]: true });
  if (fix.nodeId && fix.props) st.updateNode(fix.nodeId, { props: fix.props });
  st.toast('ok', `Aplicado: ${fix.label}. Las rutas se recalculan.`);
}

const pct = (v: number) => `${v >= 0.1 ? Math.round(v * 100) : (v * 100).toFixed(1)} %`;

export function AttackPanel() {
  const { attack, attackSel, attackStep, selectAttack, setAttackStep, runAttack, setOpen } = useSim();
  const nodes = useStore((s) => s.nodes);
  const focus = useStore((s) => s.focus);
  const label = (id: string) => (nodes.find((n) => n.id === id) as ServiceNode | undefined)?.data.label ?? (id === 'internet' ? 'Internet' : id);
  const path = attack?.paths[attackSel];
  const [profile, setProfile] = useState<AttackProfile | 'todos'>('todos');
  const visible = (attack?.paths ?? []).map((p, i) => ({ p, i })).filter(({ p }) => profile === 'todos' || p.profile === profile);

  // Animación salto a salto
  useEffect(() => {
    if (!path || attackStep >= path.steps.length) return;
    const id = setTimeout(() => setAttackStep(attackStep + 1), 900);
    return () => clearTimeout(id);
  }, [path, attackStep, setAttackStep]);

  const counts = { Crítico: 0, Alto: 0, Medio: 0, Bajo: 0 };
  for (const p of attack?.paths ?? []) counts[p.risk]++;

  // Controles de la ruta (sin repetir), los que faltan primero
  const controls = new Map<string, AttackControl & { steps: number[] }>();
  path?.steps.forEach((s, i) =>
    s.controls.forEach((c) => {
      const cur = controls.get(c.label);
      if (cur) cur.steps.push(i + 1);
      else controls.set(c.label, { ...c, steps: [i + 1] });
    }),
  );
  const ctrlList = [...controls.values()].sort((a, b) => Number(a.ok) - Number(b.ok) || a.factor - b.factor);

  return (
    <section className="simpanel attack-panel" aria-label="Rutas de ataque">
      <div className="sim-config">
        <div className="sim-head">
          <ModeSwitch />
          <button className="x" onClick={() => setOpen(false)} aria-label="Cerrar simulación">
            ×
          </button>
        </div>
        <p className="sim-desc">
          Cómo llegaría un atacante desde Internet a los datos más valiosos, salto a salto, con cada técnica de <b>MITRE ATT&amp;CK</b> y los controles que la frenan.
        </p>
        {attack && (
          <div className="atk-counts">
            {(['Crítico', 'Alto', 'Medio', 'Bajo'] as const).map((r) => (
              <span key={r} className={`atk-risk r-${r}`}>
                {counts[r]} {r.toLowerCase()}
              </span>
            ))}
          </div>
        )}
        <div className="atk-profiles" role="radiogroup" aria-label="Perfil del atacante">
          {[{ id: 'todos', label: 'Todos', help: 'Todas las rutas' }, ...PROFILES].map((pr) => {
            const n = pr.id === 'todos' ? attack?.paths.length ?? 0 : attack?.paths.filter((p) => p.profile === pr.id).length ?? 0;
            return (
              <button
                key={pr.id}
                role="radio"
                aria-checked={profile === pr.id}
                className={profile === pr.id ? 'on' : ''}
                title={pr.help}
                disabled={!n}
                onClick={() => {
                  setProfile(pr.id as AttackProfile | 'todos');
                  const first = attack?.paths.findIndex((p) => pr.id === 'todos' || p.profile === pr.id) ?? -1;
                  if (first >= 0) selectAttack(first);
                }}
              >
                {pr.label} <em>{n}</em>
              </button>
            );
          })}
        </div>
        <div className="atk-list" role="listbox" aria-label="Rutas encontradas">
          {visible.map(({ p, i }) => (
            <button key={p.id} role="option" aria-selected={i === attackSel} className={`atk-item ${i === attackSel ? 'on' : ''}`} onClick={() => selectAttack(i)}>
              <span className={`atk-risk r-${p.risk}`}>{p.risk}</span>
              <b>{p.targetLabel}</b>
              <span className="muted small">
                {p.steps.length} salto{p.steps.length > 1 ? 's' : ''} · {pct(p.likelihood)} · {p.profile === 'externo' ? `entra por ${label(p.steps[0].to)}` : PROFILES.find((x) => x.id === p.profile)?.label}
              </span>
            </button>
          ))}
          {attack && !attack.paths.length && <div className="muted small pad">No se encontró ninguna ruta desde Internet hasta los datos.</div>}
        </div>
        {attack && attack.safeTargets.length > 0 && <p className="sim-disclaimer">Sin ruta desde Internet: {attack.safeTargets.map(label).join(', ')}.</p>}
        <p className="sim-disclaimer">Modelo cualitativo para priorizar defensas; no reemplaza una prueba de penetración.</p>
      </div>

      <div className="sim-main atk-main">
        {path ? (
          <>
            <div className="atk-title">
              <b>{path.title}</b>
              <span className={`atk-risk r-${path.risk}`}>Riesgo {path.risk.toLowerCase()}</span>
              <span className="muted small">probabilidad estimada {pct(path.likelihood)} · valor {path.value}/5</span>
            </div>
            <div className="atk-transport">
              <button className="btn small primary" onClick={() => setAttackStep(attackStep >= path.steps.length ? 1 : attackStep + 1)}>
                {attackStep >= path.steps.length ? '↻ Repetir' : 'Siguiente salto ›'}
              </button>
              <button className="btn small" onClick={() => setAttackStep(path.steps.length)}>
                Ver completa
              </button>
              <button className="btn small" onClick={() => runAttack(true)} title="Recalcular las rutas">
                ⟳
              </button>
            </div>
            <ol className="atk-steps">
              {path.steps.slice(0, attackStep).map((s, i) => (
                <li key={i} className={`atk-step ${i === attackStep - 1 ? 'current' : ''}`}>
                  <span className="atk-n">{i + 1}</span>
                  <div>
                    <div className="atk-step-head">
                      <span className="atk-tactic" title={`Táctica ${TACTIC_ID[s.tactic]}`}>
                        {s.tactic}
                      </span>
                      {s.extra?.map((x) => (
                        <a key={x.id} className="atk-tech" href={techUrl(x.id)} target="_blank" rel="noreferrer" title={x.name}>
                          {x.id} · {x.name}
                        </a>
                      ))}
                      {s.technique ? (
                        <a className="atk-tech" href={techUrl(s.technique.id)} target="_blank" rel="noreferrer" title={s.technique.name}>
                          {s.technique.id} · {s.technique.name}
                        </a>
                      ) : (
                        <span className="atk-tech pass">en tránsito</span>
                      )}
                      <span className={`atk-lk ${s.likelihood >= 0.5 ? 'hi' : s.likelihood >= 0.2 ? 'mid' : 'lo'}`}>{pct(s.likelihood)}</span>
                    </div>
                    <button className="linklike atk-hop" onClick={() => focus([s.from, s.to])}>
                      {label(s.from)} → <b>{label(s.to)}</b>
                      {s.virtual && <em> (sin flecha en el diagrama)</em>}
                    </button>
                    <p>{s.how}</p>
                  </div>
                </li>
              ))}
            </ol>
          </>
        ) : (
          <div className="muted pad">Agrega actores, puntos de entrada y datos para ver las rutas de ataque.</div>
        )}
      </div>

      <div className="sim-results atk-results">
        {path && (
          <>
            {path.bestCut ? (
              <div className="atk-cut">
                <span>Cómo cortar esta ruta</span>
                <b>{path.bestCut.control.label}</b>
                <em>
                  En el salto {path.bestCut.step + 1}: la probabilidad baja de {pct(path.likelihood)} a {pct(path.bestCut.after)}.
                </em>
                {path.bestCut.control.fix && (
                  <button className="btn small primary" onClick={() => applyAttackFix(path.bestCut!.control.fix!)}>
                    ⚡ {path.bestCut.control.fix.label}
                  </button>
                )}
              </div>
            ) : (
              <div className="atk-cut ok">
                <span>Sin arreglos automáticos</span>
                <em>Los controles de esta ruta ya están, o dependen del diseño (separar redes, quitar la flecha, cambiar el servicio).</em>
              </div>
            )}
            {path.impacts.length > 0 && (
              <>
                <div className="atk-ctrls-title">Qué podría hacer al llegar</div>
                <ul className="atk-ctrls atk-impacts">
                  {path.impacts.map((im) => (
                    <li key={im.technique.id + im.label} className={im.ok ? 'ok' : 'missing'}>
                      <span className="atk-ok">{im.ok ? '✓' : '✗'}</span>
                      <div>
                        <span>
                          {im.label}{' '}
                          <a href={techUrl(im.technique.id)} target="_blank" rel="noreferrer" className="atk-m">
                            {im.technique.id}
                          </a>
                        </span>
                        <em>{im.control}</em>
                        {!im.ok && im.fix && (
                          <button className="btn small fix" onClick={() => applyAttackFix(im.fix!)}>
                            ⚡ {im.fix.label}
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            )}
            <div className="atk-ctrls-title">Mitigaciones de la ruta (MITRE)</div>
            <ul className="atk-ctrls">
              {ctrlList.map((c) => (
                <li key={c.label} className={c.ok ? 'ok' : 'missing'}>
                  <span className="atk-ok">{c.ok ? '✓' : '✗'}</span>
                  <div>
                    <span>
                      {c.label}{' '}
                      <a href={mitigationUrl(c.mitigation)} target="_blank" rel="noreferrer" className="atk-m">
                        {c.mitigation}
                      </a>
                    </span>
                    <em>
                      salto {c.steps.join(', ')}
                      {!c.ok ? ` · ×${c.factor} la probabilidad` : ''}
                    </em>
                    {!c.ok && c.fix && (
                      <button className="btn small fix" onClick={() => applyAttackFix(c.fix!)}>
                        ⚡ {c.fix.label}
                      </button>
                    )}
                  </div>
                </li>
              ))}
              {!ctrlList.length && <li className="muted small">Ningún control aplica a estos saltos.</li>}
            </ul>
          </>
        )}
      </div>
    </section>
  );
}
