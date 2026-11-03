import { useMemo, useState } from 'react';
import { SECURITY_GROUPS, SECURITY_SETTINGS } from '../security/settings';
import { useStore } from '../store';
import type { Threat } from '../threats/model';
import { Modal } from './Modals';
import { Switch } from './NetInspector';

export const openSecurity = () => window.dispatchEvent(new CustomEvent('archiplan:open', { detail: 'security' }));

/** Seguridad del proyecto: prácticas y guardrails que cumplen controles del modelo de amenazas. */
export function SecurityModal({ onClose, threats }: { onClose: () => void; threats: Threat[] }) {
  const security = useStore((s) => s.security);
  const setSecurity = useStore((s) => s.setSecurity);
  const [onlyUseful, setOnlyUseful] = useState(true);
  const usage = useMemo(() => {
    const m = new Map<string, { total: number; pending: number }>();
    for (const t of threats)
      for (const c of t.controls)
        for (const k of c.setting ?? []) {
          const u = m.get(k) ?? { total: 0, pending: 0 };
          u.total++;
          if (!c.ok && (t.status === 'abierta' || t.status === 'parcial')) u.pending++;
          m.set(k, u);
        }
    return m;
  }, [threats]);
  const on = SECURITY_SETTINGS.filter((s) => security[s.key]).length;
  return (
    <Modal title="Seguridad del proyecto" onClose={onClose} wide>
      <p className="muted small sec-intro">
        Prácticas y guardrails que no son una pieza del diagrama. Cada uno cumple controles del modelo de amenazas en todas las piezas a la vez, y los marcados con <b>Terraform</b> también se generan en el código exportado.
      </p>
      <div className="row between sec-toolbar">
        <span className="small">
          <b>{on}</b> de {SECURITY_SETTINGS.length} activos
        </span>
        <label className="toggle small">
          <input type="checkbox" checked={onlyUseful} onChange={(e) => setOnlyUseful(e.target.checked)} />
          <span>Solo los que aplican a este diagrama</span>
        </label>
      </div>
      <div className="sec-groups">
        {SECURITY_GROUPS.map((g) => {
          const items = SECURITY_SETTINGS.filter((s) => s.group === g.id && (!onlyUseful || usage.has(s.key) || security[s.key]));
          if (!items.length) return null;
          return (
            <section key={g.id} className="sec-group">
              <h3>
                {g.label} <span className="muted small">· {g.help}</span>
              </h3>
              {items.map((s) => {
                const u = usage.get(s.key);
                return (
                  <div key={s.key} className={`sec-row ${security[s.key] ? 'on' : ''}`}>
                    <Switch on={!!security[s.key]} onChange={(v) => setSecurity({ [s.key]: v })} label={s.label} />
                    <div className="sec-text">
                      <b>{s.label}</b>
                      <span>{s.help}</span>
                      <span className="sec-tags">
                        {u && (
                          <em className={u.pending && !security[s.key] ? 'pending' : ''}>
                            {u.pending && !security[s.key] ? `Cierra ${u.pending} control${u.pending > 1 ? 'es' : ''} pendiente${u.pending > 1 ? 's' : ''}` : `${u.total} control${u.total > 1 ? 'es' : ''} del modelo de amenazas`}
                          </em>
                        )}
                        {s.terraform && <em className="tf">Terraform: {s.terraform}</em>}
                      </span>
                    </div>
                  </div>
                );
              })}
            </section>
          );
        })}
      </div>
    </Modal>
  );
}
