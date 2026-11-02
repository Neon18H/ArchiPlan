import { useMemo, useState } from 'react';
import { CATEGORIES, SERVICES, ZONES } from '../catalog/catalog';
import { useStore } from '../store';
import type { CategoryId, ZoneKind } from '../types';
import { DND_MIME } from './Canvas';
import { ServiceIcon } from './ServiceIcon';

const ZONE_ORDER: ZoneKind[] = ['region', 'vpc', 'subnet-public', 'subnet-private', 'subnet-data', 'boundary'];

export function Palette() {
  const [q, setQ] = useState('');
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const addService = useStore((s) => s.addService);
  const addZone = useStore((s) => s.addZone);
  const focus = useStore((s) => s.focus);
  const view = useStore((s) => s.view);

  const groups = useMemo(() => {
    const term = q.trim().toLowerCase();
    const list = SERVICES.filter((s) => !term || `${s.name} ${s.short} ${s.description} ${CATEGORIES[s.category].label}`.toLowerCase().includes(term));
    const g = new Map<CategoryId, typeof SERVICES>();
    for (const s of list) {
      if (!g.has(s.category)) g.set(s.category, []);
      g.get(s.category)!.push(s);
    }
    return [...g.entries()];
  }, [q]);

  const toggle = (k: string) => {
    const n = new Set(closed);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setClosed(n);
  };
  const disabled = view !== 'c2';

  return (
    <aside className="palette">
      <div className="palette-search">
        <input placeholder="Buscar pieza… (RDS, cola, cdn)" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="palette-scroll">
        {!q && (
          <section>
            <button className="pal-head" onClick={() => toggle('zones')}>
              <span>Zonas y red</span>
              <span className="chev">{closed.has('zones') ? '▸' : '▾'}</span>
            </button>
            {!closed.has('zones') && (
              <div className="pal-zones">
                {ZONE_ORDER.map((k) => (
                  <div
                    key={k}
                    className={`pal-zone ${disabled ? 'is-disabled' : ''}`}
                    style={{ ['--zc' as string]: ZONES[k].color }}
                    draggable={!disabled}
                    onDragStart={(e) => {
                      e.dataTransfer.setData(DND_MIME, JSON.stringify({ kind: 'zone', id: k }));
                      e.dataTransfer.effectAllowed = 'copy';
                    }}
                    onClick={() => !disabled && focus([addZone(k)])}
                    title={ZONES[k].help}
                  >
                    {ZONES[k].label}
                  </div>
                ))}
              </div>
            )}
          </section>
        )}
        {groups.map(([cat, items]) => (
          <section key={cat}>
            <button className="pal-head" onClick={() => toggle(cat)}>
              <span>
                <i className="dot" style={{ background: CATEGORIES[cat].color }} />
                {CATEGORIES[cat].label}
              </span>
              <span className="chev">{closed.has(cat) && !q ? '▸' : '▾'}</span>
            </button>
            {(!closed.has(cat) || q) &&
              items.map((s) => (
                <div
                  key={s.id}
                  className={`pal-item ${disabled ? 'is-disabled' : ''}`}
                  draggable={!disabled}
                  onDragStart={(e) => {
                    e.dataTransfer.setData(DND_MIME, JSON.stringify({ kind: 'service', id: s.id }));
                    e.dataTransfer.effectAllowed = 'copy';
                  }}
                  onDoubleClick={() => !disabled && focus([addService(s.id)])}
                  title={`${s.description}\n\nArrastra al lienzo o haz doble clic para ubicarla automáticamente.`}
                >
                  <ServiceIcon def={s} size={28} />
                  <div className="pal-text">
                    <div className="pal-name">{s.name}</div>
                    <div className="pal-desc">{s.description}</div>
                  </div>
                </div>
              ))}
          </section>
        ))}
        {groups.length === 0 && <div className="muted pad">Nada coincide con “{q}”.</div>}
      </div>
      <div className="palette-foot">Arrastra al lienzo · doble clic = ubicación automática</div>
    </aside>
  );
}
