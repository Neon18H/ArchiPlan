import { useMemo, useState } from 'react';
import { CATEGORIES, CLOUD_LABEL, SERVICES, zoneLabel, ZONES } from '../catalog/catalog';
import { useCloud } from '../lib/useCloud';
import type { Cloud } from '../types';
import { useStore } from '../store';
import type { CategoryId, ZoneKind } from '../types';
import { DND_MIME } from './Canvas';
import { ServiceIcon } from './ServiceIcon';
import { COMPONENT_KINDS } from '../c3/model';
import type { ComponentKind } from '../types';

const ZONE_ORDER: ZoneKind[] = ['region', 'vpc', 'subnet-public', 'subnet-private', 'subnet-data', 'boundary'];

export function Palette() {
  const [q, setQ] = useState('');
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const addService = useStore((s) => s.addService);
  const addZone = useStore((s) => s.addZone);
  const focus = useStore((s) => s.focus);
  const view = useStore((s) => s.view);
  const diagramCloud = useCloud();
  const [picked, setPicked] = useState<Cloud | null>(null);
  const cloud = picked ?? diagramCloud;

  const groups = useMemo(() => {
    const term = q.trim().toLowerCase();
    const list = SERVICES.filter((s) => (s.provider === 'generic' || s.provider === cloud) && (!term || `${s.name} ${s.short} ${s.description} ${CATEGORIES[s.category].label} ${s.equiv ?? ''}`.toLowerCase().includes(term)));
    const g = new Map<CategoryId, typeof SERVICES>();
    for (const s of list) {
      if (!g.has(s.category)) g.set(s.category, []);
      g.get(s.category)!.push(s);
    }
    return [...g.entries()];
  }, [q, cloud]);

  const toggle = (k: string) => {
    const n = new Set(closed);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setClosed(n);
  };
  const disabled = view !== 'c2';

  if (view === 'c3') {
    return (
      <aside className="palette">
        <div className="palette-search">
          <div className="pal-c3-title">Componentes (C4 · nivel 3)</div>
          <div className="muted small">Módulos internos del servicio. Arrástralos dentro del contenedor y conéctalos con sus dependencias.</div>
        </div>
        <div className="palette-scroll">
          {(Object.keys(COMPONENT_KINDS) as ComponentKind[]).map((k) => (
            <div
              key={k}
              className="pal-item"
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData(DND_MIME, JSON.stringify({ kind: 'component', id: k }));
                e.dataTransfer.effectAllowed = 'copy';
              }}
              onDoubleClick={() => window.dispatchEvent(new CustomEvent('archiplan:c3add', { detail: k }))}
              title={`${COMPONENT_KINDS[k].help}\n\nArrastra al lienzo o haz doble clic.`}
            >
              <div className="c3-kind-chip" style={{ background: COMPONENT_KINDS[k].color }}>
                {COMPONENT_KINDS[k].short}
              </div>
              <div className="pal-text">
                <div className="pal-name">{COMPONENT_KINDS[k].label}</div>
                <div className="pal-desc">{COMPONENT_KINDS[k].help}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="palette-foot">Arrastra al contenedor · doble clic para agregar</div>
      </aside>
    );
  }

  return (
    <aside className="palette">
      <div className="palette-search">
        <div className="cloud-tabs" role="tablist" aria-label="Nube">
          {(['aws', 'azure'] as Cloud[]).map((c) => (
            <button key={c} role="tab" aria-selected={cloud === c} className={`${cloud === c ? 'on' : ''} c-${c}`} onClick={() => setPicked(c)}>
              {CLOUD_LABEL[c]}
            </button>
          ))}
        </div>
        <input placeholder={cloud === 'azure' ? 'Buscar pieza… (Cosmos, cola, front door)' : 'Buscar pieza… (RDS, cola, cdn)'} value={q} onChange={(e) => setQ(e.target.value)} />
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
                    {zoneLabel(k, cloud)}
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
