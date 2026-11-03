import { useState } from 'react';
import { useStore } from '../store';

/** Barra de variantes A/B sobre el lienzo: cambiar, renombrar, clonar y comparar. */
export function VariantBar({ onCompare }: { onCompare: () => void }) {
  const variants = useStore((s) => s.variants);
  const active = useStore((s) => s.activeVariant);
  const createVariant = useStore((s) => s.createVariant);
  const switchVariant = useStore((s) => s.switchVariant);
  const renameVariant = useStore((s) => s.renameVariant);
  const deleteVariant = useStore((s) => s.deleteVariant);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState('');

  const commit = () => {
    if (editing) renameVariant(editing, draft);
    setEditing(null);
  };

  return (
    <div className="variant-bar" role="toolbar" aria-label="Variantes del diseño">
      {!variants.length ? (
        <span className="vb-single" title="Clona el diseño para probar una alternativa (¿ECS o Lambda? ¿Aurora o DynamoDB?) y compáralas con las mismas pruebas">
          Diseño actual
        </span>
      ) : (
        variants.map((v) => (
          <span key={v.id} className={`vb-pill ${v.id === active ? 'on' : ''}`} title={v.note ? `${v.name} — ${v.note}` : v.name}>
            {editing === v.id ? (
              <input
                autoFocus
                aria-label="Nombre de la variante"
                value={draft}
                maxLength={40}
                onChange={(e) => setDraft(e.target.value)}
                onBlur={commit}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commit();
                  if (e.key === 'Escape') setEditing(null);
                }}
              />
            ) : (
              <button
                className="vb-name"
                onClick={() => switchVariant(v.id)}
                onDoubleClick={() => {
                  setDraft(v.name);
                  setEditing(v.id);
                }}
                aria-pressed={v.id === active}
              >
                {v.name}
              </button>
            )}
            {v.id === active && editing !== v.id && (
              <button
                className="vb-icon"
                title="Renombrar"
                aria-label={`Renombrar ${v.name}`}
                onClick={() => {
                  setDraft(v.name);
                  setEditing(v.id);
                }}
              >
                ✎
              </button>
            )}
            <button
              className="vb-icon"
              title="Eliminar variante"
              aria-label={`Eliminar ${v.name}`}
              onClick={() => {
                if (confirm(`¿Eliminar «${v.name}»? Sus cambios se pierden.`)) deleteVariant(v.id);
              }}
            >
              ×
            </button>
          </span>
        ))
      )}
      <button className="vb-add" onClick={() => createVariant()} title="Clonar el diseño actual como una nueva variante">
        ＋ Variante
      </button>
      {variants.length >= 2 && (
        <button className="vb-compare" onClick={onCompare} title="Correr las mismas pruebas a todas las variantes y compararlas">
          ⚖ Comparar
        </button>
      )}
    </div>
  );
}
