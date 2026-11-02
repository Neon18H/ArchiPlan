import { CATEGORIES } from '../catalog/catalog';
import type { ServiceDef } from '../types';

/** Ícono propio por categoría (sin depender de assets externos). */
export function ServiceIcon({ def, size = 32 }: { def: ServiceDef; size?: number }) {
  const color = CATEGORIES[def.category].color;
  const glyph = GLYPHS[def.role] ?? GLYPHS.compute;
  const isPerson = def.role === 'actor';
  return (
    <div className="svc-icon" style={{ width: size, height: size, background: isPerson ? '#eef0f3' : color, color: isPerson ? color : '#fff' }}>
      <svg viewBox="0 0 24 24" width={size * 0.5} height={size * 0.5} fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        {glyph}
      </svg>
      {!isPerson && <span className="svc-icon-short">{def.short}</span>}
    </div>
  );
}

const GLYPHS: Record<string, React.ReactNode> = {
  actor: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21c0-4 3.6-7 8-7s8 3 8 7" />
    </>
  ),
  external: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 9h18M8 14h3M14 14h2" />
    </>
  ),
  dns: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" />
    </>
  ),
  cdn: (
    <>
      <circle cx="12" cy="12" r="3" />
      <circle cx="4" cy="6" r="2" />
      <circle cx="20" cy="6" r="2" />
      <circle cx="4" cy="18" r="2" />
      <circle cx="20" cy="18" r="2" />
      <path d="M6 7l4 3M18 7l-4 3M6 17l4-3M18 17l-4-3" />
    </>
  ),
  waf: <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z M9 12l2 2 4-4" />,
  lb: (
    <>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="19" r="2.5" />
      <circle cx="12" cy="19" r="2.5" />
      <circle cx="19" cy="19" r="2.5" />
      <path d="M12 7.5v9M11 7l-5 10M13 7l5 10" />
    </>
  ),
  api: <path d="M8 4c-3 0-3 2-3 4s-2 4-2 4 2 2 2 4 0 4 3 4M16 4c3 0 3 2 3 4s2 4 2 4-2 2-2 4 0 4-3 4M10 12h4" />,
  compute: (
    <>
      <rect x="5" y="5" width="14" height="14" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
    </>
  ),
  registry: (
    <>
      <path d="M3 8l9-5 9 5-9 5z" />
      <path d="M3 8v8l9 5 9-5V8" />
    </>
  ),
  datastore: (
    <>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </>
  ),
  cache: <path d="M13 2L4 14h7l-1 8 9-12h-7z" />,
  storage: (
    <>
      <path d="M4 7l8-4 8 4-8 4z" />
      <path d="M4 12l8 4 8-4M4 17l8 4 8-4" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="M20 20l-4.5-4.5" />
    </>
  ),
  queue: (
    <>
      <rect x="2" y="8" width="5" height="8" rx="1" />
      <rect x="9.5" y="8" width="5" height="8" rx="1" />
      <rect x="17" y="8" width="5" height="8" rx="1" />
    </>
  ),
  topic: <path d="M4 10v4h3l6 4V6L7 10zM17 9a4 4 0 010 6M19.5 6.5a8 8 0 010 11" />,
  eventbus: (
    <>
      <path d="M2 12h20" />
      <circle cx="6" cy="12" r="2.2" />
      <circle cx="12" cy="12" r="2.2" />
      <circle cx="18" cy="12" r="2.2" />
      <path d="M6 9.8V5M12 14.2V19M18 9.8V5" />
    </>
  ),
  stream: <path d="M3 7c3-3 6 3 9 0s6 3 9 0M3 12c3-3 6 3 9 0s6 3 9 0M3 17c3-3 6 3 9 0s6 3 9 0" />,
  workflow: (
    <>
      <rect x="3" y="3" width="6" height="5" rx="1" />
      <rect x="15" y="9.5" width="6" height="5" rx="1" />
      <rect x="3" y="16" width="6" height="5" rx="1" />
      <path d="M9 5.5h3v13H9M12 12h3" />
    </>
  ),
  identity: (
    <>
      <circle cx="9" cy="10" r="3" />
      <path d="M4 18c0-2.5 2.2-4 5-4s5 1.5 5 4M15 8h6M15 12h6M17 16h4" />
    </>
  ),
  secrets: (
    <>
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 018 0v3M12 14v3" />
    </>
  ),
  kms: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M11 12l9-9M17 6l3 3M15 8l2 2" />
    </>
  ),
  cert: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <circle cx="12" cy="17" r="3" />
      <path d="M10.5 19.5L10 23l2-1 2 1-.5-3.5M7 8h10M7 11h6" />
    </>
  ),
  observability: <path d="M3 3v18h18M7 15l4-5 3 3 5-7" />,
  netgw: (
    <>
      <rect x="3" y="6" width="18" height="12" rx="2" />
      <path d="M8 12h8M13 9l3 3-3 3" />
    </>
  ),
  analytics: <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />,
  ai: (
    <>
      <path d="M12 3l1.8 4.6L18 9l-4.2 1.4L12 15l-1.8-4.6L6 9l4.2-1.4z" />
      <path d="M18 15l.9 2.1L21 18l-2.1.9L18 21l-.9-2.1L15 18l2.1-.9z" />
    </>
  ),
  devops: <path d="M17 2l4 4-4 4M3 11V9a3 3 0 013-3h15M7 22l-4-4 4-4M21 13v2a3 3 0 01-3 3H3" />,
};
