import { useEffect, useMemo, useRef, useState } from 'react';
import { useReactFlow } from '@xyflow/react';
import { getService } from '../catalog/catalog';
import { download, captureDiagram, diagramToPdf, downloadDataUrl } from '../export/image';
import { toMarkdown, toHtmlDoc } from '../export/doc';
import { toMermaid } from '../export/mermaid';
import { toTerraform } from '../export/terraform';
import { deleteProjectFile, isProject, listProjects, loadProjectFile, serverAvailable, slugify, type ProjectListItem } from '../lib/api';
import { useStore } from '../store';
import { TEMPLATES } from '../templates/templates';
import { COMPUTE_INFO, DEFAULT_ANSWERS, generateFromAnswers, type WizardAnswers } from '../templates/wizard';
import { ServiceIcon } from './ServiceIcon';

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-label={title}>
        <header>
          <h2>{title}</h2>
          <button className="x" onClick={onClose} aria-label="Cerrar">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

const confirmReplace = () => {
  const st = useStore.getState();
  return st.nodes.length === 0 || !st.dirty || window.confirm('Se reemplazará el diagrama actual (podrás deshacer con Ctrl+Z). ¿Continuar?');
};

/* ───────────────────────── Plantillas */

export function TemplatesModal({ onClose }: { onClose: () => void }) {
  const loadSpec = useStore((s) => s.loadSpec);
  return (
    <Modal title="Plantillas de patrones" onClose={onClose} wide>
      <p className="muted">Arranca desde un patrón probado y adáptalo. Todas pasan las reglas de conexión.</p>
      <div className="tpl-grid">
        {TEMPLATES.map((t) => {
          const ids = [...new Set(t.spec.services.map((s) => s.serviceId))].filter((id) => !['user', 'admin'].includes(id)).slice(0, 8);
          return (
            <button
              key={t.id}
              className="tpl"
              onClick={() => {
                if (!confirmReplace()) return;
                loadSpec(t.spec, { name: t.name, description: t.description }, t.decisions);
                onClose();
              }}
            >
              <div className="tpl-name">{t.name}</div>
              <div className="tpl-desc">{t.description}</div>
              <div className="tpl-icons">
                {ids.map((id) => (
                  <ServiceIcon key={id} def={getService(id)} size={24} />
                ))}
              </div>
              <div className="tpl-tags">
                {t.tags.map((x) => (
                  <span key={x}>{x}</span>
                ))}
              </div>
            </button>
          );
        })}
      </div>
    </Modal>
  );
}

/* ───────────────────────── Asistente guiado */

type Q =
  | { key: keyof WizardAnswers; q: string; help?: string; type: 'choice'; options: { v: string; label: string; desc: string }[] }
  | { key: keyof WizardAnswers; q: string; help?: string; type: 'bool' }
  | { key: keyof WizardAnswers; q: string; help?: string; type: 'text'; placeholder?: string };

const QUESTIONS: Q[] = [
  { key: 'name', q: '¿Cómo se llama la solución?', type: 'text', placeholder: 'Ej.: Plataforma de pedidos' },
  {
    key: 'kind',
    q: '¿Qué tipo de solución es?',
    type: 'choice',
    options: [
      { v: 'web', label: 'Aplicación web', desc: 'Frontend + backend + base de datos' },
      { v: 'api', label: 'API / backend móvil', desc: 'Servicios consumidos por apps o terceros' },
      { v: 'eventos', label: 'Procesamiento por eventos', desc: 'Flujos asíncronos entre servicios' },
      { v: 'datos', label: 'Datos y analítica', desc: 'Ingesta, data lake, BI' },
      { v: 'estatico', label: 'Sitio estático / SPA', desc: 'Solo contenido estático' },
    ],
  },
  {
    key: 'compute',
    q: '¿Cómo prefieres ejecutar la lógica?',
    type: 'choice',
    options: (Object.keys(COMPUTE_INFO) as WizardAnswers['compute'][]).map((k) => ({ v: k, label: COMPUTE_INFO[k].label, desc: COMPUTE_INFO[k].why })),
  },
  {
    key: 'data',
    q: '¿Qué tipo de datos maneja?',
    type: 'choice',
    options: [
      { v: 'relacional', label: 'Relacional', desc: 'Transacciones, joins, reportes (PostgreSQL/MySQL)' },
      { v: 'nosql', label: 'NoSQL', desc: 'Acceso por clave, alto volumen (DynamoDB)' },
      { v: 'ambos', label: 'Ambos', desc: 'Relacional + NoSQL' },
      { v: 'ninguno', label: 'Ninguno', desc: 'Sin persistencia propia' },
    ],
  },
  { key: 'auth', q: '¿Los usuarios inician sesión?', help: 'Agrega un proveedor de identidad (Cognito / OIDC).', type: 'bool' },
  { key: 'cdn', q: '¿Tiene usuarios en varias regiones o mucho contenido estático?', help: 'Agrega CloudFront delante.', type: 'bool' },
  { key: 'async', q: '¿Hay tareas pesadas que no deban bloquear al usuario?', help: 'Correos, reportes, pagos, procesamiento de archivos…', type: 'bool' },
  { key: 'cache', q: '¿Necesita caché para lecturas frecuentes o sesiones?', type: 'bool' },
  { key: 'files', q: '¿Guarda archivos (imágenes, documentos, adjuntos)?', type: 'bool' },
  { key: 'external', q: '¿Se integra con sistemas externos (pagos, ERP, APIs de terceros)?', type: 'bool' },
  { key: 'ai', q: '¿Usa IA generativa (LLM)?', type: 'bool' },
  { key: 'ha', q: '¿Requiere alta disponibilidad (Multi‑AZ)?', help: 'Producción crítica: sí. Prototipo o interno: puede ser no.', type: 'bool' },
  { key: 'region', q: '¿En qué región de AWS?', type: 'text', placeholder: 'us-east-1' },
];

export function WizardModal({ onClose }: { onClose: () => void }) {
  const [a, setA] = useState<WizardAnswers>(DEFAULT_ANSWERS);
  const [i, setI] = useState(0);
  const loadSpec = useStore((s) => s.loadSpec);
  const visible = QUESTIONS.filter((q) => !(a.kind === 'estatico' && ['compute', 'data', 'auth', 'cdn', 'async', 'cache', 'files', 'external', 'ai'].includes(q.key)));
  const q = visible[Math.min(i, visible.length - 1)];
  const last = i >= visible.length - 1;
  const preview = useMemo(() => generateFromAnswers(a), [a]);
  const pieces = useMemo(() => {
    const ids = preview.spec.services.map((s) => s.serviceId);
    return [...new Set(ids)];
  }, [preview]);

  const finish = () => {
    if (!confirmReplace()) return;
    loadSpec(preview.spec, { name: a.name, description: '', region: a.region }, preview.decisions);
    onClose();
  };
  const set = (k: keyof WizardAnswers, v: unknown) => setA({ ...a, [k]: v } as WizardAnswers);
  const next = () => (last ? finish() : setI(i + 1));

  return (
    <Modal title="Asistente de arquitectura" onClose={onClose} wide>
      <div className="wizard">
        <div className="wiz-left">
          <div className="wiz-steps">
            {visible.map((x, k) => (
              <button key={x.key} className={`wiz-dot ${k === i ? 'on' : ''} ${k < i ? 'done' : ''}`} onClick={() => setI(k)} title={x.q} />
            ))}
          </div>
          <div className="wiz-count">
            Pregunta {i + 1} de {visible.length}
          </div>
          <h3 className="wiz-q">{q.q}</h3>
          {q.help && <p className="muted">{q.help}</p>}
          {q.type === 'text' && (
            <input className="wiz-input" autoFocus placeholder={q.placeholder} value={String(a[q.key])} onChange={(e) => set(q.key, e.target.value)} onKeyDown={(e) => e.key === 'Enter' && next()} />
          )}
          {q.type === 'bool' && (
            <div className="wiz-options two">
              {[true, false].map((v) => (
                <button
                  key={String(v)}
                  className={`wiz-opt ${a[q.key] === v ? 'on' : ''}`}
                  onClick={() => {
                    set(q.key, v);
                    setTimeout(() => setI((x) => Math.min(x + 1, visible.length - 1)), 120);
                  }}
                >
                  <b>{v ? 'Sí' : 'No'}</b>
                </button>
              ))}
            </div>
          )}
          {q.type === 'choice' && (
            <div className="wiz-options">
              {q.options.map((o) => (
                <button
                  key={o.v}
                  className={`wiz-opt ${a[q.key] === o.v ? 'on' : ''}`}
                  onClick={() => {
                    set(q.key, o.v);
                    setTimeout(() => setI((x) => Math.min(x + 1, visible.length - 1)), 120);
                  }}
                >
                  <b>{o.label}</b>
                  <span>{o.desc}</span>
                </button>
              ))}
            </div>
          )}
          <div className="wiz-nav">
            <button className="btn" disabled={i === 0} onClick={() => setI(i - 1)}>
              Atrás
            </button>
            <button className="btn primary" onClick={next}>
              {last ? 'Generar arquitectura' : 'Siguiente'}
            </button>
          </div>
        </div>
        <div className="wiz-right">
          <div className="wiz-prev-title">Vista previa ({preview.spec.services.length} piezas)</div>
          <div className="wiz-pieces">
            {pieces.map((id) => (
              <div key={id} className="wiz-piece">
                <ServiceIcon def={getService(id)} size={22} />
                <span>{getService(id).name.replace(/^(Amazon|AWS) /, '')}</span>
              </div>
            ))}
          </div>
          {preview.decisions.length > 0 && (
            <>
              <div className="wiz-prev-title">Decisiones que se registrarán</div>
              <ul className="wiz-adrs">
                {preview.decisions.map((d) => (
                  <li key={d.title}>{d.title}</li>
                ))}
              </ul>
            </>
          )}
          <button className="btn primary block" onClick={finish}>
            Generar ahora
          </button>
        </div>
      </div>
    </Modal>
  );
}

/* ───────────────────────── Abrir proyectos */

export function ProjectsModal({ onClose }: { onClose: () => void }) {
  const [list, setList] = useState<ProjectListItem[] | null>(null);
  const [server, setServer] = useState<boolean | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const { loadProject, toast } = useStore.getState();

  const refresh = async () => {
    const ok = await serverAvailable();
    setServer(ok);
    if (ok) setList(await listProjects().catch(() => []));
  };
  useEffect(() => {
    refresh();
  }, []);

  const open = async (id: string) => {
    if (!confirmReplace()) return;
    try {
      const p = await loadProjectFile(id);
      loadProject(p, id);
      toast('ok', `Abierto: ${p.meta.name}`);
      onClose();
    } catch (e) {
      toast('error', String((e as Error).message));
    }
  };
  const importFile = async (f: File) => {
    try {
      const data = JSON.parse(await f.text());
      if (!isProject(data)) throw new Error('El archivo no es un proyecto de ArchiPlan');
      if (!confirmReplace()) return;
      loadProject(data, null);
      toast('ok', `Importado: ${data.meta.name}`);
      onClose();
    } catch (e) {
      toast('error', String((e as Error).message));
    }
  };

  return (
    <Modal title="Abrir proyecto" onClose={onClose}>
      <div className="row gap" style={{ marginBottom: 14 }}>
        <button className="btn" onClick={() => fileRef.current?.click()}>
          Importar archivo .json…
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) importFile(f);
            e.target.value = '';
          }}
        />
      </div>
      {server === false && <p className="muted">El servidor local no responde: solo puedes importar archivos. Inicia la app con <code>npm run dev</code> o <code>npm run serve</code>.</p>}
      {server && list && list.length === 0 && <p className="muted">Aún no hay proyectos guardados en la carpeta <code>projects/</code>.</p>}
      {server && list && list.length > 0 && (
        <div className="proj-list">
          {list.map((p) => (
            <div key={p.id} className="proj">
              <button className="proj-open" onClick={() => open(p.id)}>
                <b>{p.name}</b>
                <span className="muted small">
                  {p.id}.archi.json · {p.nodes} elementos · {new Date(p.updatedAt).toLocaleString('es-CO')}
                </span>
              </button>
              <button
                className="btn small danger"
                onClick={async () => {
                  if (!window.confirm(`¿Eliminar "${p.name}" del disco?`)) return;
                  await deleteProjectFile(p.id);
                  refresh();
                }}
              >
                Eliminar
              </button>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}

/* ───────────────────────── Exportar */

type CodeKind = 'mermaid' | 'terraform' | 'markdown' | 'json';

export function ExportModal({ onClose }: { onClose: () => void }) {
  const rf = useReactFlow();
  const [busy, setBusy] = useState<string | null>(null);
  const [code, setCode] = useState<CodeKind | null>(null);
  const st = useStore.getState();
  const project = st.toProject();
  const base = slugify(project.meta.name);
  const view = useStore((s) => s.view);

  const bounds = () => rf.getNodesBounds(rf.getNodes());
  const run = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (e) {
      st.toast('error', `No se pudo exportar: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };
  const texts: Record<CodeKind, { label: string; file: string; mime: string; text: () => string }> = {
    mermaid: { label: 'Mermaid', file: `${base}.mmd`, mime: 'text/plain', text: () => toMermaid(project.nodes, project.edges, project.meta.name) },
    terraform: { label: 'Terraform', file: `main.tf`, mime: 'text/plain', text: () => toTerraform(project.nodes, project.edges, project.meta) },
    markdown: { label: 'Documento (Markdown)', file: `${base}-arquitectura.md`, mime: 'text/markdown', text: () => toMarkdown(project, `${base}.png`) },
    json: { label: 'Proyecto JSON', file: `${base}.archi.json`, mime: 'application/json', text: () => JSON.stringify(project, null, 2) },
  };

  if (code) {
    const t = texts[code];
    const text = t.text();
    return (
      <Modal title={t.label} onClose={onClose} wide>
        <div className="row gap" style={{ marginBottom: 10 }}>
          <button className="btn" onClick={() => setCode(null)}>
            ← Volver
          </button>
          <span style={{ flex: 1 }} />
          <button
            className="btn"
            onClick={async () => {
              await navigator.clipboard.writeText(text);
              st.toast('ok', 'Copiado al portapapeles');
            }}
          >
            Copiar
          </button>
          <button className="btn primary" onClick={() => download(t.file, text, t.mime)}>
            Descargar {t.file}
          </button>
        </div>
        {code === 'mermaid' && (
          <p className="muted small">
            Pégalo en GitHub, GitLab, Notion o <code>mermaid.live</code>: se renderiza como diagrama.
          </p>
        )}
        {code === 'terraform' && <p className="muted small">Esqueleto con red, security groups derivados de las flechas, IAM de mínimo privilegio y TODOs. Revísalo antes de aplicar.</p>}
        <pre className="code">{text}</pre>
      </Modal>
    );
  }

  const items: { key: string; title: string; desc: string; act: () => void }[] = [
    {
      key: 'png',
      title: 'Imagen PNG',
      desc: 'Todo el diagrama en alta resolución.',
      act: () => run('png', async () => downloadDataUrl(`${base}.png`, await captureDiagram(bounds(), 'png'))),
    },
    {
      key: 'svg',
      title: 'Imagen SVG',
      desc: 'Vectorial, ideal para presentaciones.',
      act: () => run('svg', async () => downloadDataUrl(`${base}.svg`, await captureDiagram(bounds(), 'svg'))),
    },
    {
      key: 'pdf',
      title: 'PDF del diagrama',
      desc: 'A3 con título, listo para imprimir.',
      act: () =>
        run('pdf', async () => {
          const png = await captureDiagram(bounds(), 'png');
          const blob = await diagramToPdf(png, project.meta.name, `${project.meta.environment} · AWS ${project.meta.region} · ${new Date().toLocaleDateString('es-CO')}`);
          download(`${base}.pdf`, blob);
        }),
    },
    {
      key: 'doc',
      title: 'Documento de arquitectura',
      desc: 'HTML con diagrama, componentes, flujos, ADR y riesgos. Imprímelo como PDF.',
      act: () =>
        run('doc', async () => {
          const png = await captureDiagram(bounds(), 'png', 1.5);
          const html = toHtmlDoc(project, png);
          download(`${base}-arquitectura.html`, html, 'text/html;charset=utf-8');
        }),
    },
    { key: 'markdown', title: 'Documento en Markdown', desc: 'Para el repositorio o la wiki (Confluence, GitHub).', act: () => setCode('markdown') },
    { key: 'mermaid', title: 'Mermaid', desc: 'Diagrama como código, versionable en git.', act: () => setCode('mermaid') },
    { key: 'terraform', title: 'Terraform', desc: 'Esqueleto de infraestructura AWS.', act: () => setCode('terraform') },
    { key: 'json', title: 'Proyecto JSON', desc: 'Archivo para compartir, versionar o reabrir.', act: () => setCode('json') },
  ];
  return (
    <Modal title="Exportar" onClose={onClose}>
      {view === 'c1' && <p className="muted small">Las imágenes se exportan con la vista actual (C1). Cambia a C2 para el detalle completo.</p>}
      <div className="export-grid">
        {items.map((it) => (
          <button key={it.key} className="export-item" disabled={!!busy} onClick={it.act}>
            <b>{busy === it.key ? 'Generando…' : it.title}</b>
            <span>{it.desc}</span>
          </button>
        ))}
      </div>
    </Modal>
  );
}

