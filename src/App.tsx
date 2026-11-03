import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ReactFlowProvider } from '@xyflow/react';
import { getService, LAYERS } from './catalog/catalog';
import { Canvas } from './components/Canvas';
import { C3Canvas } from './components/C3Canvas';
import { c3Eligible } from './c3/model';
import { CanvasContext } from './components/context';
import { ExportModal, ProjectsModal, TemplatesModal, WizardModal } from './components/Modals';
import { Palette } from './components/Palette';
import { Sidebar } from './components/Sidebar';
import { SimPanel } from './components/SimPanel';
import { SecurityModal } from './components/SecurityPanel';
import { AiButton, AiPanel, AiWatcher } from './components/AiPanel';
import { NetLegend, NetModal, netViewData, useNetUi } from './components/NetInspector';
import { useSim } from './sim/store';
import { buildThreats } from './threats/model';
import { useThreatsUi } from './threats/ui';
import { useCloud } from './lib/useCloud';
import { download } from './export/image';
import { isService } from './lib/graph';
import { saveProjectFile, serverAvailable, slugify } from './lib/api';
import { buildGuide } from './rules/guide';
import { validate } from './rules/validate';
import { analyzeNetwork } from './net/reach';
import { netIssues } from './net/issues';
import { traceOverlay } from './net/trace';
import { useStore } from './store';
import type { Layer, Severity } from './types';

type ModalKind = 'templates' | 'wizard' | 'projects' | 'export' | 'net' | 'security' | 'ai' | null;

function Menu({ label, children }: { label: React.ReactNode; children: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    window.addEventListener('mousedown', h);
    return () => window.removeEventListener('mousedown', h);
  }, [open]);
  return (
    <div className="menu" ref={ref}>
      <button className={`tb-btn ${open ? 'on' : ''}`} onClick={() => setOpen(!open)}>
        {label} <span className="caret">▾</span>
      </button>
      {open && <div className="menu-pop">{children(() => setOpen(false))}</div>}
    </div>
  );
}

function Toolbar({ openModal, onSave, issuesCount }: { openModal: (m: ModalKind) => void; onSave: () => void; issuesCount: Record<Severity, number> }) {
  const meta = useStore((s) => s.meta);
  const dirty = useStore((s) => s.dirty);
  const view = useStore((s) => s.view);
  const layers = useStore((s) => s.layers);
  const past = useStore((s) => s.past.length);
  const future = useStore((s) => s.future.length);
  const { setMeta, undo, redo, setView, toggleLayer, clearLayers, autoLayout, newEmpty } = useStore.getState();
  const c3Ready = useStore((s) => !!s.c3Id || s.nodes.some((n) => n.selected && c3Eligible(n)));

  return (
    <header className="toolbar">
      <div className="brand">
        <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden>
          <rect width="32" height="32" rx="7" fill="#e8590c" />
          <path d="M8 22h16M10 22V12h4v10M18 22V8h4v14" stroke="#fff" strokeWidth="2.4" fill="none" />
        </svg>
        <span className="wide-only">ArchiPlan</span>
      </div>
      <input className="proj-name" value={meta.name} onChange={(e) => setMeta({ name: e.target.value })} aria-label="Nombre del proyecto" />
      {dirty && <span className="dirty" title="Cambios sin guardar en disco">●</span>}

      <div className="tb-group">
        <Menu label="Nuevo">
          {(close) => (
            <>
              <button onClick={() => (close(), openModal('wizard'))}>
                <b>Asistente guiado</b>
                <span>Responde preguntas y genera la arquitectura</span>
              </button>
              <button onClick={() => (close(), openModal('templates'))}>
                <b>Desde plantilla</b>
                <span>3 capas, serverless, microservicios, eventos…</span>
              </button>
              <button
                onClick={() => {
                  close();
                  const st = useStore.getState();
                  if (st.nodes.length && st.dirty && !window.confirm('¿Descartar el diagrama actual? (Ctrl+Z para deshacer)')) return;
                  newEmpty();
                }}
              >
                <b>Lienzo vacío</b>
                <span>Empezar desde cero</span>
              </button>
            </>
          )}
        </Menu>
        <button className="tb-btn" onClick={() => openModal('projects')}>
          Abrir
        </button>
        <button className="tb-btn" onClick={onSave} title="Ctrl+S">
          Guardar
        </button>
        <button className="tb-btn accent" onClick={() => openModal('export')}>
          Exportar
        </button>
      </div>

      <div className="tb-group">
        <button className="tb-icon" onClick={undo} disabled={!past} title="Deshacer (Ctrl+Z)">
          ↶
        </button>
        <button className="tb-icon" onClick={redo} disabled={!future} title="Rehacer (Ctrl+Y)">
          ↷
        </button>
        <button className="tb-btn" onClick={autoLayout} disabled={view !== 'c2'} title="Auto-organizar: reordena las piezas por zona y capa" aria-label="Auto-organizar">
          <span aria-hidden className="narrow-only">⇲</span>
          <span className="wide-only">Auto‑organizar</span>
        </button>
      </div>

      <div className="tb-group">
        <NetButton />
        <SimToggle />
        <AiButton />
      </div>

      <div className="tb-group">
        <div className="seg" role="tablist" aria-label="Nivel C4">
          <button className={view === 'c1' ? 'on' : ''} onClick={() => setView('c1')} aria-label="C1 Contexto" title="C4 nivel 1: actores, sistema y externos">
            C1<span className="wide-only"> Contexto</span>
          </button>
          <button className={view === 'c2' ? 'on' : ''} onClick={() => setView('c2')} aria-label="C2 Contenedores" title="C4 nivel 2: contenedores / servicios">
            C2<span className="wide-only"> Contenedores</span>
          </button>
          <button className={view === 'c3' ? 'on' : ''} disabled={!c3Ready} onClick={() => setView('c3')} aria-label="C3 Componentes" title={c3Ready ? 'C4 nivel 3: componentes del servicio' : 'Selecciona una pieza de cómputo o haz doble clic sobre ella'}>
            C3<span className="wide-only"> Componentes</span>
          </button>
        </div>
        <Menu label={layers.length ? `Capas (${layers.length})` : 'Capas'}>
          {() => (
            <div className="layers-pop">
              <div className="muted small" style={{ padding: '4px 8px 8px' }}>
                Resalta solo las capas elegidas
              </div>
              {(Object.keys(LAYERS) as Layer[]).map((l) => (
                <label key={l} className="layer-row">
                  <input type="checkbox" checked={layers.includes(l)} onChange={() => toggleLayer(l)} />
                  {LAYERS[l].label}
                </label>
              ))}
              {layers.length > 0 && (
                <button className="btn small block" onClick={clearLayers}>
                  Mostrar todas
                </button>
              )}
            </div>
          )}
        </Menu>
      </div>

      <span className="spacer" />
      <button className="health" onClick={() => window.dispatchEvent(new CustomEvent('archiplan:tab', { detail: 'issues' }))} title="Ver validación">
        <span className={`hdot ${issuesCount.error ? 'err' : issuesCount.warn ? 'warn' : 'ok'}`} />
        {issuesCount.error ? `${issuesCount.error} errores` : issuesCount.warn ? `${issuesCount.warn} avisos` : 'Sin errores'}
      </button>
    </header>
  );
}

function SimToggle() {
  const open = useSim((s) => s.open);
  const setOpen = useSim((s) => s.setOpen);
  const setView = useStore((s) => s.setView);
  return (
    <button
      className={`tb-btn sim-toggle ${open ? 'on' : ''}`}
      onClick={() => {
        if (!open) {
          setView('c2');
          useNetUi.getState().setView(false);
        }
        setOpen(!open);
      }}
      title={open ? 'Cerrar la simulación' : 'Simula carga, fallas, ataques y peticiones de usuario sobre esta arquitectura'}
      aria-label={open ? 'Cerrar simulación (barra)' : undefined}
    >
      {open ? '■ Simulación' : '▶ Simular'}
    </button>
  );
}

function NetButton() {
  const manual = useStore((s) => s.securityGroups.length > 0);
  const on = useNetUi((s) => s.view);
  const setView = useStore((s) => s.setView);
  const azure = useCloud() === 'azure';
  return (
    <button
      className={`tb-btn ${on ? 'on' : ''}`}
      aria-pressed={on}
      onClick={() => {
        if (!on) {
          setView('c2');
          useSim.getState().setOpen(false);
        }
        useNetUi.getState().setView(!on);
      }}
      title={`Vista de red: puertos, ${azure ? 'NSG' : 'Security Groups'} y qué tráfico pasa por cada flecha`}
    >
      ⛨ Red{manual && <span className="tb-dot" aria-label="red personalizada" />}
    </button>
  );
}

function Toasts() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`} onClick={() => dismiss(t.id)}>
          {t.text}
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const decisions = useStore((s) => s.decisions);
  const layers = useStore((s) => s.layers);
  const view = useStore((s) => s.view);
  const [modal, setModal] = useState<ModalKind>(null);
  const simOpen = useSim((s) => s.open);
  const simResult = useSim((s) => s.result);
  const simIdx = useSim((s) => s.idx);
  const simPlaying = useSim((s) => s.playing);
  const simMode = useSim((s) => s.mode);
  const trace = useSim((s) => s.trace);
  const traceStep = useSim((s) => s.step);
  const securityGroups = useStore((s) => s.securityGroups);
  const netViewOn = useNetUi((s) => s.view);
  const threatState = useStore((s) => s.threats);
  const strideOverlay = useThreatsUi((s) => s.overlay);
  const cloud = useCloud();

  // Validación en vivo (solo depende de la estructura, no de la selección)
  const structKey = useMemo(
    () => JSON.stringify([nodes.map((n) => [n.id, n.parentId, n.data]), edges.map((e) => [e.id, e.source, e.target, e.data])]),
    [nodes, edges],
  );
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const netAnalysis = useMemo(() => analyzeNetwork(nodes, edges, securityGroups), [structKey, securityGroups]); // eslint-disable-line react-hooks/exhaustive-deps
  const issues = useMemo(() => [...validate(nodes, edges), ...netIssues(netAnalysis, nodes)], [structKey, netAnalysis]); // eslint-disable-line react-hooks/exhaustive-deps
  const security = useStore((s) => s.security);
  const threatModel = useMemo(() => buildThreats(nodes, edges, threatState, { security, securityGroups }), [structKey, threatState, security, securityGroups]); // eslint-disable-line react-hooks/exhaustive-deps
  const guide = useMemo(() => buildGuide(nodes, edges, decisions, issues, threatModel.threats), [structKey, decisions, issues, threatModel]); // eslint-disable-line react-hooks/exhaustive-deps

  const ctx = useMemo(() => {
    const rank = { error: 3, warn: 2, info: 1 } as const;
    const nodeIssues = new Map<string, Severity>();
    const edgeIssues = new Map<string, Severity>();
    for (const i of issues) {
      if (i.edgeIds?.length) {
        for (const e of i.edgeIds) if (!edgeIssues.has(e) || rank[i.severity] > rank[edgeIssues.get(e)!]) edgeIssues.set(e, i.severity);
        continue;
      }
      if (i.severity === 'info' && i.nodeIds.length > 1) continue;
      for (const n of i.nodeIds) if (!nodeIssues.has(n) || rank[i.severity] > rank[nodeIssues.get(n)!]) nodeIssues.set(n, i.severity);
    }
    const dimmed = new Set<string>();
    if (layers.length) for (const n of nodes) if (isService(n) && !layers.includes(getService(n.data.serviceId).layer)) dimmed.add(n.id);
    const traceOn = simOpen && simMode === 'request' && view === 'c2' && trace ? traceOverlay({ ...trace, hops: trace.hops.slice(0, traceStep) }) : null;
    const traceCtx = traceOn && trace ? { ...traceOn, failedEdgeId: traceStep >= trace.hops.length ? trace.failedEdgeId ?? null : null, current: trace.hops[Math.min(traceStep, trace.hops.length) - 1]?.nodeId ?? null } : null;
    const netBlocked = new Map<string, string>();
    for (const v of netAnalysis.verdicts.values()) if (!v.ok) netBlocked.set(v.edgeId, v.short ?? 'bloqueado');
    const frame = simOpen && simMode === 'load' && simResult && view === 'c2' ? simResult.frames[simIdx] : null;
    const sim = frame ? { nodes: frame.nodes, edges: frame.edges, targetId: simResult!.targetId, playing: simPlaying } : null;
    let stride: { nodes: Map<string, { open: number; worst: string | null }>; boundaries: Map<string, string> } | null = null;
    const netView = netViewOn && view === 'c2' && !sim && !traceCtx ? netViewData(nodes, edges, netAnalysis) : null;
    if (strideOverlay && !sim && !traceCtx && !netView && view === 'c2') {
      const rank: Record<string, number> = { Bajo: 1, Medio: 2, Alto: 3, Crítico: 4 };
      const nm = new Map<string, { open: number; worst: string | null }>();
      for (const t of threatModel.threats) {
        if (!(t.status === 'abierta' || t.status === 'parcial') || t.kind === 'flow') continue;
        for (const id of t.nodeIds.slice(0, 1)) {
          const cur = nm.get(id) ?? { open: 0, worst: null };
          cur.open++;
          if (!cur.worst || rank[t.risk] > rank[cur.worst]) cur.worst = t.risk;
          nm.set(id, cur);
        }
      }
      const short: Record<string, string> = { 'Borde AWS': 'Borde', 'Servicios AWS': cloud === 'azure' ? 'PaaS' : 'AWS', 'Borde Azure': 'Borde', 'Servicios Azure': 'PaaS', 'Subnet pública': 'Pública', 'Subnet privada': 'Privada', 'Subnet de datos': 'Datos', 'Red corporativa': 'Corp.' };
      stride = { nodes: nm, boundaries: new Map(threatModel.boundaries.filter((b) => b.inbound).map((b) => [b.edgeId, `${short[b.from] ?? b.from}→${short[b.to] ?? b.to}`])) };
    }
    return { nodeIssues, edgeIssues, dimmed, readOnly: view !== 'c2', sim, stride, cloud, trace: traceCtx, netBlocked, netView };
  }, [issues, layers, nodes, edges, view, simOpen, simMode, simResult, simIdx, simPlaying, strideOverlay, threatModel, cloud, trace, traceStep, netAnalysis, netViewOn]);

  const counts = { error: issues.filter((i) => i.severity === 'error').length, warn: issues.filter((i) => i.severity === 'warn').length, info: issues.filter((i) => i.severity === 'info').length };

  const save = useCallback(async () => {
    const st = useStore.getState();
    const p = st.toProject();
    const id = st.projectId ?? slugify(p.meta.name);
    if (await serverAvailable()) {
      try {
        await saveProjectFile(id, p);
        st.setProjectId(id);
        st.markSaved();
        st.toast('ok', `Guardado en projects/${id}.archi.json`);
        return;
      } catch (e) {
        st.toast('error', String((e as Error).message));
        return;
      }
    }
    download(`${id}.archi.json`, JSON.stringify(p, null, 2), 'application/json');
    st.markSaved();
    st.toast('info', 'Servidor local no disponible: se descargó el archivo del proyecto.');
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target as HTMLElement)?.tagName);
      if (mod && e.key.toLowerCase() === 's') {
        e.preventDefault();
        save();
      } else if (mod && !typing && e.key.toLowerCase() === 'z' && !e.shiftKey) {
        e.preventDefault();
        useStore.getState().undo();
      } else if (mod && !typing && (e.key.toLowerCase() === 'y' || (e.key.toLowerCase() === 'z' && e.shiftKey))) {
        e.preventDefault();
        useStore.getState().redo();
      }
    };
    const onOpen = (e: Event) => setModal((e as CustomEvent).detail as ModalKind);
    const beforeUnload = (e: BeforeUnloadEvent) => {
      if (useStore.getState().dirty) e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('archiplan:open', onOpen);
    window.addEventListener('beforeunload', beforeUnload);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('archiplan:open', onOpen);
      window.removeEventListener('beforeunload', beforeUnload);
    };
  }, [save]);

  return (
    <ReactFlowProvider>
      <CanvasContext.Provider value={ctx}>
        <div className="app">
          <Toolbar openModal={setModal} onSave={save} issuesCount={counts} />
          <div className="main">
            <Palette />
            <div className={`center ${simOpen ? 'with-sim' : ''}`}>
              {view === 'c3' ? <C3Canvas /> : <Canvas />}
              {netViewOn && view === 'c2' && <NetLegend />}
              <AiPanel issues={issues} threats={threatModel.threats} />
              {simOpen && view !== 'c3' && <SimPanel />}
            </div>
            <Sidebar issues={issues} guide={guide} threats={threatModel.threats} />
          </div>
          {modal === 'templates' && <TemplatesModal onClose={() => setModal(null)} />}
          {modal === 'wizard' && <WizardModal onClose={() => setModal(null)} />}
          {modal === 'projects' && <ProjectsModal onClose={() => setModal(null)} />}
          {modal === 'export' && <ExportModal onClose={() => setModal(null)} />}
          {modal === 'net' && <NetModal onClose={() => setModal(null)} />}
          <AiWatcher issues={issues} threats={threatModel.threats} />
          {modal === 'security' && <SecurityModal onClose={() => setModal(null)} threats={threatModel.threats} />}
          <Toasts />
        </div>
      </CanvasContext.Provider>
    </ReactFlowProvider>
  );
}
