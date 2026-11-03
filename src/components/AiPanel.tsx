import { drOf } from '../resilience/model';
import { useEffect, useMemo, useRef, useState } from 'react';
import { buildContext, QUICK_ACTIONS, REVIEW_PROMPT, SYSTEM_PROMPT } from '../ai/context';
import { aiApi, useAi, type ProviderId } from '../ai/store';
import { isService } from '../lib/graph';
import { useSim } from '../sim/store';
import { useStore } from '../store';
import type { Threat } from '../threats/model';
import type { Issue } from '../types';
import { useNetAnalysis } from './NetInspector';

/* ───────────────────────── Markdown mínimo con enlaces a piezas [[Nombre]] */

function focusByName(name: string) {
  const st = useStore.getState();
  const n = st.nodes.find((x) => isService(x) && x.data.label.trim().toLowerCase() === name.trim().toLowerCase());
  if (n) {
    if (st.view !== 'c2') st.setView('c2');
    st.focus([n.id]);
  } else st.toast('info', `No encontré «${name}» en el diagrama.`);
}

function inline(text: string, key: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  const re = /(\[\[([^\]]+)\]\]|\*\*([^*]+)\*\*|`([^`]+)`|_([^_]+)_)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const k = `${key}-${i++}`;
    if (m[2]) {
      const name = m[2];
      out.push(
        <button key={k} className="ai-ref" onClick={() => focusByName(name)} title="Ver en el diagrama">
          {name}
        </button>,
      );
    }
    else if (m[3]) out.push(<b key={k}>{inline(m[3], k)}</b>);
    else if (m[4]) out.push(<code key={k}>{m[4]}</code>);
    else if (m[5]) out.push(<em key={k}>{m[5]}</em>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function Md({ text }: { text: string }) {
  const blocks: React.ReactNode[] = [];
  const lines = text.replace(/\r/g, '').split('\n');
  let i = 0;
  let k = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (l.startsWith('```')) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) code.push(lines[i++]);
      i++;
      blocks.push(<pre key={k++}>{code.join('\n')}</pre>);
      continue;
    }
    const h = l.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      blocks.push(<div key={k++} className={`ai-h h${h[1].length}`}>{inline(h[2], `h${k}`)}</div>);
      i++;
      continue;
    }
    if (/^\s*([-*•]|\d+[.)])\s+/.test(l)) {
      const ordered = /^\s*\d+[.)]/.test(l);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*•]|\d+[.)])\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*•]|\d+[.)])\s+/, '');
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*•]|\d+[.)])\s+/.test(lines[i])) item += ` ${lines[i++].trim()}`;
        items.push(item);
      }
      const Tag = ordered ? 'ol' : 'ul';
      blocks.push(
        <Tag key={k++}>
          {items.map((it, j) => (
            <li key={j}>{inline(it, `l${k}-${j}`)}</li>
          ))}
        </Tag>,
      );
      continue;
    }
    if (!l.trim()) {
      i++;
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|```|\s*([-*•]|\d+[.)])\s+)/.test(lines[i])) para.push(lines[i++]);
    blocks.push(<p key={k++}>{inline(para.join(' '), `p${k}`)}</p>);
  }
  return <div className="md">{blocks}</div>;
}

/* ───────────────────────── contexto vivo */

function useAiContext(issues: Issue[], threats: Threat[]) {
  const meta = useStore((s) => s.meta);
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const securityGroups = useStore((s) => s.securityGroups);
  const security = useStore((s) => s.security);
  const net = useNetAnalysis();
  const sim = useSim((s) => s.result);
  const trace = useSim((s) => s.trace);
  return () => {
    const { variants, activeVariant } = useStore.getState();
    const variant = variants.length ? { names: variants.map((v) => v.name), active: variants.find((v) => v.id === activeVariant)?.name ?? '' } : null;
    return buildContext({ meta, nodes, edges, securityGroups, security, issues, threats, net, sim, trace, variant, dr: drOf(meta) });
  };
}

/** Revisión automática mientras se diseña (siempre montado en App). */
export function AiWatcher({ issues, threats }: { issues: Issue[]; threats: Threat[] }) {
  const auto = useAi((s) => s.auto);
  const configured = useAi((s) => !!s.config?.configured);
  const loadConfig = useAi((s) => s.loadConfig);
  const nodes = useStore((s) => s.nodes);
  const edges = useStore((s) => s.edges);
  const sgs = useStore((s) => s.securityGroups);
  const security = useStore((s) => s.security);
  const ctx = useAiContext(issues, threats);
  const key = useMemo(() => JSON.stringify([nodes.map((n) => [n.id, n.parentId, n.data]), edges.map((e) => [e.source, e.target, e.data]), sgs, security]), [nodes, edges, sgs, security]);
  const ctxRef = useRef(ctx);
  ctxRef.current = ctx;
  useEffect(() => {
    if (auto && !useAi.getState().config) void loadConfig();
  }, [auto, loadConfig]);
  useEffect(() => {
    if (!auto || !configured || nodes.filter(isService).length < 2) return;
    if (useAi.getState().lastReviewKey === key) return;
    const t = setTimeout(() => {
      const st = useAi.getState();
      if (st.streaming || st.lastReviewKey === key) return;
      void st.review(`${SYSTEM_PROMPT}\n\n${ctxRef.current()}`, `${REVIEW_PROMPT} Céntrate en lo que cambió o en lo más urgente; sé breve.`, key);
    }, 8000);
    return () => clearTimeout(t);
  }, [auto, configured, key, nodes]);
  return null;
}

/* ───────────────────────── configuración */

function Settings() {
  const config = useAi((s) => s.config);
  const setConfig = useAi((s) => s.setConfig);
  const setView = useAi((s) => s.setView);
  const [provider, setProvider] = useState<ProviderId>(config?.provider ?? 'anthropic');
  const p = config?.providers[provider];
  const [key, setKey] = useState('');
  const [model, setModel] = useState(p?.model ?? '');
  const [models, setModels] = useState<string[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => {
    setModel(useAi.getState().config?.providers[provider]?.model ?? '');
    setModels([]);
    setMsg(null);
    setKey('');
  }, [provider]);
  if (!config || !p) return <div className="muted pad">Cargando…</div>;
  const save = async () => {
    setBusy('save');
    setMsg(null);
    try {
      const c = await aiApi.save({ provider, model: model.trim() || p.defaultModel, ...(key.trim() ? { key: key.trim() } : {}) });
      setConfig(c);
      setKey('');
      setMsg({ ok: true, text: c.configured ? 'Guardado.' : 'Guardado, pero falta la API key de este proveedor.' });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  const test = async () => {
    setBusy('test');
    setMsg(null);
    try {
      const out = await aiApi.stream('Responde solo con: OK', [{ role: 'user', content: 'Prueba de conexión' }], () => {}, new AbortController().signal);
      setMsg({ ok: true, text: `Conectado: el modelo respondió «${out.trim().slice(0, 60)}».` });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  const loadModels = async () => {
    setBusy('models');
    setMsg(null);
    try {
      const r = await aiApi.models(provider);
      setModels(r.models);
      setMsg({ ok: true, text: `${r.models.length} modelos disponibles en tu cuenta.` });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="ai-settings">
      <div className="ai-sub">Proveedor</div>
      <div className="ai-providers">
        {(Object.keys(config.providers) as ProviderId[]).map((id) => (
          <button key={id} className={`ai-prov ${provider === id ? 'on' : ''}`} onClick={() => setProvider(id)}>
            <b>{config.providers[id].label}</b>
            <span>{config.providers[id].key ? `Key ${config.providers[id].key}` : 'Sin API key'}</span>
            {config.provider === id && <em>en uso</em>}
          </button>
        ))}
      </div>
      <label className="field">
        <span className="field-label">API key</span>
        <input type="password" autoComplete="off" placeholder={p.key ? `Guardada (${p.key}). Escribe otra para reemplazarla.` : p.keyHint} value={key} onChange={(e) => setKey(e.target.value)} />
        <span className="field-help">
          Consíguela en{' '}
          <a href={p.keysUrl} target="_blank" rel="noreferrer">
            {p.keysUrl.replace('https://', '')}
          </a>
          . Se guarda solo en este equipo ({config.file}), nunca en los proyectos.
        </span>
      </label>
      <label className="field">
        <span className="field-label">Modelo</span>
        <input list="ai-models" value={model} placeholder={p.defaultModel} onChange={(e) => setModel(e.target.value)} />
        <datalist id="ai-models">
          {[...new Set([...p.suggestions, ...models])].map((m) => (
            <option key={m} value={m} />
          ))}
        </datalist>
        <span className="field-help">
          Recomendado: {p.defaultModel}.{' '}
          <button className="linklike small" disabled={!p.key || !!busy} onClick={loadModels}>
            {busy === 'models' ? 'Cargando…' : 'Ver los modelos de mi cuenta'}
          </button>
        </span>
      </label>
      {models.length > 0 && (
        <div className="ai-model-list">
          {models.slice(0, 40).map((m) => (
            <button key={m} className={m === model ? 'on' : ''} onClick={() => setModel(m)}>
              {m}
            </button>
          ))}
        </div>
      )}
      <div className="row gap">
        <button className="btn primary" disabled={!!busy} onClick={save}>
          {busy === 'save' ? 'Guardando…' : 'Guardar y usar este proveedor'}
        </button>
        <button className="btn" disabled={!!busy || !(config.provider === provider && config.configured)} onClick={test} title={config.provider === provider ? '' : 'Guarda primero este proveedor'}>
          {busy === 'test' ? 'Probando…' : 'Probar'}
        </button>
      </div>
      {msg && <div className={`ai-msg ${msg.ok ? 'ok' : 'bad'}`}>{msg.text}</div>}
      {config.configured && (
        <button className="linklike small" onClick={() => setView('chat')}>
          ← Volver al chat
        </button>
      )}
      <p className="small muted">El asistente lee el diagrama, la red, el escalado, la validación, las amenazas y tus simulaciones. Cada mensaje (y cada revisión automática) consume tokens de tu cuenta del proveedor.</p>
    </div>
  );
}

/* ───────────────────────── panel */

export function AiPanel({ issues, threats }: { issues: Issue[]; threats: Threat[] }) {
  const { open, view, config, serverOk, messages, streaming, auto, observations } = useAi();
  const { setOpen, setView, setAuto, send, stop, clear, loadConfig } = useAi.getState();
  const ctx = useAiContext(issues, threats);
  const [input, setInput] = useState('');
  const listRef = useRef<HTMLDivElement>(null);
  const hasSel = useStore((s) => s.nodes.some((n) => n.selected) || s.edges.some((e) => e.selected));
  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [messages]);
  useEffect(() => {
    if (open && !config) void loadConfig();
  }, [open, config, loadConfig]);
  if (!open) return null;
  const ask = (prompt: string, label?: string) => {
    if (!prompt.trim()) return;
    void send(prompt.trim(), `${SYSTEM_PROMPT}\n\n${ctx()}`, label);
    setInput('');
  };
  const ready = !!config?.configured;
  return (
    <aside className="ai-panel" aria-label="Asistente IA">
      <header className="ai-head">
        <b>✦ Asistente</b>
        {config && ready && <span className="ai-model" title={config.providers[config.provider].label}>{config.model}</span>}
        <span className="ai-head-actions">
          {ready && view === 'chat' && messages.length > 0 && (
            <button className="linklike small" onClick={clear}>
              Nueva conversación
            </button>
          )}
          <button className="icon-btn" title="Configurar proveedor" aria-label="Configurar proveedor" onClick={() => setView(view === 'settings' ? 'chat' : 'settings')}>
            ⚙
          </button>
          <button className="icon-btn" aria-label="Cerrar asistente" onClick={() => setOpen(false)}>
            ×
          </button>
        </span>
      </header>
      {serverOk === false ? (
        <div className="pad small">El asistente necesita el servidor local de ArchiPlan (npm run serve o npm run dev): las llamadas a la IA salen desde ahí para no exponer tu API key.</div>
      ) : view === 'settings' || !ready ? (
        <Settings />
      ) : (
        <>
          <label className="ai-auto toggle small">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span>Revisar mientras diseño (comenta solo cuando cambias el diagrama)</span>
          </label>
          {auto && observations && (
            <div className={`ai-obs ${observations.error ? 'bad' : ''}`}>
              <div className="ai-sub">
                Observaciones {observations.streaming ? '· revisando…' : `· ${new Date(observations.at).toLocaleTimeString()}`}
              </div>
              <Md text={observations.text || '…'} />
            </div>
          )}
          <div className="ai-list" ref={listRef}>
            {!messages.length && (
              <div className="ai-empty">
                <p>Pregúntame lo que quieras sobre este diseño. Leo el diagrama, la red, el escalado, la validación y las amenazas cada vez que me escribes.</p>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`ai-msg-row ${m.role} ${m.error ? 'bad' : ''}`}>
                {m.role === 'user' ? <div className="ai-bubble">{m.label ?? m.content}</div> : m.content ? <Md text={m.content} /> : <div className="ai-typing">Pensando…</div>}
              </div>
            ))}
          </div>
          <div className="ai-quick">
            {QUICK_ACTIONS.filter((q) => !q.needsSelection || hasSel).map((q) => (
              <button key={q.label} disabled={streaming} onClick={() => ask(q.prompt, q.label)}>
                {q.label}
              </button>
            ))}
          </div>
          <form
            className="ai-input"
            onSubmit={(e) => {
              e.preventDefault();
              ask(input);
            }}
          >
            <textarea
              rows={2}
              value={input}
              placeholder="Ej.: ¿por qué falla la petición a la API? ¿Está bien el SG de la base de datos?"
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  ask(input);
                }
              }}
            />
            {streaming ? (
              <button type="button" className="btn" onClick={stop}>
                Detener
              </button>
            ) : (
              <button type="submit" className="btn primary" disabled={!input.trim()}>
                Enviar
              </button>
            )}
          </form>
        </>
      )}
    </aside>
  );
}

/** Botón de la barra superior. */
export function AiButton() {
  const open = useAi((s) => s.open);
  const unseen = useAi((s) => s.unseen);
  const setOpen = useAi((s) => s.setOpen);
  return (
    <button className="tb-btn ai-btn" aria-pressed={open} onClick={() => setOpen(!open)} title="Asistente de IA que revisa tu arquitectura">
      ✦ IA{unseen && <span className="tb-dot" aria-label="observaciones nuevas" />}
    </button>
  );
}
