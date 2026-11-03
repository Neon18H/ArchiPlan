import { create } from 'zustand';

export type ProviderId = 'openai' | 'anthropic' | 'deepseek' | 'openrouter';

export interface ProviderInfo {
  label: string;
  model: string;
  defaultModel: string;
  suggestions: string[];
  key: string | null;
  keyHint: string;
  keysUrl: string;
}

export interface AiConfig {
  provider: ProviderId;
  model: string;
  configured: boolean;
  file: string;
  providers: Record<ProviderId, ProviderInfo>;
}

export interface ChatMsg {
  role: 'user' | 'assistant';
  content: string;
  /** Mensaje de una acción rápida (se muestra con su etiqueta corta). */
  label?: string;
  error?: boolean;
}

/* ───────────────────────── API local (/api/ai) */

async function json<T>(r: Response): Promise<T> {
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((j as { error?: string }).error || `Error ${r.status}`);
  return j as T;
}

export const aiApi = {
  config: () => fetch('/api/ai/config').then((r) => json<AiConfig>(r)),
  save: (body: { provider?: ProviderId; model?: string; key?: string; clearKey?: boolean }) =>
    fetch('/api/ai/config', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => json<AiConfig>(r)),
  models: (provider: ProviderId) => fetch(`/api/ai/models?provider=${provider}`).then((r) => json<{ models: string[] }>(r)),
  /** Envía la conversación y va entregando el texto a medida que llega. */
  async stream(system: string, messages: ChatMsg[], onText: (t: string) => void, signal: AbortSignal): Promise<string> {
    const r = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ system, messages: messages.filter((m) => !m.error).map((m) => ({ role: m.role, content: m.content })) }),
      signal,
    });
    if (!r.ok || !r.body) {
      const j = await r.json().catch(() => ({}));
      throw new Error((j as { error?: string }).error || `Error ${r.status}`);
    }
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let all = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const t = dec.decode(value, { stream: true });
      all += t;
      onText(all);
    }
    return all;
  },
};

/* ───────────────────────── estado del asistente */

const AUTO_KEY = 'archiplan:ai:auto';
const readAuto = () => {
  try {
    return localStorage.getItem(AUTO_KEY) === '1';
  } catch {
    return false;
  }
};

interface AiState {
  open: boolean;
  view: 'chat' | 'settings';
  config: AiConfig | null;
  serverOk: boolean | null;
  messages: ChatMsg[];
  streaming: boolean;
  /** Revisión automática mientras se diseña. */
  auto: boolean;
  observations: { text: string; at: number; streaming: boolean; error?: boolean } | null;
  lastReviewKey: string;
  unseen: boolean;
  controller: AbortController | null;
  setOpen: (v: boolean) => void;
  setView: (v: 'chat' | 'settings') => void;
  setAuto: (v: boolean) => void;
  loadConfig: () => Promise<void>;
  setConfig: (c: AiConfig) => void;
  send: (prompt: string, system: string, label?: string) => Promise<void>;
  review: (system: string, prompt: string, key: string) => Promise<void>;
  stop: () => void;
  clear: () => void;
}

export const useAi = create<AiState>((set, get) => ({
  open: false,
  view: 'chat',
  config: null,
  serverOk: null,
  messages: [],
  streaming: false,
  auto: readAuto(),
  observations: null,
  lastReviewKey: '',
  unseen: false,
  controller: null,
  setOpen: (v) => {
    set({ open: v, ...(v ? { unseen: false } : {}) });
    if (v && !get().config) void get().loadConfig();
  },
  setView: (v) => set({ view: v }),
  setAuto: (v) => {
    try {
      localStorage.setItem(AUTO_KEY, v ? '1' : '0');
    } catch {
      /* sin almacenamiento */
    }
    set({ auto: v, ...(v ? {} : { lastReviewKey: '' }) });
  },
  loadConfig: async () => {
    try {
      const c = await aiApi.config();
      set({ config: c, serverOk: true, ...(!c.configured ? { view: 'settings' } : {}) });
    } catch {
      set({ serverOk: false });
    }
  },
  setConfig: (c) => set({ config: c }),
  send: async (prompt, system, label) => {
    if (get().streaming) return;
    const ctl = new AbortController();
    const history: ChatMsg[] = [...get().messages, { role: 'user', content: prompt, label }];
    set({ messages: [...history, { role: 'assistant', content: '' }], streaming: true, controller: ctl });
    const update = (content: string, error = false) => {
      const ms = get().messages.slice();
      ms[ms.length - 1] = { role: 'assistant', content, error };
      set({ messages: ms });
    };
    try {
      const all = await aiApi.stream(system, history, (t) => update(t), ctl.signal);
      update(all || '(sin respuesta)');
    } catch (e) {
      if (ctl.signal.aborted) update(`${get().messages[get().messages.length - 1].content}\n\n_(detenido)_`);
      else update((e as Error).message, true);
    } finally {
      set({ streaming: false, controller: null });
    }
  },
  review: async (system, prompt, key) => {
    if (get().streaming) return;
    set({ lastReviewKey: key, observations: { text: '', at: Date.now(), streaming: true } });
    const ctl = new AbortController();
    try {
      const all = await aiApi.stream(system, [{ role: 'user', content: prompt }], (t) => set({ observations: { text: t, at: Date.now(), streaming: true } }), ctl.signal);
      set({ observations: { text: all, at: Date.now(), streaming: false }, unseen: !get().open });
    } catch (e) {
      set({ observations: { text: (e as Error).message, at: Date.now(), streaming: false, error: true } });
    }
  },
  stop: () => get().controller?.abort(),
  clear: () => set({ messages: [] }),
}));
