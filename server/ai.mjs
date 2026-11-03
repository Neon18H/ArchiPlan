// Proxy local hacia proveedores de IA (OpenAI, Anthropic, DeepSeek, OpenRouter).
// La API key se guarda en la máquina del arquitecto (~/.archiplan/ai.json), nunca en los
// proyectos ni en el repositorio, y nunca se devuelve completa al navegador.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const PROVIDERS = {
  openai: {
    label: 'OpenAI (GPT)',
    kind: 'openai',
    base: () => process.env.ARCHIPLAN_AI_BASE_OPENAI || 'https://api.openai.com/v1',
    model: 'gpt-5.6-terra',
    suggestions: ['gpt-5.6-terra', 'gpt-5.6-sol', 'gpt-5.6-luna'],
    keyHint: 'sk-…',
    keysUrl: 'https://platform.openai.com/api-keys',
  },
  anthropic: {
    label: 'Anthropic (Claude)',
    kind: 'anthropic',
    base: () => process.env.ARCHIPLAN_AI_BASE_ANTHROPIC || 'https://api.anthropic.com/v1',
    model: 'claude-sonnet-5-5',
    suggestions: ['claude-sonnet-5-5', 'claude-opus-5-5', 'claude-haiku-5-5'],
    keyHint: 'sk-ant-…',
    keysUrl: 'https://console.anthropic.com/settings/keys',
  },
  deepseek: {
    label: 'DeepSeek',
    kind: 'openai',
    base: () => process.env.ARCHIPLAN_AI_BASE_DEEPSEEK || 'https://api.deepseek.com',
    model: 'deepseek-v4-flash',
    suggestions: ['deepseek-v4-flash', 'deepseek-v4-pro'],
    keyHint: 'sk-…',
    keysUrl: 'https://platform.deepseek.com/api_keys',
  },
  openrouter: {
    label: 'OpenRouter (muchos modelos)',
    kind: 'openai',
    base: () => process.env.ARCHIPLAN_AI_BASE_OPENROUTER || 'https://openrouter.ai/api/v1',
    model: 'anthropic/claude-sonnet-5',
    suggestions: ['anthropic/claude-sonnet-5', 'openai/gpt-5.6-terra', 'deepseek/deepseek-v4-flash'],
    keyHint: 'sk-or-…',
    keysUrl: 'https://openrouter.ai/keys',
  },
};

function configFile() {
  const dir = process.env.ARCHIPLAN_CONFIG_DIR || path.join(os.homedir(), '.archiplan');
  return path.join(dir, 'ai.json');
}

async function readConfig() {
  try {
    const c = JSON.parse(await fs.readFile(configFile(), 'utf8'));
    return { provider: c.provider in PROVIDERS ? c.provider : 'anthropic', models: c.models || {}, keys: c.keys || {} };
  } catch {
    return { provider: 'anthropic', models: {}, keys: {} };
  }
}

async function writeConfig(c) {
  const file = configFile();
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(c, null, 2), { encoding: 'utf8', mode: 0o600 });
}

const mask = (k) => (k ? `${k.slice(0, 4)}…${k.slice(-4)}` : null);

function publicConfig(c) {
  return {
    provider: c.provider,
    model: c.models[c.provider] || PROVIDERS[c.provider].model,
    configured: !!c.keys[c.provider],
    file: configFile(),
    providers: Object.fromEntries(
      Object.entries(PROVIDERS).map(([id, p]) => [id, { label: p.label, model: c.models[id] || p.model, defaultModel: p.model, suggestions: p.suggestions, key: mask(c.keys[id]), keyHint: p.keyHint, keysUrl: p.keysUrl }]),
    ),
  };
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 2 * 1024 * 1024) throw new Error('Solicitud demasiado grande');
    chunks.push(c);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
}

function headersFor(id, key) {
  const p = PROVIDERS[id];
  if (p.kind === 'anthropic') return { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' };
  const h = { 'content-type': 'application/json', authorization: `Bearer ${key}` };
  if (id === 'openrouter') Object.assign(h, { 'HTTP-Referer': 'https://github.com/Neon18H/ArchiPlan', 'X-Title': 'ArchiPlan' });
  return h;
}

async function providerError(r) {
  let msg = `${r.status} ${r.statusText}`;
  try {
    const j = await r.json();
    msg = j?.error?.message || j?.message || msg;
  } catch {
    /* sin cuerpo */
  }
  if (r.status === 401 || r.status === 403) return `La API key no es válida o no tiene permiso (${msg}).`;
  if (r.status === 404) return `El modelo no existe o no está disponible para tu cuenta (${msg}).`;
  if (r.status === 429) return `Límite de uso o saldo agotado en el proveedor (${msg}).`;
  return msg;
}

/** Lee un stream SSE y llama a onEvent(data) por cada evento. */
async function readSse(body, onEvent) {
  const dec = new TextDecoder();
  let buf = '';
  for await (const chunk of body) {
    buf += dec.decode(chunk, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (!data || data === '[DONE]') continue;
      try {
        onEvent(JSON.parse(data));
      } catch {
        /* línea parcial o comentario */
      }
    }
  }
}

async function streamChat(id, key, model, system, messages, res, signal) {
  const p = PROVIDERS[id];
  const msgs = messages.filter((m) => m && typeof m.content === 'string' && (m.role === 'user' || m.role === 'assistant')).slice(-30);
  let r;
  if (p.kind === 'anthropic') {
    r = await fetch(`${p.base()}/messages`, {
      method: 'POST',
      headers: headersFor(id, key),
      body: JSON.stringify({ model, max_tokens: 4096, system, messages: msgs, stream: true }),
      signal,
    });
  } else {
    r = await fetch(`${p.base()}/chat/completions`, {
      method: 'POST',
      headers: headersFor(id, key),
      body: JSON.stringify({ model, stream: true, messages: [{ role: 'system', content: system }, ...msgs] }),
      signal,
    });
  }
  if (!r.ok) return send(res, 502, { error: await providerError(r) });
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  let wrote = false;
  const write = (t) => {
    if (!t) return;
    wrote = true;
    res.write(t);
  };
  try {
    await readSse(r.body, (ev) => {
      if (p.kind === 'anthropic') {
        if (ev.type === 'content_block_delta' && ev.delta?.type === 'text_delta') write(ev.delta.text);
        if (ev.type === 'error') write(`\n\n[Error del proveedor: ${ev.error?.message ?? 'desconocido'}]`);
      } else {
        const d = ev.choices?.[0]?.delta;
        if (d && typeof d.content === 'string') write(d.content);
        if (ev.error) write(`\n\n[Error del proveedor: ${ev.error.message ?? 'desconocido'}]`);
      }
    });
  } catch (e) {
    if (!signal.aborted) write(`\n\n[Se cortó la conexión con el proveedor: ${e.message}]`);
  }
  if (!wrote && !signal.aborted) res.write('[El modelo no devolvió texto.]');
  res.end();
}

async function listModels(id, key) {
  const p = PROVIDERS[id];
  const r = await fetch(`${p.base()}/models`, { headers: headersFor(id, key) });
  if (!r.ok) throw new Error(await providerError(r));
  const j = await r.json();
  const ids = (j.data || []).map((m) => m.id).filter(Boolean);
  if (id === 'openai') return ids.filter((m) => /^(gpt|o\d|chatgpt)/.test(m) && !/(audio|realtime|transcribe|tts|image|embedding|search|moderation)/.test(m)).sort().reverse();
  return ids.sort();
}

/** Maneja /api/ai/*. Devuelve true si atendió la petición. */
export async function handleAi(req, res, url) {
  if (!url.pathname.startsWith('/api/ai/')) return false;
  const cfg = await readConfig();

  if (url.pathname === '/api/ai/config' && req.method === 'GET') {
    send(res, 200, publicConfig(cfg));
    return true;
  }
  if (url.pathname === '/api/ai/config' && req.method === 'PUT') {
    const b = await readJson(req);
    if (b.provider && !(b.provider in PROVIDERS)) {
      send(res, 400, { error: 'Proveedor desconocido' });
      return true;
    }
    if (b.provider) cfg.provider = b.provider;
    const target = b.provider || cfg.provider;
    if (typeof b.model === 'string') cfg.models[target] = b.model.trim();
    if (typeof b.key === 'string' && b.key.trim()) cfg.keys[target] = b.key.trim();
    if (b.clearKey) delete cfg.keys[target];
    await writeConfig(cfg);
    send(res, 200, publicConfig(cfg));
    return true;
  }
  if (url.pathname === '/api/ai/models' && req.method === 'GET') {
    const id = url.searchParams.get('provider') || cfg.provider;
    if (!(id in PROVIDERS)) {
      send(res, 400, { error: 'Proveedor desconocido' });
      return true;
    }
    if (!cfg.keys[id]) {
      send(res, 400, { error: 'Primero guarda la API key de este proveedor.' });
      return true;
    }
    try {
      send(res, 200, { models: await listModels(id, cfg.keys[id]) });
    } catch (e) {
      send(res, 502, { error: e.message });
    }
    return true;
  }
  if (url.pathname === '/api/ai/chat' && req.method === 'POST') {
    const b = await readJson(req);
    const id = b.provider && b.provider in PROVIDERS ? b.provider : cfg.provider;
    const key = cfg.keys[id];
    if (!key) {
      send(res, 400, { error: 'Configura una API key en ✦ IA → Configurar.' });
      return true;
    }
    const model = (typeof b.model === 'string' && b.model) || cfg.models[id] || PROVIDERS[id].model;
    const ctl = new AbortController();
    res.on('close', () => ctl.abort());
    try {
      await streamChat(id, key, model, String(b.system || ''), Array.isArray(b.messages) ? b.messages : [], res, ctl.signal);
    } catch (e) {
      if (!res.headersSent) send(res, 502, { error: `No se pudo contactar al proveedor: ${e.message}` });
      else res.end();
    }
    return true;
  }
  send(res, 404, { error: 'No encontrado' });
  return true;
}
