// API mínima para guardar proyectos como archivos JSON en disco.
// Se usa tanto desde Vite (dev) como desde server/index.mjs (producción).
import fs from 'node:fs/promises';
import path from 'node:path';
import { handleAi } from './ai.mjs';

const SAFE = /^[a-zA-Z0-9._-]{1,80}$/;

export function projectsDir() {
  return path.resolve(process.env.ARCHIPLAN_PROJECTS_DIR || path.join(process.cwd(), 'projects'));
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 20 * 1024 * 1024) throw new Error('Proyecto demasiado grande');
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function createApiHandler() {
  return async function api(req, res, next) {
    const url = new URL(req.url || '/', 'http://localhost');
    if (!url.pathname.startsWith('/api/')) return next ? next() : undefined;
    const dir = projectsDir();
    try {
      if (await handleAi(req, res, url)) return;
      await fs.mkdir(dir, { recursive: true });
      if (url.pathname === '/api/health') return send(res, 200, { ok: true, dir });

      if (url.pathname === '/api/projects' && req.method === 'GET') {
        const files = (await fs.readdir(dir)).filter((f) => f.endsWith('.archi.json'));
        const list = [];
        for (const f of files) {
          try {
            const st = await fs.stat(path.join(dir, f));
            const data = JSON.parse(await fs.readFile(path.join(dir, f), 'utf8'));
            list.push({
              id: f.replace(/\.archi\.json$/, ''),
              name: data?.meta?.name || f,
              updatedAt: st.mtime.toISOString(),
              nodes: Array.isArray(data?.nodes) ? data.nodes.length : 0,
            });
          } catch {
            /* archivo corrupto: se ignora */
          }
        }
        list.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        return send(res, 200, list);
      }

      const m = url.pathname.match(/^\/api\/projects\/([^/]+)$/);
      if (m) {
        const id = decodeURIComponent(m[1]);
        if (!SAFE.test(id)) return send(res, 400, { error: 'Identificador inválido' });
        const file = path.join(dir, `${id}.archi.json`);
        if (req.method === 'GET') {
          return send(res, 200, JSON.parse(await fs.readFile(file, 'utf8')));
        }
        if (req.method === 'PUT') {
          const body = await readBody(req);
          JSON.parse(body); // valida que sea JSON
          await fs.writeFile(file, body, 'utf8');
          return send(res, 200, { ok: true, id });
        }
        if (req.method === 'DELETE') {
          await fs.rm(file, { force: true });
          return send(res, 200, { ok: true });
        }
      }
      return send(res, 404, { error: 'No encontrado' });
    } catch (e) {
      const status = e && e.code === 'ENOENT' ? 404 : 500;
      return send(res, status, { error: String(e?.message || e) });
    }
  };
}
