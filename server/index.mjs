// Servidor de producción: sirve la app compilada (dist/) y la API de proyectos.
// Uso: npm run serve   (o: npm run build && npm start)
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApiHandler, projectsDir } from './api.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const PORT = Number(process.env.PORT || 4317);
const HOST = process.env.HOST || '127.0.0.1'; // solo local por defecto
const api = createApiHandler();
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.json': 'application/json', '.woff2': 'font/woff2',
};

http
  .createServer(async (req, res) => {
    if ((req.url || '').startsWith('/api/')) return api(req, res);
    const rel = decodeURIComponent(new URL(req.url || '/', 'http://x').pathname);
    let file = path.join(root, rel);
    if (!file.startsWith(root)) { res.statusCode = 403; return res.end(); }
    try {
      if ((await fs.stat(file)).isDirectory()) file = path.join(file, 'index.html');
    } catch {
      file = path.join(root, 'index.html');
    }
    try {
      const data = await fs.readFile(file);
      res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
      res.end(data);
    } catch {
      res.statusCode = 500;
      res.end('Compila primero la app con: npm run build');
    }
  })
  .listen(PORT, HOST, () => {
    console.log(`\n  ArchiPlan corriendo en  http://${HOST}:${PORT}`);
    console.log(`  Proyectos guardados en  ${projectsDir()}\n`);
  });
