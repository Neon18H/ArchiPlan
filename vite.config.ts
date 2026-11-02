import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// @ts-ignore - módulo JS compartido con el servidor de producción
import { createApiHandler } from './server/api.mjs';

// La API de proyectos (guardar/abrir en disco) también funciona en modo desarrollo.
export default defineConfig({
  plugins: [
    react(),
    {
      name: 'archiplan-api',
      configureServer(server) {
        server.middlewares.use(createApiHandler());
      },
    },
  ],
  server: { port: 5173, open: true },
  build: { chunkSizeWarningLimit: 900 },
});
